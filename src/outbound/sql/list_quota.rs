//! Fresh databases enforce the quota at once; upgraded ones wait for recount and enable.
//! Both lock the switch row exclusively, and publish re-reads it shared, so nothing slips past.

use std::fmt::Write;

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbErr, DeriveIden, FromQueryResult,
    Statement,
    sea_query::{Expr, ExprTrait, LockType, Query},
};

use super::migrations::RECOUNT_LIST_COUNT_SQL;
use super::store::begin_read_committed;
use crate::utils::metrics::record_list_quota_enforced;

pub(crate) const ROW_ID: i32 = 1;

/// Issuers named per reason in a refusal.
const NAMED_ISSUERS: usize = 20;

#[derive(DeriveIden)]
enum ListQuota {
    Table,
    Id,
    Enforced,
}

#[derive(Debug, thiserror::Error)]
pub enum ListQuotaError {
    #[error("database error: {0}")]
    Db(#[from] DbErr),
    #[error("the list quota is enforced; run `list-quota disable` before recounting")]
    Enforced,
    #[error(
        "limits.max_lists_per_issuer is not enforced on this database, which a release without \
         the list quota has served. For the rollout from that release, set \
         APP_LIMITS__LIST_QUOTA_TRANSITION=true; once no pod of it is left, run \
         `list-quota recount` and `list-quota enable`, then remove the setting"
    )]
    NotEnforced,
    #[error("refusing to enable the list quota{}", describe_refusal(.max, .over_quota, .miscounted))]
    Refused {
        max: u64,
        over_quota: Vec<IssuerCount>,
        miscounted: Vec<IssuerCount>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, FromQueryResult)]
pub struct IssuerCount {
    pub issuer: String,
    pub list_count: i64,
    /// Lists that exist.
    pub actual: i64,
}

fn describe_refusal(max: &u64, over_quota: &[IssuerCount], miscounted: &[IssuerCount]) -> String {
    let mut out = String::new();
    if !over_quota.is_empty() {
        let _ = write!(
            out,
            "\n  {} issuer(s) have more than {max} status lists; delete lists or raise \
             limits.max_lists_per_issuer:",
            over_quota.len()
        );
        list_issuers(&mut out, over_quota, |c| format!("{} lists", c.actual));
    }
    if !miscounted.is_empty() {
        let _ = write!(
            out,
            "\n  {} issuer(s) have a list_count that does not match their lists; run \
             `list-quota recount` once no pod of an older release is left:",
            miscounted.len()
        );
        list_issuers(&mut out, miscounted, |c| {
            format!("list_count {}, {} lists", c.list_count, c.actual)
        });
    }
    out
}

fn list_issuers(
    out: &mut String,
    issuers: &[IssuerCount],
    detail: impl Fn(&IssuerCount) -> String,
) {
    for issuer in issuers.iter().take(NAMED_ISSUERS) {
        let _ = write!(out, "\n    {} ({})", issuer.issuer, detail(issuer));
    }
    if issuers.len() > NAMED_ISSUERS {
        let _ = write!(out, "\n    … and {} more", issuers.len() - NAMED_ISSUERS);
    }
}

/// If it reads off, re-read under a shared lock to wait out a running enable or recount.
pub(crate) async fn list_quota_enforced(txn: &DatabaseTransaction) -> Result<bool, DbErr> {
    let enforced = read_switch(txn, None).await? || read_switch(txn, Some(LockType::Share)).await?;
    record_list_quota_enforced(enforced);
    Ok(enforced)
}

pub async fn is_enforced(db: &DatabaseConnection) -> Result<bool, DbErr> {
    read_switch(db, None).await
}

#[derive(Debug, PartialEq, Eq)]
pub enum StartupState {
    Enforced,
    /// `limits.list_quota_transition` is still set.
    EnforcedWithTransitionSet,
    Transition,
}

/// On for fresh databases; elsewhere it may stay off only while transition is set.
pub async fn on_startup(
    db: &DatabaseConnection,
    fresh: bool,
    transition: bool,
    max_lists_per_issuer: u64,
) -> Result<StartupState, ListQuotaError> {
    if fresh {
        enable(db, max_lists_per_issuer).await?;
    }
    let enforced = is_enforced(db).await?;
    record_list_quota_enforced(enforced);
    match (enforced, transition) {
        (true, false) => Ok(StartupState::Enforced),
        (true, true) => Ok(StartupState::EnforcedWithTransitionSet),
        (false, true) => Ok(StartupState::Transition),
        (false, false) => Err(ListQuotaError::NotEnforced),
    }
}

/// Refuses while any issuer is over the cap or miscounted, and names them.
pub async fn enable(
    db: &DatabaseConnection,
    max_lists_per_issuer: u64,
) -> Result<(), ListQuotaError> {
    let txn = begin_read_committed(db).await?;
    read_switch(&txn, Some(LockType::Update)).await?;
    set_switch(&txn, true).await?;

    let max = i64::try_from(max_lists_per_issuer).unwrap_or(i64::MAX);
    // `max` is an integer, so interpolating it is safe.
    let sql = issuer_counts(&format!("actual > {max} OR list_count <> actual"));
    let offenders =
        IssuerCount::find_by_statement(Statement::from_string(db.get_database_backend(), sql))
            .all(&txn)
            .await?;
    if offenders.is_empty() {
        txn.commit().await?;
        return Ok(());
    }
    txn.rollback().await?;

    let over_quota = offenders
        .iter()
        .filter(|c| c.actual > max)
        .cloned()
        .collect();
    let miscounted = offenders
        .into_iter()
        .filter(|c| c.list_count != c.actual)
        .collect();
    Err(ListQuotaError::Refused {
        max: max_lists_per_issuer,
        over_quota,
        miscounted,
    })
}

/// The quota only bounds new lists, so issuers can be over from an earlier, higher cap.
pub async fn issuers_over(db: &DatabaseConnection, limit: u64) -> Result<Vec<IssuerCount>, DbErr> {
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    // `limit` is an integer, so interpolating it is safe.
    let sql = issuer_counts(&format!("actual > {limit}"));
    IssuerCount::find_by_statement(Statement::from_string(db.get_database_backend(), sql))
        .all(db)
        .await
}

pub fn name_issuers(issuers: &[IssuerCount]) -> String {
    let mut out = String::new();
    list_issuers(&mut out, issuers, |c| format!("{} lists", c.actual));
    out
}

/// Wrapped in an outer query since Postgres can't use the `actual` alias in HAVING.
fn issuer_counts(condition: &str) -> String {
    format!(
        "SELECT issuer, list_count, actual FROM (\
           SELECT c.issuer AS issuer, c.list_count AS list_count, COUNT(s.list_id) AS actual \
           FROM credentials c LEFT JOIN status_lists s ON s.issuer = c.issuer \
           GROUP BY c.issuer, c.list_count\
         ) counts \
         WHERE {condition} \
         ORDER BY issuer"
    )
}

pub async fn disable(db: &DatabaseConnection) -> Result<(), ListQuotaError> {
    let txn = begin_read_committed(db).await?;
    read_switch(&txn, Some(LockType::Update)).await?;
    set_switch(&txn, false).await?;
    txn.commit().await?;
    Ok(())
}

/// Refused while enforced: a recount racing enforced publishes could undercount.
pub async fn recount(db: &DatabaseConnection) -> Result<(), ListQuotaError> {
    let txn = begin_read_committed(db).await?;
    if read_switch(&txn, Some(LockType::Update)).await? {
        txn.rollback().await?;
        return Err(ListQuotaError::Enforced);
    }
    txn.execute_unprepared(RECOUNT_LIST_COUNT_SQL).await?;
    txn.commit().await?;
    Ok(())
}

async fn read_switch<C: ConnectionTrait>(conn: &C, lock: Option<LockType>) -> Result<bool, DbErr> {
    let mut query = Query::select()
        .column(ListQuota::Enforced)
        .from(ListQuota::Table)
        .and_where(Expr::col(ListQuota::Id).eq(ROW_ID))
        .to_owned();
    if let Some(lock) = lock {
        query.lock(lock);
    }
    conn.query_one_raw(conn.get_database_backend().build(&query))
        .await?
        .ok_or_else(|| DbErr::RecordNotFound("the list_quota row is missing".to_string()))?
        .try_get_by_index(0)
}

async fn set_switch(txn: &DatabaseTransaction, enforced: bool) -> Result<(), DbErr> {
    let update = Query::update()
        .table(ListQuota::Table)
        .value(ListQuota::Enforced, enforced)
        .and_where(Expr::col(ListQuota::Id).eq(ROW_ID))
        .to_owned();
    txn.execute_raw(txn.get_database_backend().build(&update))
        .await?;
    Ok(())
}
