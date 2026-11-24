//! Fresh databases enforce the quota at once; upgraded ones wait for recount and enable.
//! Both lock the switch row exclusively, and publish re-reads it shared, so nothing slips past.

use std::{collections::HashMap, fmt::Write};

use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbErr, DeriveIden,
    EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter, QuerySelect, Statement,
    sea_query::{Expr, ExprTrait, LockType, Query},
};

use super::migrations::RECOUNT_LIST_COUNT_SQL;
use super::models::{issuers, status_lists};
use super::store::begin_read_committed;
use crate::domain::models::tier::{IssuerTier, Tiers};
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
    #[error("status list {0} was not found")]
    ListNotFound(String),
    #[error("status list {0} is already retired")]
    AlreadyRetired(String),
    #[error("status list {0} is not retired")]
    NotRetired(String),
    #[error("issuer {issuer} has {count} active lists; unretiring would exceed {max}")]
    UnretireOverQuota {
        issuer: String,
        count: i64,
        max: u64,
    },
    #[error("status list owner {0} is missing from issuers")]
    MissingIssuer(String),
    #[error("status list {0} changed owner during retirement")]
    OwnerChanged(String),
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
            "\n  {} issuer(s) have more than {max} active status lists; retire lists or raise \
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

#[derive(Debug, FromQueryResult)]
pub struct IssuerStatus {
    pub issuer: String,
    pub active: i64,
    pub retired: i64,
}

pub async fn issuer_status(db: &DatabaseConnection) -> Result<Vec<IssuerStatus>, DbErr> {
    let sql = "SELECT a.issuer AS issuer, \
        COUNT(CASE WHEN s.retired_at IS NULL THEN s.list_id END) AS active, \
        COUNT(CASE WHEN s.retired_at IS NOT NULL THEN s.list_id END) AS retired \
        FROM issuers a LEFT JOIN status_lists s ON s.issuer = a.issuer \
        GROUP BY a.issuer ORDER BY a.issuer";
    IssuerStatus::find_by_statement(Statement::from_string(db.get_database_backend(), sql))
        .all(db)
        .await
}

/// Wrapped in an outer query since Postgres can't use the `actual` alias in HAVING.
fn issuer_counts(condition: &str) -> String {
    format!(
        "SELECT issuer, list_count, actual FROM (\
           SELECT a.issuer AS issuer, a.list_count AS list_count, COUNT(s.list_id) AS actual \
           FROM issuers a LEFT JOIN status_lists s ON s.issuer = a.issuer AND s.retired_at IS NULL \
           GROUP BY a.issuer, a.list_count\
         ) counts \
         WHERE {condition} \
         ORDER BY issuer"
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetirementChange {
    pub list_id: String,
    pub issuer: String,
    pub active_count: i64,
}

pub async fn set_retired(
    db: &DatabaseConnection,
    list_ids: &[String],
    retired: bool,
    tiers: &Tiers,
    registry_tiers: &HashMap<String, IssuerTier>,
) -> Result<Vec<RetirementChange>, ListQuotaError> {
    let txn = begin_read_committed(db).await?;
    // The switch lock serializes this operation with recount and enable when either is running.
    read_switch(&txn, Some(LockType::Share)).await?;
    let mut ordered = Vec::with_capacity(list_ids.len());
    for list_id in list_ids {
        let row = status_lists::Entity::find_by_id(list_id)
            .one(&txn)
            .await?
            .ok_or_else(|| ListQuotaError::ListNotFound(list_id.clone()))?;
        ordered.push((row.issuer, list_id.clone()));
    }
    ordered.sort();
    ordered.dedup();

    let mut changes = Vec::with_capacity(ordered.len());
    for (issuer, list_id) in ordered {
        match set_retired_one(&txn, &issuer, &list_id, retired, tiers, registry_tiers).await {
            Ok(change) => changes.push(change),
            Err(error) => {
                txn.rollback().await?;
                return Err(error);
            }
        }
    }
    txn.commit().await?;
    for change in &changes {
        tracing::info!(
            list_id = %change.list_id,
            issuer = %change.issuer,
            active_count = change.active_count,
            retired,
            "status list retirement changed"
        );
    }
    Ok(changes)
}

async fn set_retired_one(
    txn: &DatabaseTransaction,
    issuer: &str,
    list_id: &str,
    retired: bool,
    tiers: &Tiers,
    registry_tiers: &HashMap<String, IssuerTier>,
) -> Result<RetirementChange, ListQuotaError> {
    let owner = issuers::Entity::find_by_id(issuer)
        .lock_exclusive()
        .one(txn)
        .await?
        .ok_or_else(|| ListQuotaError::MissingIssuer(issuer.to_owned()))?;
    let row = status_lists::Entity::find_by_id(list_id)
        .one(txn)
        .await?
        .ok_or_else(|| ListQuotaError::ListNotFound(list_id.to_owned()))?;
    if row.issuer != issuer {
        return Err(ListQuotaError::OwnerChanged(list_id.to_owned()));
    }
    if row.retired_at.is_some() == retired {
        return Err(if retired {
            ListQuotaError::AlreadyRetired(list_id.to_owned())
        } else {
            ListQuotaError::NotRetired(list_id.to_owned())
        });
    }

    let tier = if owner.source == "portal" {
        IssuerTier::from_name_or_strictest(&owner.tier)
    } else {
        registry_tiers
            .get(issuer)
            .copied()
            .unwrap_or(IssuerTier::Sandbox)
    };
    let max = tiers.get(tier).max_lists;
    let limit = i64::try_from(max).unwrap_or(i64::MAX);
    let actual = status_lists::Entity::find()
        .filter(status_lists::Column::Issuer.eq(issuer))
        .filter(status_lists::Column::RetiredAt.is_null())
        .count(txn)
        .await?;
    let count = i64::try_from(actual).unwrap_or(i64::MAX);
    if !retired && count >= limit {
        return Err(ListQuotaError::UnretireOverQuota {
            issuer: issuer.to_owned(),
            count,
            max,
        });
    }
    let active_count = count + if retired { -1 } else { 1 };
    let updated = status_lists::Entity::update_many()
        .col_expr(
            status_lists::Column::RetiredAt,
            Expr::value(retired.then(|| time::OffsetDateTime::now_utc().unix_timestamp())),
        )
        .filter(status_lists::Column::ListId.eq(list_id))
        .exec(txn)
        .await?;
    if updated.rows_affected != 1 {
        return Err(ListQuotaError::ListNotFound(list_id.to_owned()));
    }
    issuers::Entity::update_many()
        .col_expr(issuers::Column::ListCount, Expr::value(active_count))
        .filter(issuers::Column::Issuer.eq(issuer))
        .exec(txn)
        .await?;
    Ok(RetirementChange {
        list_id: list_id.to_owned(),
        issuer: issuer.to_owned(),
        active_count,
    })
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
