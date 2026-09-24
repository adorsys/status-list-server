//! The switch that turns `limits.max_lists_per_issuer` on, and the operator
//! steps behind `status-list-server list-quota`.
//!
//! Pods of a release that predates the quota publish without counting, so the
//! quota ships off. After the rollout the operator runs [`recount`], then
//! [`enable`], which refuses while any issuer is over the cap or miscounted.
//!
//! Every publish reads the switch in its own transaction (see
//! [`list_quota_enforced`]); [`enable`] and [`recount`] hold the switch row's
//! exclusive lock, so no publish that reads the quota as off can run alongside
//! them. On SQLite, which has no row locks, the database lock serializes them.

use std::fmt;

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbErr, FromQueryResult, Statement,
    sea_query::{Alias, Expr, Query},
};

use super::migrations::RECOUNT_LIST_COUNT_SQL;
use super::store::begin_read_committed;

/// The id of the switch's only row in `list_quota`.
pub(crate) const ROW_ID: i32 = 1;

/// How many issuers a refusal names per reason; the total is always given.
const NAMED_ISSUERS: usize = 20;

#[derive(Debug)]
pub enum ListQuotaError {
    Db(DbErr),
    /// `recount` while the quota is enforced: a publish racing the recount
    /// could be missed, leaving the quota too generous.
    Enforced,
    /// `enable` found issuers over the cap or with a stale counter.
    Refused {
        max: u64,
        over_quota: Vec<IssuerCount>,
        miscounted: Vec<IssuerCount>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, FromQueryResult)]
pub struct IssuerCount {
    pub issuer: String,
    /// `credentials.list_count`.
    pub list_count: i64,
    /// Lists that exist.
    pub actual: i64,
}

impl From<DbErr> for ListQuotaError {
    fn from(e: DbErr) -> Self {
        Self::Db(e)
    }
}

impl std::error::Error for ListQuotaError {}

impl fmt::Display for ListQuotaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Db(e) => write!(f, "database error: {e}"),
            Self::Enforced => write!(
                f,
                "the list quota is enforced; run `list-quota disable` before recounting"
            ),
            Self::Refused {
                max,
                over_quota,
                miscounted,
            } => {
                write!(f, "refusing to enable the list quota")?;
                if !over_quota.is_empty() {
                    write!(
                        f,
                        "\n  {} issuer(s) have more than {max} status lists; delete lists or \
                         raise limits.max_lists_per_issuer:",
                        over_quota.len()
                    )?;
                    write_issuers(f, over_quota, |c| format!("{} lists", c.actual))?;
                }
                if !miscounted.is_empty() {
                    write!(
                        f,
                        "\n  {} issuer(s) have a list_count that does not match their lists; \
                         run `list-quota recount` once no pod of an older release is left:",
                        miscounted.len()
                    )?;
                    write_issuers(f, miscounted, |c| {
                        format!("list_count {}, {} lists", c.list_count, c.actual)
                    })?;
                }
                Ok(())
            }
        }
    }
}

fn write_issuers(
    f: &mut fmt::Formatter<'_>,
    issuers: &[IssuerCount],
    detail: impl Fn(&IssuerCount) -> String,
) -> fmt::Result {
    for issuer in issuers.iter().take(NAMED_ISSUERS) {
        write!(f, "\n    {} ({})", issuer.issuer, detail(issuer))?;
    }
    if issuers.len() > NAMED_ISSUERS {
        write!(f, "\n    … and {} more", issuers.len() - NAMED_ISSUERS)?;
    }
    Ok(())
}

/// Whether this publish must respect the quota. Runs in the publish
/// transaction, before the slot is taken.
///
/// Once the quota is on a plain read is enough. While it reads as off the row
/// is read again under a shared lock, which waits for an `enable` or `recount`
/// in progress: the publish then either sees the quota on, or completes before
/// the next one starts and is counted by it.
pub(crate) async fn list_quota_enforced(txn: &DatabaseTransaction) -> Result<bool, DbErr> {
    if read_switch(txn, Lock::None).await? {
        return Ok(true);
    }
    read_switch(txn, Lock::Shared).await
}

/// The switch as a pod reads it at startup.
pub async fn is_enforced(db: &DatabaseConnection) -> Result<bool, DbErr> {
    read_switch(db, Lock::None).await
}

/// Turns the quota on, unless an issuer has more than `max_lists_per_issuer`
/// lists or a `list_count` that differs from its lists; the error names them.
pub async fn enable(
    db: &DatabaseConnection,
    max_lists_per_issuer: u64,
) -> Result<(), ListQuotaError> {
    let txn = begin_read_committed(db).await?;
    read_switch(&txn, Lock::Exclusive).await?;
    set_switch(&txn, true).await?;

    let max = i64::try_from(max_lists_per_issuer).unwrap_or(i64::MAX);
    // `max` is an integer, so formatting it into the statement is safe.
    let sql = format!(
        "SELECT issuer, list_count, actual FROM (\
           SELECT c.issuer AS issuer, c.list_count AS list_count, \
             (SELECT COUNT(*) FROM status_lists s WHERE s.issuer = c.issuer) AS actual \
           FROM credentials c\
         ) counts \
         WHERE actual > {max} OR list_count <> actual \
         ORDER BY issuer"
    );
    let offenders =
        IssuerCount::find_by_statement(Statement::from_string(db.get_database_backend(), sql))
            .all(&txn)
            .await?;

    if offenders.is_empty() {
        txn.commit().await?;
        return Ok(());
    }
    txn.rollback().await?;
    let (over_quota, miscounted) = offenders.into_iter().fold(
        (Vec::new(), Vec::new()),
        |(mut over, mut miscounted), count| {
            if count.actual > max {
                over.push(count.clone());
            }
            if count.list_count != count.actual {
                miscounted.push(count);
            }
            (over, miscounted)
        },
    );
    Err(ListQuotaError::Refused {
        max: max_lists_per_issuer,
        over_quota,
        miscounted,
    })
}

/// Turns the quota off. Needed before recounting, and before rolling back to a
/// release that predates the quota.
pub async fn disable(db: &DatabaseConnection) -> Result<(), ListQuotaError> {
    let txn = begin_read_committed(db).await?;
    read_switch(&txn, Lock::Exclusive).await?;
    set_switch(&txn, false).await?;
    txn.commit().await?;
    Ok(())
}

/// Recomputes every issuer's `list_count` from the lists that exist. Refuses
/// while the quota is enforced.
pub async fn recount(db: &DatabaseConnection) -> Result<(), ListQuotaError> {
    let txn = begin_read_committed(db).await?;
    if read_switch(&txn, Lock::Exclusive).await? {
        txn.rollback().await?;
        return Err(ListQuotaError::Enforced);
    }
    txn.execute_unprepared(RECOUNT_LIST_COUNT_SQL).await?;
    txn.commit().await?;
    Ok(())
}

enum Lock {
    None,
    Shared,
    Exclusive,
}

async fn read_switch<C: ConnectionTrait>(conn: &C, lock: Lock) -> Result<bool, DbErr> {
    let mut query = Query::select();
    query
        .column(Alias::new("enforced"))
        .from(Alias::new("list_quota"))
        .and_where(Expr::col(Alias::new("id")).eq(ROW_ID));
    match lock {
        Lock::None => {}
        Lock::Shared => {
            query.lock_shared();
        }
        Lock::Exclusive => {
            query.lock_exclusive();
        }
    }
    let row = conn
        .query_one(conn.get_database_backend().build(&query))
        .await?
        .ok_or_else(|| {
            DbErr::RecordNotFound(
                "the list_quota row is missing; run this release's migrations".to_string(),
            )
        })?;
    row.try_get_by_index(0)
}

async fn set_switch(txn: &DatabaseTransaction, enforced: bool) -> Result<(), DbErr> {
    let mut update = Query::update();
    update
        .table(Alias::new("list_quota"))
        .value(Alias::new("enforced"), enforced)
        .and_where(Expr::col(Alias::new("id")).eq(ROW_ID));
    txn.execute(txn.get_database_backend().build(&update))
        .await?;
    Ok(())
}
