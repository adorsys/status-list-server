#[cfg(test)]
mod tests;

use arc_swap::ArcSwap;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    DatabaseTransaction, DbErr, EntityTrait, IsolationLevel, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, Statement, TransactionTrait, Value,
    sea_query::{Expr, ExprTrait, OnConflict},
};
use std::{collections::BTreeSet, sync::Arc};
use tracing::warn;

use super::error::{RepositoryError, contention_err};
use super::list_quota::list_quota_enforced;
use super::models::{
    Credentials, StatusListHistoryRecord, StatusListRecord, credentials, issuers,
    status_list_allocations, status_list_history, status_lists,
};
use crate::{
    domain::models::status_list::choose_unallocated_indices, utils::metrics_db::time_query,
};

#[derive(Clone)]
pub struct SeaOrmStore<T> {
    db: Arc<SwappableDatabaseConnection>,
    _phantom: std::marker::PhantomData<T>,
}

pub struct SwappableDatabaseConnection {
    active: ArcSwap<DatabaseConnection>,
}

impl SwappableDatabaseConnection {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self {
            active: ArcSwap::from(db),
        }
    }

    pub fn current(&self) -> Arc<DatabaseConnection> {
        self.active.load_full()
    }

    pub fn swap(&self, db: Arc<DatabaseConnection>) -> Arc<DatabaseConnection> {
        self.active.swap(db)
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod swappable_tests {
    use super::*;

    #[tokio::test]
    async fn swap_replaces_active_pool_and_returns_previous_pool() {
        let first = Arc::new(
            sea_orm::Database::connect("sqlite::memory:")
                .await
                .expect("first sqlite pool"),
        );
        let second = Arc::new(
            sea_orm::Database::connect("sqlite::memory:")
                .await
                .expect("second sqlite pool"),
        );
        let swappable = SwappableDatabaseConnection::new(first.clone());

        let old = swappable.swap(second.clone());

        assert!(Arc::ptr_eq(&old, &first));
        assert!(Arc::ptr_eq(&swappable.current(), &second));
    }
}

impl<T> SeaOrmStore<T> {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self::from_handle(Arc::new(SwappableDatabaseConnection::new(db)))
    }

    pub fn from_handle(db: Arc<SwappableDatabaseConnection>) -> Self {
        Self {
            db,
            _phantom: std::marker::PhantomData,
        }
    }

    /// The active pooled connection, for adapters that issue their own reads.
    pub(crate) fn current(&self) -> Arc<DatabaseConnection> {
        self.db.current()
    }

    /// Begins a transaction pinned to READ COMMITTED, so PostgreSQL and MySQL
    /// run at the same level rather than at their differing defaults (READ
    /// COMMITTED and REPEATABLE READ).
    ///
    /// Used by every client-facing write: both publish paths, both update paths,
    /// and credential registration. Deliberately *not* used by
    /// `delete_older_than`, which is a batched background sweep and inherits the
    /// server default.
    ///
    /// The guard does not need it — `UPDATE ... WHERE` is a current read on both
    /// engines, and the only `SELECT`s are on `reserve_list_slot`'s rejection
    /// path, which relies on seeing rows committed while it waited. Pinning buys:
    ///
    /// - A raised server default (`default_transaction_isolation`,
    ///   `transaction_isolation`) can no longer turn a guard miss into a
    ///   serialization failure.
    /// - On InnoDB, READ COMMITTED drops next-key locks. Snapshot inserts all
    ///   land in the same gap of `idx_status_list_history_exp`, which the
    ///   retention sweep also scans, so this removes a real source of `1213`.
    ///   This applies to every stock MySQL deployment, since REPEATABLE READ is
    ///   the InnoDB default.
    ///
    /// Cost is three extra round trips per write (`SET TRANSACTION`, `BEGIN`,
    /// `COMMIT`); sea-orm issues the isolation level as its own statement.
    ///
    /// MySQL requires `binlog_format` ROW or MIXED at this level; STATEMENT
    /// fails these writes with error 1665. `verify_binlog_format` checks at boot.
    ///
    /// SQLite and the mock backend are excluded: SQLite has no per-transaction
    /// isolation and sea-orm warns on every transaction if a level is supplied.
    async fn begin_read_committed(&self) -> Result<DatabaseTransaction, DbErr> {
        begin_read_committed(&self.db.current()).await
    }
}

pub(super) async fn begin_read_committed(
    db: &DatabaseConnection,
) -> Result<DatabaseTransaction, DbErr> {
    match db.get_database_backend() {
        DatabaseBackend::Postgres | DatabaseBackend::MySql => {
            db.begin_with_config(Some(IsolationLevel::ReadCommitted), None)
                .await
        }
        _ => db.begin().await,
    }
}

/// Takes one of the issuer's quota slots with a guarded
/// `UPDATE … SET list_count = list_count + 1 WHERE list_count < max`. The row
/// lock makes concurrent publishes re-check the guard, so the quota is exact.
/// While the quota is off, the guard is lifted but the count still kept.
///
/// Must run before the `status_lists` `INSERT`: that insert's FK check takes a
/// shared lock on this ownership row, and two publishes upgrading it would
/// deadlock on InnoDB (`1213`). Being in the publish transaction, the slot is
/// rolled back with any later failure. The caller must roll back on `Err`.
///
/// An existing `list_id` is reported as `DuplicateEntry` even at a full quota,
/// so a retried publish still gets its 409.
async fn reserve_list_slot(
    txn: &DatabaseTransaction,
    issuer: &str,
    list_id: &str,
    max_lists_per_issuer: u64,
) -> Result<(), RepositoryError> {
    let max = if list_quota_enforced(txn).await.map_err(map_update_err)? {
        i64::try_from(max_lists_per_issuer).unwrap_or(i64::MAX)
    } else {
        i64::MAX
    };
    let reserved = issuers::Entity::update_many()
        .col_expr(
            issuers::Column::ListCount,
            Expr::col(issuers::Column::ListCount).add(1),
        )
        .filter(issuers::Column::Issuer.eq(issuer))
        .filter(issuers::Column::ListCount.lt(max))
        .exec(txn)
        .await
        .map_err(map_update_err)?;
    if reserved.rows_affected > 0 {
        return Ok(());
    }

    // Zero rows: either the quota is full or the ownership row is missing.
    let count = issuers::Entity::find_by_id(issuer)
        .select_only()
        .column(issuers::Column::ListCount)
        .into_tuple::<i64>()
        .one(txn)
        .await
        .map_err(find_err)?;
    match count {
        Some(count) => {
            // A same-issuer racer held the row lock we waited on, so it has committed.
            let exists = status_lists::Entity::find_by_id(list_id)
                .select_only()
                .column(status_lists::Column::ListId)
                .into_tuple::<String>()
                .one(txn)
                .await
                .map_err(find_err)?
                .is_some();
            if exists {
                return Err(RepositoryError::DuplicateEntry);
            }
            Err(RepositoryError::QuotaExceeded {
                count: u64::try_from(count).unwrap_or(0),
                max: max_lists_per_issuer,
            })
        }
        // A missing ownership row violates the FK invariant required for publishing.
        None => Err(RepositoryError::InsertError(format!(
            "issuer {issuer} has no ownership row to reserve a status list slot"
        ))),
    }
}

impl SeaOrmStore<StatusListRecord> {
    #[tracing::instrument(skip(self, entity, snapshot, allocated_indices), fields(db.system = "sea-orm"))]
    pub async fn create_status_list(
        &self,
        entity: StatusListRecord,
        snapshot: Option<StatusListHistoryRecord>,
        allocated_indices: &[i32],
        max_lists_per_issuer: u64,
    ) -> Result<(), RepositoryError> {
        match snapshot {
            Some(snapshot) => {
                self.insert_one_with_snapshot_and_allocations(
                    entity,
                    snapshot,
                    allocated_indices,
                    max_lists_per_issuer,
                )
                .await
            }
            None => {
                self.insert_one_with_allocations(entity, allocated_indices, max_lists_per_issuer)
                    .await
            }
        }
    }

    /// Pinned too, so a racing publish fails the same way with or without history.
    #[tracing::instrument(skip(self, entity), fields(db.system = "sea-orm"))]
    pub async fn insert_one(
        &self,
        entity: StatusListRecord,
        max_lists_per_issuer: u64,
    ) -> Result<(), RepositoryError> {
        self.insert_one_with_allocations(entity, &[], max_lists_per_issuer)
            .await
    }

    #[tracing::instrument(skip(self, entity, allocated_indices), fields(db.system = "sea-orm"))]
    pub async fn insert_one_with_allocations(
        &self,
        entity: StatusListRecord,
        allocated_indices: &[i32],
        max_lists_per_issuer: u64,
    ) -> Result<(), RepositoryError> {
        time_query("insert_with_allocations", "status_list", async {
            let txn = self.begin_read_committed().await.map_err(map_insert_err)?;
            if let Err(reserve_err) =
                reserve_list_slot(&txn, &entity.issuer, &entity.list_id, max_lists_per_issuer).await
            {
                txn.rollback().await.map_err(|rollback_err| {
                    RepositoryError::InsertError(format!(
                        "status list slot reservation failed ({reserve_err}); \
                         rolling the transaction back also failed: {rollback_err}"
                    ))
                })?;
                return Err(reserve_err);
            }

            let list_id = entity.list_id.clone();
            let active = status_lists::ActiveModel {
                list_id: Set(entity.list_id),
                issuer: Set(entity.issuer),
                status_list: Set(entity.status_list),
                sub: Set(entity.sub),
                updated_at: Set(entity.updated_at),
                version: Set(entity.version),
            };
            if let Err(insert_err) = status_lists::Entity::insert(active)
                .exec_without_returning(&txn)
                .await
            {
                // Roll back first: Postgres poisons the txn (25P02), MySQL may hold locks (1205).
                txn.rollback().await.map_err(|rollback_err| {
                    RepositoryError::InsertError(format!(
                        "status list insert failed ({insert_err}); \
                         rolling the transaction back also failed: {rollback_err}"
                    ))
                })?;
                return Err(map_insert_err(insert_err));
            }

            if let Err(insert_err) = insert_allocation_rows(&txn, &list_id, allocated_indices).await
            {
                txn.rollback().await.map_err(|rollback_err| {
                    RepositoryError::InsertError(format!(
                        "allocation record insert failed ({insert_err}); \
                         rolling the transaction back also failed: {rollback_err}"
                    ))
                })?;
                return Err(map_insert_err(insert_err));
            }

            txn.commit().await.map_err(map_insert_err)?;
            Ok(())
        })
        .await
    }

    /// One transaction, because nothing later repairs a list published without its first snapshot.
    #[tracing::instrument(skip(self, entity, snapshot))]
    pub async fn insert_one_with_snapshot(
        &self,
        entity: StatusListRecord,
        snapshot: StatusListHistoryRecord,
        max_lists_per_issuer: u64,
    ) -> Result<(), RepositoryError> {
        self.insert_one_with_snapshot_and_allocations(entity, snapshot, &[], max_lists_per_issuer)
            .await
    }

    #[tracing::instrument(skip(self, entity, snapshot, allocated_indices))]
    pub async fn insert_one_with_snapshot_and_allocations(
        &self,
        entity: StatusListRecord,
        snapshot: StatusListHistoryRecord,
        allocated_indices: &[i32],
        max_lists_per_issuer: u64,
    ) -> Result<(), RepositoryError> {
        time_query(
            "insert_with_snapshot_and_allocations",
            "status_list",
            async {
                #[cfg(test)]
                let probed_list_id = entity.list_id.clone();

                if snapshot.list_id != entity.list_id {
                    return Err(RepositoryError::InsertError(format!(
                        "snapshot list_id ({}) does not match entity list_id ({})",
                        snapshot.list_id, entity.list_id
                    )));
                }

                let txn = self.begin_read_committed().await.map_err(map_insert_err)?;

                if let Err(reserve_err) =
                    reserve_list_slot(&txn, &entity.issuer, &entity.list_id, max_lists_per_issuer)
                        .await
                {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::InsertError(format!(
                            "status list slot reservation failed ({reserve_err}); \
                         rolling the transaction back also failed: {rollback_err}"
                        ))
                    })?;
                    return Err(reserve_err);
                }

                let list_id = entity.list_id.clone();
                let active = status_lists::ActiveModel {
                    list_id: Set(entity.list_id),
                    issuer: Set(entity.issuer),
                    status_list: Set(entity.status_list),
                    sub: Set(entity.sub),
                    updated_at: Set(entity.updated_at),
                    version: Set(entity.version),
                };
                if let Err(insert_err) = status_lists::Entity::insert(active)
                    .exec_without_returning(&txn)
                    .await
                {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::InsertError(format!(
                            "status list insert failed ({insert_err}); \
                         rolling the transaction back also failed: {rollback_err}"
                        ))
                    })?;
                    return Err(map_insert_err(insert_err));
                }

                if let Err(insert_err) =
                    insert_allocation_rows(&txn, &list_id, allocated_indices).await
                {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::InsertError(format!(
                            "allocation record insert failed ({insert_err}); \
                         rolling the transaction back also failed: {rollback_err}"
                        ))
                    })?;
                    return Err(map_insert_err(insert_err));
                }

                let history_active: status_list_history::ActiveModel = snapshot.into();
                if let Err(insert_err) = status_list_history::Entity::insert(history_active)
                    .exec_without_returning(&txn)
                    .await
                {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::InsertError(format!(
                            "history snapshot insert failed ({insert_err}); \
                         rolling back the status list insert also failed: {rollback_err}"
                        ))
                    })?;
                    return Err(map_snapshot_insert_err(insert_err));
                }

                #[cfg(test)]
                snapshot_txn_test_hook::INSERT_BEFORE_COMMIT
                    .pause(&probed_list_id)
                    .await;

                txn.commit().await.map_err(map_insert_err)?;
                Ok(())
            },
        )
        .await
    }

    pub async fn find_one_by(
        &self,
        value: &str,
    ) -> Result<Option<StatusListRecord>, RepositoryError> {
        time_query("find_one", "status_list", async {
            let db = self.db.current();
            status_lists::Entity::find_by_id(value)
                .one(&*db)
                .await
                .map_err(find_err)
        })
        .await
    }

    #[tracing::instrument(skip(self), fields(issuer))]
    pub async fn find_all_by(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        time_query("find_all", "status_list", async {
            let db = self.db.current();
            status_lists::Entity::find()
                .filter(status_lists::Column::Issuer.eq(issuer))
                .all(&*db)
                .await
                .map(|tokens| tokens.into_iter().collect())
                .map_err(find_err)
        })
        .await
    }

    /// Ok(false) means the version guard missed: someone else wrote first, or the row is gone.
    /// `entity.version` must be greater than `expected_version`, or two writers could both match.
    #[tracing::instrument(skip(self, entity), fields(db.system = "sea-orm"))]
    pub async fn update_one(
        &self,
        list_id: &str,
        entity: StatusListRecord,
        expected_version: i64,
    ) -> Result<bool, RepositoryError> {
        if entity.version <= expected_version {
            return Err(RepositoryError::UpdateError(format!(
                "guarded update requires a strictly newer version \
                 (new={}, expected-guard={}); a non-advancing version would \
                 silently reintroduce the same-version lost update",
                entity.version, expected_version
            )));
        }
        time_query("update", "status_list", async {
            let txn = self.begin_read_committed().await.map_err(map_update_err)?;

            let result = status_lists::Entity::update_many()
                .col_expr(status_lists::Column::Issuer, Expr::value(entity.issuer))
                .col_expr(
                    status_lists::Column::StatusList,
                    Expr::value(entity.status_list),
                )
                .col_expr(status_lists::Column::Sub, Expr::value(entity.sub))
                .col_expr(
                    status_lists::Column::UpdatedAt,
                    Expr::value(entity.updated_at),
                )
                .col_expr(status_lists::Column::Version, Expr::value(entity.version))
                .filter(status_lists::Column::ListId.eq(list_id))
                .filter(status_lists::Column::Version.eq(expected_version))
                .exec(&txn)
                .await;

            let result = match result {
                Ok(result) => result,
                Err(update_err) => {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::UpdateError(format!(
                            "guarded update failed ({update_err}); \
                             rolling the transaction back also failed: {rollback_err}"
                        ))
                    })?;
                    return Err(map_update_err(update_err));
                }
            };

            txn.commit().await.map_err(map_update_err)?;
            Ok(result.rows_affected > 0)
        })
        .await
    }

    /// The row lock is held through the snapshot insert, so racers wait before getting false.
    #[tracing::instrument(skip(self, entity, snapshot), fields(db.system = "sea-orm"))]
    pub async fn update_one_with_snapshot(
        &self,
        list_id: &str,
        entity: StatusListRecord,
        expected_version: i64,
        snapshot: StatusListHistoryRecord,
    ) -> Result<bool, RepositoryError> {
        if snapshot.list_id != list_id || entity.list_id != list_id {
            return Err(RepositoryError::UpdateError(format!(
                "snapshot list_id ({}) or entity list_id ({}) does not match list_id ({})",
                snapshot.list_id, entity.list_id, list_id
            )));
        }

        if entity.version <= expected_version {
            return Err(RepositoryError::UpdateError(format!(
                "guarded update requires a strictly newer version \
                 (new={}, expected-guard={}); a non-advancing version would \
                 silently reintroduce the same-version lost update",
                entity.version, expected_version
            )));
        }

        time_query("update_with_snapshot", "status_list", async {
            let txn = self.begin_read_committed().await.map_err(map_update_err)?;

            let result = status_lists::Entity::update_many()
                .col_expr(status_lists::Column::Issuer, Expr::value(entity.issuer))
                .col_expr(
                    status_lists::Column::StatusList,
                    Expr::value(entity.status_list),
                )
                .col_expr(status_lists::Column::Sub, Expr::value(entity.sub))
                .col_expr(
                    status_lists::Column::UpdatedAt,
                    Expr::value(entity.updated_at),
                )
                .col_expr(status_lists::Column::Version, Expr::value(entity.version))
                .filter(status_lists::Column::ListId.eq(list_id))
                .filter(status_lists::Column::Version.eq(expected_version))
                .exec(&txn)
                .await;

            let result = match result {
                Ok(result) => result,
                Err(update_err) => {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::UpdateError(format!(
                            "guarded update failed ({update_err}); \
                             rolling the transaction back also failed: {rollback_err}"
                        ))
                    })?;
                    return Err(map_update_err(update_err));
                }
            };

            if result.rows_affected == 0 {
                if let Err(e) = txn.rollback().await {
                    tracing::warn!(error = ?e, "rollback of empty conflict transaction failed");
                }
                return Ok(false);
            }

            let history_active: status_list_history::ActiveModel = snapshot.into();
            if let Err(insert_err) = status_list_history::Entity::insert(history_active)
                .exec_without_returning(&txn)
                .await
            {
                txn.rollback().await.map_err(|rollback_err| {
                    RepositoryError::InsertError(format!(
                        "history snapshot insert failed ({insert_err}); \
                         rolling back the row update also failed: {rollback_err}"
                    ))
                })?;
                return Err(map_snapshot_insert_err(insert_err));
            }

            #[cfg(test)]
            snapshot_txn_test_hook::UPDATE_BEFORE_COMMIT
                .pause(list_id)
                .await;

            txn.commit().await.map_err(map_update_err)?;
            Ok(true)
        })
        .await
    }

    /// Test-only: does not decrement `issuers.list_count`. A production
    /// caller must decrement it in the same transaction as the `DELETE`.
    #[cfg(test)]
    pub async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        time_query("delete", "status_list", async {
            let db = self.db.current();
            let result = status_lists::Entity::delete_by_id(value)
                .exec(&*db)
                .await
                .map_err(map_delete_err)?;
            Ok(result.rows_affected > 0)
        })
        .await
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        time_query("find_by_issuer", "status_list", async {
            let db = self.db.current();
            status_lists::Entity::find()
                .filter(status_lists::Column::Sub.eq(issuer))
                .all(&*db)
                .await
                .map_err(find_err)
        })
        .await
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_all(&self) -> Result<Vec<StatusListRecord>, RepositoryError> {
        time_query("find_all", "status_list", async {
            let db = self.db.current();
            status_lists::Entity::find()
                .all(&*db)
                .await
                .map_err(find_err)
        })
        .await
    }

    /// Keyset on list_id, not updated_at, which every status update moves.
    /// `after` is client-supplied, so it stays out of the span.
    #[tracing::instrument(skip(self, after), fields(db.system = "sea-orm"))]
    pub async fn find_status_list_uris_after(
        &self,
        issuer: Option<&str>,
        after: Option<&str>,
        limit: u64,
    ) -> Result<Vec<(String, String)>, RepositoryError> {
        time_query("list_uris", "status_list", async {
            let db = self.db.current();
            let mut query = status_lists::Entity::find()
                .select_only()
                .column(status_lists::Column::ListId)
                .column(status_lists::Column::Sub);
            if let Some(issuer) = issuer {
                query = query.filter(status_lists::Column::Issuer.eq(issuer));
            }
            if let Some(after) = after {
                query = query.filter(status_lists::Column::ListId.gt(after));
            }
            query
                .order_by_asc(status_lists::Column::ListId)
                .limit(limit)
                .into_tuple::<(String, String)>()
                .all(&*db)
                .await
                .map_err(find_err)
        })
        .await
    }

    pub async fn count_status_lists_by_issuer(&self, issuer: &str) -> Result<u64, RepositoryError> {
        time_query("count", "status_list", async {
            status_lists::Entity::find()
                .filter(status_lists::Column::Issuer.eq(issuer))
                .count(self.db.current().as_ref())
                .await
                .map_err(find_err)
        })
        .await
    }

    pub async fn count_status_lists_by_issuers(
        &self,
        issuer_ids: &[String],
    ) -> Result<std::collections::HashMap<String, u64>, RepositoryError> {
        if issuer_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        time_query("count_by_issuers", "status_list", async {
            let rows = status_lists::Entity::find()
                .select_only()
                .column(status_lists::Column::Issuer)
                .column_as(status_lists::Column::ListId.count(), "list_count")
                .filter(status_lists::Column::Issuer.is_in(issuer_ids.iter().cloned()))
                .group_by(status_lists::Column::Issuer)
                .into_tuple::<(String, i64)>()
                .all(self.db.current().as_ref())
                .await
                .map_err(find_err)?;
            rows.into_iter()
                .map(|(issuer, count)| {
                    u64::try_from(count)
                        .map(|count| (issuer, count))
                        .map_err(|error| RepositoryError::DataError(error.to_string()))
                })
                .collect()
        })
        .await
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_status_list_issuers(&self) -> Result<Vec<String>, RepositoryError> {
        time_query("list_issuers", "status_list", async {
            let db = self.db.current();
            status_lists::Entity::find()
                .select_only()
                .column(status_lists::Column::Issuer)
                .distinct()
                .order_by_asc(status_lists::Column::Issuer)
                .into_tuple::<String>()
                .all(&*db)
                .await
                .map_err(find_err)
        })
        .await
    }

    /// Reads the `issuers.list_count` counter the quota is enforced against,
    /// one row per issuer, rather than counting `status_lists`.
    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn list_counts_by_issuer(
        &self,
    ) -> Result<std::collections::HashMap<String, u64>, RepositoryError> {
        time_query("count_by_issuer", "issuers", async {
            let db = self.db.current();
            let rows = issuers::Entity::find()
                .select_only()
                .column(issuers::Column::Issuer)
                .column(issuers::Column::ListCount)
                .filter(issuers::Column::ListCount.gt(0))
                .into_tuple::<(String, i64)>()
                .all(&*db)
                .await
                .map_err(find_err)?;
            Ok(rows
                .into_iter()
                .map(|(issuer, count)| (issuer, u64::try_from(count).unwrap_or(0)))
                .collect())
        })
        .await
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn allocate_indices(
        &self,
        list_id: &str,
        issuer: &str,
        count: u32,
    ) -> Result<Vec<i32>, RepositoryError> {
        time_query("allocate", "status_list_allocation", async {
            let txn = self.begin_read_committed().await.map_err(map_insert_err)?;

            let lock_result = status_lists::Entity::update_many()
                .col_expr(
                    status_lists::Column::UpdatedAt,
                    Expr::col(status_lists::Column::UpdatedAt),
                )
                .filter(status_lists::Column::ListId.eq(list_id))
                .exec(&txn)
                .await;
            match lock_result {
                Ok(result) if result.rows_affected == 1 => {}
                Ok(_) => {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::UpdateError(format!(
                            "allocation parent-list lock matched no row; rollback failed: {rollback_err}"
                        ))
                    })?;
                    return Err(RepositoryError::NotFound);
                }
                Err(update_err) => {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::UpdateError(format!(
                            "allocation parent-list lock failed ({update_err}); \
                             rolling the transaction back also failed: {rollback_err}"
                        ))
                    })?;
                    return Err(map_update_err(update_err));
                }
            }

            let parent = match status_lists::Entity::find_by_id(list_id).one(&txn).await {
                Ok(Some(parent)) => parent,
                Ok(None) => {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::FindError(format!(
                            "allocation parent-list lookup found no row; rollback failed: {rollback_err}"
                        ))
                    })?;
                    return Err(RepositoryError::NotFound);
                }
                Err(find_error) => {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::FindError(format!(
                            "allocation parent-list lookup failed ({find_error}); \
                             rolling the transaction back also failed: {rollback_err}"
                        ))
                    })?;
                    return Err(find_err(find_error));
                }
            };
            if parent.issuer != issuer {
                txn.rollback().await.map_err(|rollback_err| {
                    RepositoryError::UpdateError(format!(
                        "allocation issuer check failed; rollback failed: {rollback_err}"
                    ))
                })?;
                return Err(RepositoryError::IssuerMismatch);
            }
            let Some(limit) = parent.status_list.size else {
                txn.rollback().await.map_err(|rollback_err| {
                    RepositoryError::UpdateError(format!(
                        "allocation fixed-size check failed; rollback failed: {rollback_err}"
                    ))
                })?;
                return Err(RepositoryError::ListNotFixedSize);
            };

            let existing = match status_list_allocations::Entity::find()
                .select_only()
                .column(status_list_allocations::Column::Idx)
                .filter(status_list_allocations::Column::ListId.eq(list_id))
                .order_by_asc(status_list_allocations::Column::Idx)
                .into_tuple::<i32>()
                .all(&txn)
                .await
            {
                Ok(existing) => existing,
                Err(find_error) => {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::FindError(format!(
                            "allocation lookup failed ({find_error}); \
                             rolling the transaction back also failed: {rollback_err}"
                        ))
                    })?;
                    return Err(find_err(find_error));
                }
            };

            let existing: BTreeSet<i32> = existing.into_iter().collect();
            let allocated = match choose_unallocated_indices(&existing, count as usize, limit) {
                Ok(allocated) => allocated,
                Err(crate::domain::models::status_list::StatusListError::AllocationExhausted) => {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::InsertError(format!(
                            "not enough indices to allocate; rollback failed: {rollback_err}"
                        ))
                    })?;
                    return Err(RepositoryError::AllocationExhausted);
                }
                Err(err) => {
                    txn.rollback().await.map_err(|rollback_err| {
                        RepositoryError::InsertError(format!(
                            "allocation selection failed ({err}); rollback failed: {rollback_err}"
                        ))
                    })?;
                    return Err(RepositoryError::InsertError(err.to_string()));
                }
            };

            if let Err(insert_err) = insert_allocation_rows(&txn, list_id, &allocated).await {
                txn.rollback().await.map_err(|rollback_err| {
                    RepositoryError::InsertError(format!(
                        "allocation insert failed ({insert_err}); \
                         rolling the transaction back also failed: {rollback_err}"
                    ))
                })?;
                return Err(map_insert_err(insert_err));
            }

            txn.commit().await.map_err(map_insert_err)?;
            Ok(allocated)
        })
        .await
    }

    #[tracing::instrument(skip(self, indices), fields(db.system = "sea-orm"))]
    pub async fn first_unallocated_index(
        &self,
        list_id: &str,
        indices: &[i32],
    ) -> Result<Option<i32>, RepositoryError> {
        if indices.is_empty() {
            return Ok(None);
        }

        time_query("first_unallocated", "status_list_allocation", async {
            let db = self.db.current();
            let allocated = status_list_allocations::Entity::find()
                .select_only()
                .column(status_list_allocations::Column::Idx)
                .filter(status_list_allocations::Column::ListId.eq(list_id))
                .filter(status_list_allocations::Column::Idx.is_in(indices.iter().copied()))
                .into_tuple::<i32>()
                .all(&*db)
                .await
                .map_err(find_err)?
                .into_iter()
                .collect::<BTreeSet<_>>();

            Ok(indices
                .iter()
                .copied()
                .find(|index| !allocated.contains(index)))
        })
        .await
    }
}

impl SeaOrmStore<StatusListHistoryRecord> {
    #[tracing::instrument(skip(self, entity), fields(db.system = "sea-orm"))]
    pub async fn insert_one(&self, entity: StatusListHistoryRecord) -> Result<(), RepositoryError> {
        time_query("insert", "snapshot", async {
            let db = self.db.current();
            let active: status_list_history::ActiveModel = entity.into();
            status_list_history::Entity::insert(active)
                .exec_without_returning(&*db)
                .await
                .map_err(map_snapshot_insert_err)?;
            Ok(())
        })
        .await
    }

    /// Snapshots overlap on purpose; the newest one in effect at `time` wins.
    /// `version` breaks ties between snapshots written in the same second.
    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_valid_at(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<Option<StatusListHistoryRecord>, RepositoryError> {
        time_query("find_valid_at", "snapshot", async {
            let db = self.db.current();
            status_list_history::Entity::find()
                .filter(status_list_history::Column::ListId.eq(list_id))
                .filter(status_list_history::Column::Iat.lte(time))
                .filter(status_list_history::Column::Exp.gt(time))
                .order_by_desc(status_list_history::Column::Iat)
                .order_by_desc(status_list_history::Column::Version)
                .one(&*db)
                .await
                .map_err(find_err)
        })
        .await
    }

    /// Batched to keep locks short; not atomic across batches, which is fine for cleanup.
    /// Postgres can't LIMIT a DELETE and MySQL rejects the subquery (1093), so the SQL differs.
    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn delete_older_than(&self, cutoff: i64) -> Result<u64, RepositoryError> {
        time_query("delete_older_than", "snapshot", async {
            const BATCH_SIZE: u64 = 500;
            let mut total_deleted: u64 = 0;

            loop {
                let db = self.db.current();
                let backend = db.get_database_backend();
                let sql = match backend {
                    DatabaseBackend::Postgres => {
                        "DELETE FROM status_list_history \
                         WHERE snapshot_id IN \
                         (SELECT snapshot_id FROM status_list_history WHERE exp < $1 LIMIT $2)"
                    }
                    DatabaseBackend::MySql => {
                        "DELETE FROM status_list_history WHERE exp < ? LIMIT ?"
                    }
                    _ => {
                        "DELETE FROM status_list_history \
                         WHERE snapshot_id IN \
                         (SELECT snapshot_id FROM status_list_history WHERE exp < ? LIMIT ?)"
                    }
                };

                let count = (*db)
                    .execute_raw(Statement::from_sql_and_values(
                        backend,
                        sql,
                        vec![Value::from(cutoff), Value::from(BATCH_SIZE)],
                    ))
                    .await
                    .map_err(map_delete_err)?
                    .rows_affected();

                total_deleted += count;

                if count < BATCH_SIZE {
                    break;
                }
            }

            if total_deleted > 0 {
                warn!(
                    deleted = total_deleted,
                    cutoff, "Deleted expired status list history snapshots"
                );
            }

            Ok(total_deleted)
        })
        .await
    }
}

impl SeaOrmStore<Credentials> {
    /// Pinned so registration cannot inherit a raised server default and turn a
    /// duplicate issuer into a serialization failure.
    pub async fn insert_one(&self, entity: Credentials) -> Result<String, RepositoryError> {
        time_query("insert", "credential", async {
            let issuer = entity.issuer.clone();
            let requested_aggregation_id = entity.aggregation_id.clone();
            let aggregation_id = requested_aggregation_id.clone().unwrap_or_else(|| {
                crate::domain::models::credential::AggregationId::generate().to_string()
            });
            let mut active: credentials::ActiveModel = entity.into();
            let txn = self.begin_read_committed().await.map_err(map_insert_err)?;
            if let Err(error) = issuers::Entity::insert(issuers::ActiveModel {
                issuer: Set(issuer.clone()),
                aggregation_id: Set(Some(aggregation_id.clone())),
                list_count: Set(0),
                ..Default::default()
            })
            .on_conflict(
                OnConflict::column(issuers::Column::Issuer)
                    .do_nothing_on([issuers::Column::Issuer])
                    .to_owned(),
            )
            .exec_without_returning(&txn)
            .await
            {
                return Err(
                    rollback_insert_failure(txn, "issuer ownership insert", map_insert_err(error))
                        .await,
                );
            }

            if let Err(error) = issuers::Entity::update_many()
                .col_expr(issuers::Column::AggregationId, Expr::value(&aggregation_id))
                .filter(issuers::Column::Issuer.eq(&issuer))
                .filter(issuers::Column::AggregationId.is_null())
                .exec(&txn)
                .await
            {
                return Err(
                    rollback_insert_failure(txn, "issuer aggregation ID update", map_insert_err(error))
                        .await,
                );
            }
            let stored_issuer = match issuers::Entity::find_by_id(&issuer).one(&txn).await {
                Ok(Some(stored_issuer)) => stored_issuer,
                Ok(None) => {
                    return Err(rollback_insert_failure(
                        txn,
                        "issuer ownership lookup",
                        RepositoryError::InsertError(
                            "issuer ownership row disappeared during credential registration"
                                .into(),
                        ),
                    )
                    .await);
                }
                Err(error) => {
                    return Err(
                        rollback_insert_failure(txn, "issuer ownership lookup", map_insert_err(error))
                            .await,
                    );
                }
            };
            let stored_aggregation_id = match stored_issuer.aggregation_id {
                Some(aggregation_id) => aggregation_id,
                None => {
                    return Err(rollback_insert_failure(
                        txn,
                        "issuer aggregation ID lookup",
                        RepositoryError::InsertError(
                            "issuer ownership row has no aggregation ID after credential registration"
                                .into(),
                        ),
                    )
                    .await);
                }
            };
            active.aggregation_id = Set(Some(stored_aggregation_id.clone()));

            if let Err(insert_err) = credentials::Entity::insert(active)
                .exec_without_returning(&txn)
                .await
            {
                return Err(
                    rollback_insert_failure(txn, "credential insert", map_insert_err(insert_err))
                        .await,
                );
            }
            txn.commit().await.map_err(map_insert_err)?;
            Ok(stored_aggregation_id)
        })
        .await
    }

    pub async fn find_one_by(&self, value: &str) -> Result<Option<Credentials>, RepositoryError> {
        time_query("find_one", "credential", async {
            let db = self.db.current();
            credentials::Entity::find_by_id(value)
                .one(&*db)
                .await
                .map(|opt| opt.map(Credentials::from))
                .map_err(find_err)
        })
        .await
    }

    /// Returns up to two rows so callers can fail closed on a duplicate kid.
    pub async fn find_credentials_by_kid(
        &self,
        kid: &str,
    ) -> Result<Vec<Credentials>, RepositoryError> {
        time_query("find_by_kid", "credential", async {
            let db = self.db.current();
            credentials::Entity::find()
                .filter(credentials::Column::KeyId.eq(kid))
                .limit(2)
                .all(&*db)
                .await
                .map(|rows| rows.into_iter().map(Credentials::from).collect())
                .map_err(find_err)
        })
        .await
    }

    /// None: unknown issuer. Some(None): registered before aggregation IDs existed.
    pub async fn find_aggregation_id(
        &self,
        issuer: &str,
    ) -> Result<Option<Option<String>>, RepositoryError> {
        time_query("find_aggregation_id", "issuer", async {
            let db = self.db.current();
            issuers::Entity::find_by_id(issuer)
                .select_only()
                .column(issuers::Column::AggregationId)
                .into_tuple::<Option<String>>()
                .one(&*db)
                .await
                .map_err(find_err)
        })
        .await
    }

    /// Sets the issuer's aggregation ID unless it already has one.
    pub async fn assign_aggregation_id(
        &self,
        issuer: &str,
        aggregation_id: &str,
    ) -> Result<(), RepositoryError> {
        time_query("assign_aggregation_id", "issuer", async {
            let txn = self.begin_read_committed().await.map_err(map_update_err)?;
            issuers::Entity::update_many()
                .col_expr(issuers::Column::AggregationId, Expr::value(aggregation_id))
                .filter(issuers::Column::Issuer.eq(issuer))
                .filter(issuers::Column::AggregationId.is_null())
                .exec(&txn)
                .await
                .map_err(map_update_err)?;
            txn.commit().await.map_err(map_update_err)?;
            Ok(())
        })
        .await
    }

    pub async fn find_issuer_by_aggregation_id(
        &self,
        aggregation_id: &str,
    ) -> Result<Option<String>, RepositoryError> {
        time_query("find_issuer_by_aggregation_id", "credential", async {
            let db = self.db.current();
            issuers::Entity::find()
                .select_only()
                .column(issuers::Column::Issuer)
                .filter(issuers::Column::AggregationId.eq(aggregation_id))
                .into_tuple::<String>()
                .one(&*db)
                .await
                .map_err(find_err)
        })
        .await
    }

    /// Reserve registry mappings atomically. Concurrent pods may insert the
    /// same mapping; rows are read back after conflict handling to reject any
    /// attempt to change either side of the association.
    pub async fn record_registry_aggregation_ids(
        &self,
        mappings: &[(String, crate::domain::models::credential::AggregationId)],
    ) -> Result<(), RepositoryError> {
        time_query(
            "record_registry_aggregation_ids",
            "issuer_aggregation",
            async {
                if mappings.is_empty() {
                    return Ok(());
                }
                let txn = self.begin_read_committed().await.map_err(map_insert_err)?;
                for (issuer, aggregation_id) in mappings {
                    let id = aggregation_id.to_string();
                    let current = issuers::Entity::find_by_id(issuer)
                        .one(&txn)
                        .await
                        .map_err(find_err)?;
                    match current {
                        Some(row) if row.aggregation_id.as_deref() == Some(id.as_str()) => {}
                        Some(row) if row.aggregation_id.is_some() => {
                            txn.rollback().await.map_err(map_insert_err)?;
                            return Err(RepositoryError::DuplicateEntry);
                        }
                        Some(_) => {
                            issuers::Entity::update_many()
                                .col_expr(issuers::Column::AggregationId, Expr::value(&id))
                                .filter(issuers::Column::Issuer.eq(issuer))
                                .filter(issuers::Column::AggregationId.is_null())
                                .exec(&txn)
                                .await
                                .map_err(map_update_err)?;
                        }
                        None => {
                            issuers::Entity::insert(issuers::ActiveModel {
                                issuer: Set(issuer.clone()),
                                aggregation_id: Set(Some(id.clone())),
                                list_count: Set(0),
                                ..Default::default()
                            })
                            .on_conflict(
                                OnConflict::column(issuers::Column::Issuer)
                                    .do_nothing_on([issuers::Column::Issuer])
                                    .to_owned(),
                            )
                            .exec_without_returning(&txn)
                            .await
                            .map_err(map_insert_err)?;
                            issuers::Entity::update_many()
                                .col_expr(issuers::Column::AggregationId, Expr::value(&id))
                                .filter(issuers::Column::Issuer.eq(issuer))
                                .filter(issuers::Column::AggregationId.is_null())
                                .exec(&txn)
                                .await
                                .map_err(map_update_err)?;
                        }
                    }
                    let by_id = issuers::Entity::find()
                        .filter(issuers::Column::AggregationId.eq(&id))
                        .one(&txn)
                        .await
                        .map_err(find_err)?;
                    if by_id.as_ref().is_none_or(|row| row.issuer != *issuer) {
                        txn.rollback().await.map_err(map_insert_err)?;
                        return Err(RepositoryError::DuplicateEntry);
                    }
                }
                txn.commit().await.map_err(map_insert_err)
            },
        )
        .await
    }

    pub async fn update_one(
        &self,
        issuer: &str,
        entity: Credentials,
    ) -> Result<bool, RepositoryError> {
        time_query("update", "credential", async {
            let db = self.db.current();
            let existing = credentials::Entity::find_by_id(issuer)
                .one(&*db)
                .await
                .map_err(find_err)?;
            if existing.is_none() {
                return Ok(false);
            }
            let active: credentials::ActiveModel = entity.into();
            active.update(&*db).await.map_err(map_update_err)?;
            Ok(true)
        })
        .await
    }

    pub async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        time_query("delete", "credential", async {
            let db = self.db.current();
            let result = credentials::Entity::delete_by_id(value)
                .exec(&*db)
                .await
                .map_err(map_delete_err)?;
            Ok(result.rows_affected > 0)
        })
        .await
    }
}

/// Classifies an insert failure, distinguishing the one case that is a client
/// conflict rather than a server fault.
///
/// Only unique-constraint violations are singled out, because only they are
/// caused by something the client can see and act on — a `list_id` or `issuer`
/// that is already taken — and they must reach the client as 409, not 500
/// (#143, #244).
///
/// Foreign-key violations deliberately fall through to `InsertError`/500.
/// Credentials and status lists both reference `issuers`; registration creates
/// the ownership row in the same transaction, so a missing owner is inconsistent data.
/// If that ever stops holding, add a `ForeignKeyConstraintViolation` arm rather
/// than widening the unique-violation one.
///
/// Order matters in the body: the duplicate-key check runs first, so a unique
/// violation is never reclassified as retryable contention.
fn map_insert_err(e: sea_orm::DbErr) -> RepositoryError {
    match e.sql_err() {
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_)) => RepositoryError::DuplicateEntry,
        _ => contention_err(&e).unwrap_or_else(|| RepositoryError::InsertError(e.to_string())),
    }
}

async fn rollback_insert_failure(
    txn: DatabaseTransaction,
    operation: &str,
    error: RepositoryError,
) -> RepositoryError {
    match txn.rollback().await {
        Ok(()) => error,
        Err(rollback_err) => RepositoryError::InsertError(format!(
            "{operation} failed ({error}); rolling the transaction back also failed: {rollback_err}"
        )),
    }
}

fn map_update_err(e: sea_orm::DbErr) -> RepositoryError {
    contention_err(&e).unwrap_or_else(|| RepositoryError::UpdateError(e.to_string()))
}

/// A unique violation here is a snapshot_id collision, not a republish, so never a 409.
fn map_snapshot_insert_err(e: sea_orm::DbErr) -> RepositoryError {
    contention_err(&e).unwrap_or_else(|| RepositoryError::InsertError(e.to_string()))
}

/// The retention sweep is the likeliest deadlock victim, so classify contention.
fn map_delete_err(e: sea_orm::DbErr) -> RepositoryError {
    contention_err(&e).unwrap_or_else(|| RepositoryError::DeleteError(e.to_string()))
}

/// Connection acquisition and transport failures map to `Unavailable` (503).
/// Other read failures remain backend errors; contention is deliberately not
/// mapped to 409 because a read did not propose conflicting state.
fn find_err(e: sea_orm::DbErr) -> RepositoryError {
    use sea_orm::{ConnAcquireErr, DbErr, RuntimeErr, SqlxError};

    let unavailable = match &e {
        DbErr::ConnectionAcquire(ConnAcquireErr::Timeout | ConnAcquireErr::ConnectionClosed) => {
            true
        }
        DbErr::Conn(RuntimeErr::SqlxError(source))
        | DbErr::Exec(RuntimeErr::SqlxError(source))
        | DbErr::Query(RuntimeErr::SqlxError(source)) => matches!(
            source.as_ref(),
            SqlxError::Io(_) | SqlxError::PoolTimedOut | SqlxError::PoolClosed
        ),
        _ => false,
    };
    if unavailable {
        tracing::error!(error = %e, "SQL read failed because the database is unavailable");
        RepositoryError::Unavailable
    } else {
        RepositoryError::FindError(e.to_string())
    }
}

const ALLOCATION_INSERT_CHUNK_ROWS: usize = 400;

async fn insert_allocation_rows<C>(conn: &C, list_id: &str, indices: &[i32]) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    for chunk in indices.chunks(ALLOCATION_INSERT_CHUNK_ROWS) {
        let rows = chunk
            .iter()
            .map(|idx| status_list_allocations::ActiveModel {
                list_id: Set(list_id.to_string()),
                idx: Set(*idx),
            });
        status_list_allocations::Entity::insert_many(rows)
            .exec_without_returning(conn)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod snapshot_txn_test_hook {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    use tokio::sync::{Mutex, oneshot};

    pub(super) struct Probe {
        #[cfg(any(feature = "mysql", feature = "postgres-tests"))]
        pub(super) list_id: String,
        pub(super) ready: oneshot::Sender<()>,
        pub(super) release: oneshot::Receiver<()>,
    }

    pub(super) struct PauseSite {
        slot: OnceLock<Mutex<HashMap<String, Probe>>>,
    }

    impl PauseSite {
        const fn new() -> Self {
            Self {
                slot: OnceLock::new(),
            }
        }

        fn slot(&self) -> &Mutex<HashMap<String, Probe>> {
            self.slot.get_or_init(|| Mutex::new(HashMap::new()))
        }

        #[cfg(any(feature = "mysql", feature = "postgres-tests"))]
        pub(super) async fn install(&self, probe_to_install: Probe) {
            let mut guard = self.slot().lock().await;
            assert!(
                !guard.contains_key(&probe_to_install.list_id),
                "only one contention probe can be installed per list at a time"
            );
            guard.insert(probe_to_install.list_id.clone(), probe_to_install);
        }

        pub(super) async fn pause(&self, list_id: &str) {
            let installed_probe = { self.slot().lock().await.remove(list_id) };

            if let Some(installed_probe) = installed_probe {
                let _ = installed_probe.ready.send(());
                let _ = installed_probe.release.await;
            }
        }
    }

    pub(super) static UPDATE_BEFORE_COMMIT: PauseSite = PauseSite::new();

    pub(super) static INSERT_BEFORE_COMMIT: PauseSite = PauseSite::new();

    #[cfg(any(feature = "mysql", feature = "postgres-tests"))]
    #[tokio::test]
    async fn probes_for_different_lists_can_coexist_without_consuming_each_other() {
        let site = PauseSite::new();
        let (ready_a, received_a) = oneshot::channel();
        let (release_a, wait_a) = oneshot::channel();
        let (ready_b, mut received_b) = oneshot::channel();
        let (release_b, wait_b) = oneshot::channel();
        site.install(Probe {
            list_id: "list-a".into(),
            ready: ready_a,
            release: wait_a,
        })
        .await;
        site.install(Probe {
            list_id: "list-b".into(),
            ready: ready_b,
            release: wait_b,
        })
        .await;

        site.pause("unrelated-list").await;
        release_a.send(()).unwrap();
        site.pause("list-a").await;
        received_a.await.unwrap();
        assert!(matches!(
            received_b.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        release_b.send(()).unwrap();
        site.pause("list-b").await;
        received_b.await.unwrap();
        site.pause("list-a").await;
    }
}
