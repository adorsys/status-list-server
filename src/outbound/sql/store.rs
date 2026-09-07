use arc_swap::ArcSwap;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    DatabaseTransaction, DbErr, EntityTrait, IsolationLevel, QueryFilter, QueryOrder, QuerySelect,
    Set, Statement, TransactionTrait, Value, sea_query::Expr,
};
use std::sync::Arc;
use tracing::warn;

use super::error::{RepositoryError, contention_err};
use super::models::{
    Credentials, StatusListHistoryRecord, StatusListRecord, credentials, status_list_history,
    status_lists,
};
use crate::utils::metrics_db::time_query;

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
    /// engines, and no transaction here issues a `SELECT`. Pinning buys:
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
        let db = self.db.current();
        match db.get_database_backend() {
            DatabaseBackend::Postgres | DatabaseBackend::MySql => {
                db.begin_with_config(Some(IsolationLevel::ReadCommitted), None)
                    .await
            }
            _ => db.begin().await,
        }
    }
}

impl SeaOrmStore<StatusListRecord> {
    /// Pinned like `insert_one_with_snapshot`, so a racing publish reports the
    /// same error whichever path `history_retention_secs` selects.
    #[tracing::instrument(skip(self, entity), fields(db.system = "sea-orm"))]
    pub async fn insert_one(&self, entity: StatusListRecord) -> Result<(), RepositoryError> {
        time_query("insert", "status_list", async {
            let active = status_lists::ActiveModel {
                list_id: Set(entity.list_id),
                issuer: Set(entity.issuer),
                status_list: Set(entity.status_list),
                sub: Set(entity.sub),
                updated_at: Set(entity.updated_at),
            };
            let txn = self.begin_read_committed().await.map_err(map_insert_err)?;
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
            txn.commit().await.map_err(map_insert_err)?;
            Ok(())
        })
        .await
    }

    /// Like [`insert_one`](Self::insert_one), but the row `INSERT` and the
    /// `status_list_history` `INSERT` covering its initial state run in one
    /// transaction: both commit or neither does. Without this a publish whose
    /// snapshot insert fails leaves a list with no snapshot covering it, and —
    /// unlike an update — no later write repairs that hole.
    ///
    /// A duplicate `list_id` is still reported as
    /// [`RepositoryError::DuplicateEntry`] so the publish conflict keeps mapping
    /// to 409 rather than 500.
    ///
    #[tracing::instrument(skip(self, entity, snapshot))]
    pub async fn insert_one_with_snapshot(
        &self,
        entity: StatusListRecord,
        snapshot: StatusListHistoryRecord,
    ) -> Result<(), RepositoryError> {
        time_query("insert_with_snapshot", "status_list", async {
            #[cfg(test)]
            let probed_list_id = entity.list_id.clone();

            if snapshot.list_id != entity.list_id {
                return Err(RepositoryError::InsertError(format!(
                    "snapshot list_id ({}) does not match entity list_id ({})",
                    snapshot.list_id, entity.list_id
                )));
            }

            let txn = self.begin_read_committed().await.map_err(map_insert_err)?;

            let active = status_lists::ActiveModel {
                list_id: Set(entity.list_id),
                issuer: Set(entity.issuer),
                status_list: Set(entity.status_list),
                sub: Set(entity.sub),
                updated_at: Set(entity.updated_at),
            };
            if let Err(insert_err) = status_lists::Entity::insert(active)
                .exec_without_returning(&txn)
                .await
            {
                // `insert_err` is classified after the rollback, not from it: on
                // Postgres the failed statement poisons the transaction (`25P02`),
                // so reading the rollback's own error would degrade a duplicate to a
                // 500. Verified by `assert_duplicate_list_id_is_conflict`.
                //
                // Explicit rather than left to `Drop`: MySQL's 1205 rolls back only
                // the statement (`innodb_rollback_on_timeout` is `OFF`).
                //
                // A failed rollback drops the classification and returns 500 — no
                // 409 can promise "nothing landed" when the write may still land.
                txn.rollback().await.map_err(|rollback_err| {
                    RepositoryError::InsertError(format!(
                        "status list insert failed ({insert_err}); \
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
        })
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

    /// Optimistic-concurrency update guarded on `updated_at`:
    /// `UPDATE ... WHERE list_id = ? AND updated_at = ?`. `Ok(false)` means the
    /// guard did not match — a racing writer advanced the stamp, or the row is
    /// gone — so a lost update was prevented.
    ///
    /// `rows_affected` is used deliberately: its semantics are identical across
    /// the Postgres/MySQL/SQLite sea-orm backends, unlike `SELECT ... FOR UPDATE`
    /// row locking (see #143).
    ///
    /// Wrapped in a pinned transaction rather than run as a single autocommit
    /// statement. Autocommit would be correct, but this is the guarded update
    /// used when history is disabled (`history_retention_secs = 0`), and leaving
    /// it unpinned made the same race report `update_conflict` on one deployment
    /// and `write_contention` on another. Costs three extra round trips.
    ///
    /// # Caller contract
    ///
    /// `entity.updated_at` MUST be strictly greater than `expected_updated_at`.
    /// With a non-advancing stamp two same-second writers would both match
    /// `WHERE updated_at = expected` and both succeed, losing a flip. Enforced
    /// below rather than trusted.
    #[tracing::instrument(skip(self, entity), fields(db.system = "sea-orm"))]
    pub async fn update_one(
        &self,
        list_id: &str,
        entity: StatusListRecord,
        expected_updated_at: i64,
    ) -> Result<bool, RepositoryError> {
        if entity.updated_at <= expected_updated_at {
            return Err(RepositoryError::UpdateError(format!(
                "guarded update requires a strictly newer updated_at \
                 (new={}, expected-guard={}); a non-advancing stamp would \
                 silently reintroduce the same-second lost update",
                entity.updated_at, expected_updated_at
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
                .filter(status_lists::Column::ListId.eq(list_id))
                .filter(status_lists::Column::UpdatedAt.eq(expected_updated_at))
                .exec(&txn)
                .await;

            let result = match result {
                Ok(result) => result,
                Err(update_err) => {
                    // Classified after the rollback, and the classification dropped
                    // if the rollback fails — see `insert_one_with_snapshot` for why
                    // a transaction that will not roll back must not become a 409.
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

    /// Like [`update_one`](Self::update_one), but the guarded `UPDATE` and the
    /// `status_list_history` `INSERT` run in one transaction: both commit or
    /// neither does. This closes the split the plain `update_one` leaves open,
    /// where the row changes but a failing snapshot insert leaves nothing
    /// recording it. Transaction semantics are portable across all three
    /// sea-orm backends (#143). Same `false`-on-guard-miss and
    /// strictly-advancing-stamp contract as `update_one`.
    ///
    /// Concurrency cost: the `UPDATE`'s row lock is held until `COMMIT`, across
    /// the snapshot `INSERT`. A racing writer guarded on the same stamp blocks
    /// on that lock instead of reading `rows_affected == 0` immediately. It
    /// still resolves to `false`, but a conflict costs a lock wait.
    ///
    /// Pinned to READ COMMITTED, same as `update_one`.
    #[tracing::instrument(skip(self, entity, snapshot), fields(db.system = "sea-orm"))]
    pub async fn update_one_with_snapshot(
        &self,
        list_id: &str,
        entity: StatusListRecord,
        expected_updated_at: i64,
        snapshot: StatusListHistoryRecord,
    ) -> Result<bool, RepositoryError> {
        if snapshot.list_id != list_id || entity.list_id != list_id {
            return Err(RepositoryError::UpdateError(format!(
                "snapshot list_id ({}) or entity list_id ({}) does not match list_id ({})",
                snapshot.list_id, entity.list_id, list_id
            )));
        }

        if entity.updated_at <= expected_updated_at {
            return Err(RepositoryError::UpdateError(format!(
                "guarded update requires a strictly newer updated_at \
                 (new={}, expected-guard={}); a non-advancing stamp would \
                 silently reintroduce the same-second lost update",
                entity.updated_at, expected_updated_at
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
                .filter(status_lists::Column::ListId.eq(list_id))
                .filter(status_lists::Column::UpdatedAt.eq(expected_updated_at))
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

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_all_status_list_uris(&self) -> Result<Vec<String>, RepositoryError> {
        time_query("list_uris", "status_list", async {
            let db = self.db.current();
            status_lists::Entity::find()
                .select_only()
                .column(status_lists::Column::Sub)
                .group_by(status_lists::Column::Sub)
                .order_by_asc(status_lists::Column::Sub)
                .into_tuple::<String>()
                .all(&*db)
                .await
                .map_err(find_err)
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

    /// Finds the snapshot whose half-open validity interval contains `time`.
    /// Using `iat <= time < exp` ensures the token returned to a client passes
    /// the draft-21 §8.4 `iat`/`exp` validation rule.
    ///
    /// Intervals intentionally overlap: each update writes a fresh snapshot with
    /// `exp = iat + token_exp_secs` while the superseded snapshot keeps its
    /// original (later) `exp`, so both can match a `time` in the overlap. That is
    /// not an inconsistency — `ORDER BY iat DESC LIMIT 1` deterministically
    /// returns the newest snapshot in effect at `time`, which is the correct
    /// answer for "what was the status then". The memory adapter mirrors this via
    /// `max_by_key(iat)`.
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
                .one(&*db)
                .await
                .map_err(find_err)
        })
        .await
    }

    /// Deletes snapshots older than the given cutoff timestamp.
    /// Batches the delete in chunks to avoid holding long-lived locks.
    /// Returns the total number of rows deleted.
    ///
    /// Single-statement batched deletes are used per database backend:
    /// - **PostgreSQL**: Does not support direct `LIMIT` on `DELETE`. Requires
    ///   `WHERE snapshot_id IN (SELECT snapshot_id FROM ... LIMIT ...)`.
    /// - **MySQL**: Fails with Error 1093 if target table is subqueried in an `IN` clause.
    ///   Uses direct `DELETE FROM status_list_history WHERE exp < ? LIMIT ?`.
    /// - **SQLite / Fallback**: Uses subquery `WHERE snapshot_id IN (...)` with `?` parameters.
    ///
    /// Note: This operation is not atomic across batches. If interrupted,
    /// some expired snapshots may be deleted while others remain. This is
    /// acceptable for a cleanup operation; subsequent runs will clean up
    /// any remaining rows.
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
                    .execute(Statement::from_sql_and_values(
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
    pub async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        time_query("insert", "credential", async {
            let active: credentials::ActiveModel = entity.into();
            let txn = self.begin_read_committed().await.map_err(map_insert_err)?;
            if let Err(insert_err) = credentials::Entity::insert(active)
                .exec_without_returning(&txn)
                .await
            {
                txn.rollback().await.map_err(|rollback_err| {
                    RepositoryError::InsertError(format!(
                        "credential insert failed ({insert_err}); \
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
/// The only FK on the write paths is `status_lists.issuer -> credentials.issuer`,
/// and authentication resolves the issuer's credential before any handler runs,
/// so reaching this function with a missing issuer means the credential was
/// deleted mid-request — a server-side consistency failure, correctly a 500.
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

fn map_update_err(e: sea_orm::DbErr) -> RepositoryError {
    contention_err(&e).unwrap_or_else(|| RepositoryError::UpdateError(e.to_string()))
}

/// For `status_list_history` inserts, which must **not** use [`map_insert_err`].
///
/// A unique violation there is a `snapshot_id` UUID collision, not a client
/// republishing a list, so reporting `DuplicateEntry` would surface it as
/// `409 status_list_already_exists` — a lie to the caller. Guarded by
/// `test_sqlite_update_with_snapshot_is_atomic`. Contention is still classified.
fn map_snapshot_insert_err(e: sea_orm::DbErr) -> RepositoryError {
    contention_err(&e).unwrap_or_else(|| RepositoryError::InsertError(e.to_string()))
}

/// Classified because the retention sweep is the likeliest deadlock victim: it
/// scans a range of `idx_status_list_history_exp` while snapshot inserts write
/// into the top of that same range.
fn map_delete_err(e: sea_orm::DbErr) -> RepositoryError {
    contention_err(&e).unwrap_or_else(|| RepositoryError::DeleteError(e.to_string()))
}

/// Not a classifier, unlike its `map_*_err` siblings: contention maps to 409,
/// and a 409 on a read claims a conflict with state the request never proposed.
fn find_err(e: sea_orm::DbErr) -> RepositoryError {
    RepositoryError::FindError(e.to_string())
}

/// Lets a contention test hold a transaction open at a chosen point so a second
/// writer provably collides with it, rather than with an already-committed row.
///
/// Without this a "race" test is really a sequential test: the first writer has
/// already committed by the time the second starts, so the second never blocks
/// on a lock and the interesting window — one writer holding an uncommitted row
/// or index entry while another arrives — is never entered.
#[cfg(test)]
mod snapshot_txn_test_hook {
    use std::sync::OnceLock;
    use tokio::sync::{Mutex, oneshot};

    pub(super) struct Probe {
        pub(super) list_id: String,
        /// Fires once the paused writer is inside the transaction, holding its
        /// locks. The test waits on this before starting the second writer.
        pub(super) ready: oneshot::Sender<()>,
        /// The test fires this to let the paused writer commit.
        pub(super) release: oneshot::Receiver<()>,
    }

    /// One installable pause point. Each site owns its own slot so the insert
    /// and update contention tests cannot capture each other's probe.
    pub(super) struct PauseSite {
        slot: OnceLock<Mutex<Option<Probe>>>,
    }

    impl PauseSite {
        const fn new() -> Self {
            Self {
                slot: OnceLock::new(),
            }
        }

        fn slot(&self) -> &Mutex<Option<Probe>> {
            self.slot.get_or_init(|| Mutex::new(None))
        }

        #[cfg(any(feature = "mysql", feature = "postgres-tests"))]
        pub(super) async fn install(&self, probe_to_install: Probe) {
            let mut guard = self.slot().lock().await;
            assert!(
                guard.is_none(),
                "only one contention probe can be installed at a time"
            );
            *guard = Some(probe_to_install);
        }

        /// Pauses only the writer working on the probed `list_id`, and only
        /// once — the probe is taken, so every other call is a no-op and the
        /// production path is untouched for all other rows.
        pub(super) async fn pause(&self, list_id: &str) {
            let installed_probe = {
                let mut guard = self.slot().lock().await;
                if guard
                    .as_ref()
                    .is_some_and(|installed| installed.list_id == list_id)
                {
                    guard.take()
                } else {
                    None
                }
            };

            if let Some(installed_probe) = installed_probe {
                let _ = installed_probe.ready.send(());
                let _ = installed_probe.release.await;
            }
        }
    }

    /// Inside `update_one_with_snapshot`, after the snapshot INSERT, while the
    /// guarded UPDATE still holds its exclusive row lock.
    pub(super) static UPDATE_BEFORE_COMMIT: PauseSite = PauseSite::new();

    /// Inside `insert_one_with_snapshot`, after the snapshot INSERT, while the
    /// row INSERT still holds its uncommitted primary-key entry.
    pub(super) static INSERT_BEFORE_COMMIT: PauseSite = PauseSite::new();
}

#[cfg(test)]
mod tests;
