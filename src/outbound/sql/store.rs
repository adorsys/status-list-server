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

#[derive(Clone)]
pub struct SeaOrmStore<T> {
    db: Arc<DatabaseConnection>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> SeaOrmStore<T> {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
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
        match self.db.get_database_backend() {
            DatabaseBackend::Postgres | DatabaseBackend::MySql => {
                self.db
                    .begin_with_config(Some(IsolationLevel::ReadCommitted), None)
                    .await
            }
            _ => self.db.begin().await,
        }
    }
}

impl SeaOrmStore<StatusListRecord> {
    /// Pinned like `insert_one_with_snapshot`, so a racing publish reports the
    /// same error whichever path `history_retention_secs` selects.
    #[tracing::instrument(skip(self, entity), fields(db.system = "sea-orm"))]
    pub async fn insert_one(&self, entity: StatusListRecord) -> Result<(), RepositoryError> {
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
    }

    pub async fn find_one_by(
        &self,
        value: &str,
    ) -> Result<Option<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map_err(find_err)
    }

    #[tracing::instrument(skip(self), fields(issuer))]
    pub async fn find_all_by(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .filter(status_lists::Column::Issuer.eq(issuer))
            .all(&*self.db)
            .await
            .map(|tokens| tokens.into_iter().collect())
            .map_err(find_err)
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
    }

    pub async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        let result = status_lists::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(map_delete_err)?;
        Ok(result.rows_affected > 0)
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .filter(status_lists::Column::Sub.eq(issuer))
            .all(&*self.db)
            .await
            .map_err(find_err)
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_all(&self) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .all(&*self.db)
            .await
            .map_err(find_err)
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_all_status_list_uris(&self) -> Result<Vec<String>, RepositoryError> {
        status_lists::Entity::find()
            .select_only()
            .column(status_lists::Column::Sub)
            .group_by(status_lists::Column::Sub)
            .order_by_asc(status_lists::Column::Sub)
            .into_tuple::<String>()
            .all(&*self.db)
            .await
            .map_err(find_err)
    }
}

impl SeaOrmStore<StatusListHistoryRecord> {
    #[tracing::instrument(skip(self, entity), fields(db.system = "sea-orm"))]
    pub async fn insert_one(&self, entity: StatusListHistoryRecord) -> Result<(), RepositoryError> {
        let active: status_list_history::ActiveModel = entity.into();
        status_list_history::Entity::insert(active)
            .exec_without_returning(&*self.db)
            .await
            .map_err(map_snapshot_insert_err)?;
        Ok(())
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
        status_list_history::Entity::find()
            .filter(status_list_history::Column::ListId.eq(list_id))
            .filter(status_list_history::Column::Iat.lte(time))
            .filter(status_list_history::Column::Exp.gt(time))
            .order_by_desc(status_list_history::Column::Iat)
            .one(&*self.db)
            .await
            .map_err(find_err)
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
        const BATCH_SIZE: u64 = 500;
        let mut total_deleted: u64 = 0;

        loop {
            let backend = self.db.get_database_backend();
            let sql = match backend {
                DatabaseBackend::Postgres => {
                    "DELETE FROM status_list_history \
                     WHERE snapshot_id IN \
                     (SELECT snapshot_id FROM status_list_history WHERE exp < $1 LIMIT $2)"
                }
                DatabaseBackend::MySql => "DELETE FROM status_list_history WHERE exp < ? LIMIT ?",
                _ => {
                    "DELETE FROM status_list_history \
                     WHERE snapshot_id IN \
                     (SELECT snapshot_id FROM status_list_history WHERE exp < ? LIMIT ?)"
                }
            };

            let count = (*self.db)
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
    }
}

impl SeaOrmStore<Credentials> {
    /// Pinned so registration cannot inherit a raised server default and turn a
    /// duplicate issuer into a serialization failure.
    pub async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
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
    }

    pub async fn find_one_by(&self, value: &str) -> Result<Option<Credentials>, RepositoryError> {
        credentials::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map(|opt| opt.map(Credentials::from))
            .map_err(find_err)
    }

    pub async fn update_one(
        &self,
        issuer: &str,
        entity: Credentials,
    ) -> Result<bool, RepositoryError> {
        let existing = credentials::Entity::find_by_id(issuer)
            .one(&*self.db)
            .await
            .map_err(find_err)?;
        if existing.is_none() {
            return Ok(false);
        }
        let active: credentials::ActiveModel = entity.into();
        active.update(&*self.db).await.map_err(map_update_err)?;
        Ok(true)
    }

    pub async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        let result = credentials::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(map_delete_err)?;
        Ok(result.rows_affected > 0)
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

        /// Only the container tests install probes, so under any other feature
        /// set this is dead code and `-D warnings` rejects it.
        #[cfg(any(feature = "mysql", feature = "postgres-tests"))]
        pub(super) async fn install(&self, probe_to_install: Probe) {
            let mut guard = self.slot().lock().await;
            assert!(
                guard.is_none(),
                "a contention probe is already installed at this pause site"
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
mod test {
    use super::*;
    use crate::outbound::sql::models::StatusList;
    use jsonwebtoken::jwk::Jwk;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Statement, Transaction};
    // `MigratorTrait` is only needed by `sqlite_connection` below; the MySQL
    // and Postgres helpers live in `test_containers` and import it themselves.
    #[cfg(feature = "sqlite")]
    use sea_orm_migration::MigratorTrait;

    // Container fixtures live in `test_containers` because the HTTP-layer
    // publish test needs them too; the call sites below are unchanged.
    #[cfg(feature = "mysql")]
    use crate::outbound::sql::test_containers::mysql_helpers;
    #[cfg(feature = "postgres-tests")]
    use crate::outbound::sql::test_containers::postgres_helpers;

    #[cfg(feature = "sqlite")]
    async fn sqlite_connection() -> Arc<DatabaseConnection> {
        let mut opt = sea_orm::ConnectOptions::new("sqlite::memory:");
        opt.max_connections(1);
        opt.map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
        let db = sea_orm::Database::connect(opt)
            .await
            .expect("Failed to connect to SQLite");
        crate::outbound::sql::Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations on SQLite");
        Arc::new(db)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_credentials_round_trip() {
        let db = sqlite_connection().await;
        let store = SeaOrmStore::<Credentials>::new(db);

        let public_key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();

        let issuer = "issuer-cred-sqlite";
        let entity = Credentials::new(issuer.to_string(), public_key.clone());

        store.insert_one(entity.clone()).await.unwrap();

        let found = store.find_one_by(issuer).await.unwrap().unwrap();
        assert_eq!(found.issuer, issuer);
        assert_eq!(found.public_key, public_key);

        let deleted = store.delete_by(issuer).await.unwrap();
        assert!(deleted);

        let gone = store.find_one_by(issuer).await.unwrap();
        assert!(gone.is_none());
    }

    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_credentials_round_trip() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        let db = test_db.connection().await;
        let store = SeaOrmStore::<Credentials>::new(db);

        let public_key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();

        let entity = Credentials::new("issuer-mysql".to_string(), public_key.clone());

        store.insert_one(entity.clone()).await.unwrap();

        let found = store.find_one_by("issuer-mysql").await.unwrap().unwrap();
        assert_eq!(found.issuer, "issuer-mysql");
        assert_eq!(found.public_key, public_key);

        let deleted = store.delete_by("issuer-mysql").await.unwrap();
        assert!(deleted);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_status_list_round_trip() {
        let db = sqlite_connection().await;

        let cred_key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();
        let issuer = "issuer-list-sqlite";
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), cred_key))
            .await
            .unwrap();

        let store = SeaOrmStore::<StatusListRecord>::new(db);

        let record = StatusListRecord {
            list_id: "list-sqlite-test".to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "compressed".to_string(),
            },
            sub: "sub-sqlite-test".to_string(),
            updated_at: 0,
        };

        store.insert_one(record.clone()).await.unwrap();

        let found = store
            .find_one_by("list-sqlite-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.list_id, "list-sqlite-test");
        assert_eq!(found.issuer, issuer);
        assert_eq!(found.status_list, record.status_list);

        let updated = store
            .update_one(
                "list-sqlite-test",
                StatusListRecord {
                    sub: "sub-2-sqlite-test".to_string(),
                    updated_at: record.updated_at + 1, // guarded write must advance the stamp
                    ..record.clone()
                },
                record.updated_at,
            )
            .await
            .unwrap();
        assert!(updated);

        let updated_found = store
            .find_one_by("list-sqlite-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_found.sub, "sub-2-sqlite-test");
        assert_eq!(updated_found.updated_at, record.updated_at + 1);

        let by_issuer = store.find_by_issuer("sub-2-sqlite-test").await.unwrap();
        assert!(!by_issuer.is_empty());

        let deleted = store.delete_by("list-sqlite-test").await.unwrap();
        assert!(deleted);
    }

    #[tokio::test]
    async fn test_status_list_find_all() {
        let models = vec![
            status_lists::Model {
                list_id: "list1".to_string(),
                issuer: "issuer1".to_string(),
                status_list: StatusList {
                    bits: 1,
                    lst: "abc".to_string(),
                },
                sub: "https://example.com/statuslists/list1".to_string(),
                updated_at: 0,
            },
            status_lists::Model {
                list_id: "list2".to_string(),
                issuer: "issuer2".to_string(),
                status_list: StatusList {
                    bits: 8,
                    lst: "xyz".to_string(),
                },
                sub: "https://example.com/statuslists/list2".to_string(),
                updated_at: 0,
            },
        ];

        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![models.clone()])
                .into_connection(),
        );

        let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

        let records = store.find_all().await.unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].list_id, "list1");
        assert_eq!(records[0].sub, "https://example.com/statuslists/list1");
        assert_eq!(records[0].status_list.bits, 1);
        assert_eq!(records[0].status_list.lst, "abc");

        assert_eq!(records[1].list_id, "list2");
        assert_eq!(records[1].sub, "https://example.com/statuslists/list2");
        assert_eq!(records[1].status_list.bits, 8);
        assert_eq!(records[1].status_list.lst, "xyz");
    }

    #[tokio::test]
    async fn test_status_list_find_all_status_list_uris() {
        let rows = vec![
            std::collections::BTreeMap::from([(
                "sub".to_string(),
                sea_orm::Value::from("https://example.com/statuslists/a"),
            )]),
            std::collections::BTreeMap::from([(
                "sub".to_string(),
                sea_orm::Value::from("https://example.com/statuslists/b"),
            )]),
        ];

        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<std::collections::BTreeMap<String, sea_orm::Value>, Vec<_>, _>(
                    vec![rows],
                )
                .into_connection(),
        );

        let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

        let subs = store.find_all_status_list_uris().await.unwrap();

        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0], "https://example.com/statuslists/a");
        assert_eq!(subs[1], "https://example.com/statuslists/b");
    }

    #[tokio::test]
    async fn test_seaorm_store() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);

        let public_key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();

        let entity = Credentials::new("issuer1".to_string(), public_key.clone());
        let updated_entity = Credentials::new("issuer1".to_string(), public_key.clone());

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<credentials::Model, Vec<_>, _>(vec![
                    vec![credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone().into(),
                    }],
                    vec![credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone().into(),
                    }],
                    vec![credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone().into(),
                    }],
                    vec![credentials::Model {
                        issuer: updated_entity.issuer.clone(),
                        public_key: updated_entity.public_key.clone().into(),
                    }],
                ])
                .append_exec_results(vec![
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    },
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    },
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    },
                ])
                .into_connection(),
        );

        let store = SeaOrmStore::<Credentials>::new(db_conn);

        store.insert_one(entity.clone()).await.unwrap();

        let credential = store.find_one_by("issuer1").await.unwrap().unwrap();
        assert_eq!(credential.issuer, "issuer1");
        assert_eq!(credential.public_key, public_key);

        let updated = store
            .update_one("issuer1", updated_entity.clone())
            .await
            .unwrap();
        assert!(updated);

        let deleted = store.delete_by("issuer1").await.unwrap();
        assert!(deleted);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_negative_paths() {
        let db = sqlite_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db);

        let key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();

        cred_store
            .insert_one(Credentials::new(
                "issuer-neg-sqlite".to_string(),
                key.clone(),
            ))
            .await
            .unwrap();
        let dup = cred_store
            .insert_one(Credentials::new(
                "issuer-neg-sqlite".to_string(),
                key.clone(),
            ))
            .await;
        assert!(dup.is_err(), "duplicate PK insert should fail");

        let rec = StatusListRecord {
            list_id: "list-neg-sqlite".to_string(),
            issuer: "nonexistent-issuer".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "compressed".to_string(),
            },
            sub: "sub-neg-sqlite".to_string(),
            updated_at: 0,
        };
        let fk_err = store.insert_one(rec).await;
        assert!(fk_err.is_err(), "insert with dangling FK should fail");

        let missing = store
            .update_one(
                "missing-list-sqlite",
                StatusListRecord {
                    list_id: "missing-list-sqlite".to_string(),
                    issuer: "issuer-neg-sqlite".to_string(),
                    status_list: StatusList {
                        bits: 1,
                        lst: "compressed".to_string(),
                    },
                    sub: "sub-neg-sqlite".to_string(),
                    updated_at: 1, // must advance past the guard value below
                },
                0,
            )
            .await
            .unwrap();
        assert!(!missing, "update on missing row should report no rows");

        cred_store.delete_by("issuer-neg-sqlite").await.unwrap();
    }

    /// A duplicate primary key must surface as `DuplicateEntry`, not a generic
    /// insert error — the one property a mock cannot verify, since it depends on
    /// the real driver's error parsing into `SqlErr::UniqueConstraintViolation`.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_duplicate_insert_maps_to_duplicate_entry() {
        let db = sqlite_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db);

        let key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();
        let issuer = "issuer-dup-sqlite";
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key.clone()))
            .await
            .unwrap();

        // Duplicate credential (same issuer primary key).
        let dup_cred = cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await;
        assert!(
            matches!(dup_cred, Err(RepositoryError::DuplicateEntry)),
            "duplicate credential insert must map to DuplicateEntry, got {dup_cred:?}"
        );

        // Duplicate status list (same list_id primary key).
        let record = StatusListRecord {
            list_id: "list-dup-sqlite".to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-dup-sqlite".to_string(),
            updated_at: 0,
        };
        store.insert_one(record.clone()).await.unwrap();
        let dup_list = store.insert_one(record).await;
        assert!(
            matches!(dup_list, Err(RepositoryError::DuplicateEntry)),
            "duplicate status list insert must map to DuplicateEntry, got {dup_list:?}"
        );
    }

    /// Cross-backend proof (#143): MySQL's duplicate-key error must also parse
    /// into `SqlErr::UniqueConstraintViolation`, where the driver format could
    /// diverge from sqlite.
    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_duplicate_insert_maps_to_duplicate_entry() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        let db = test_db.connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db);

        let key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();
        let issuer = "issuer-dup-mysql";
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key.clone()))
            .await
            .unwrap();

        let dup_cred = cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await;
        assert!(
            matches!(dup_cred, Err(RepositoryError::DuplicateEntry)),
            "duplicate credential insert must map to DuplicateEntry on MySQL, got {dup_cred:?}"
        );

        let record = StatusListRecord {
            list_id: "list-dup-mysql".to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-dup-mysql".to_string(),
            updated_at: 0,
        };
        store.insert_one(record.clone()).await.unwrap();
        let dup_list = store.insert_one(record).await;
        assert!(
            matches!(dup_list, Err(RepositoryError::DuplicateEntry)),
            "duplicate status list insert must map to DuplicateEntry on MySQL, got {dup_list:?}"
        );
    }

    /// The lost-update proof: two writers reading the same `updated_at` cannot
    /// both win. Deterministic (no threads) — first write lands, second's guard
    /// misses — and the loser's flip must not overwrite the winner's.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_update_one_optimistic_guard_rejects_stale_write() {
        let db = sqlite_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db);

        let key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();
        let issuer = "issuer-guard-sqlite";
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        // Seed a row at a known guard value V.
        let v = 1000;
        let base = StatusListRecord {
            list_id: "list-guard-sqlite".to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-guard-sqlite".to_string(),
            updated_at: v,
        };
        store.insert_one(base.clone()).await.unwrap();

        // Both writers read the same state, so both guard on V.
        let writer_a = StatusListRecord {
            status_list: StatusList {
                bits: 1,
                lst: "flip-A".to_string(),
            },
            updated_at: v + 1,
            ..base.clone()
        };
        let writer_b = StatusListRecord {
            status_list: StatusList {
                bits: 1,
                lst: "flip-B".to_string(),
            },
            updated_at: v + 1,
            ..base.clone()
        };

        // First writer wins.
        let a_won = store.update_one(&base.list_id, writer_a, v).await.unwrap();
        assert!(a_won, "first guarded write should land");

        // Second writer guarded on the now-stale V: rejected, not silently applied.
        let b_won = store.update_one(&base.list_id, writer_b, v).await.unwrap();
        assert!(!b_won, "stale guarded write must be rejected");

        // A's flip survived; B's did not overwrite it.
        let stored = store.find_one_by(&base.list_id).await.unwrap().unwrap();
        assert_eq!(stored.status_list.lst, "flip-A");
        assert_eq!(stored.updated_at, v + 1);
    }

    /// A client that loses the optimistic guard should be able to follow the
    /// contract exposed at the HTTP layer: observe 409, re-read, and retry with
    /// the fresh `updated_at`. If the guard ever becomes permanently
    /// unmatchable, this test fails on the retry.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_update_one_conflict_loser_can_reread_and_retry() {
        let db = sqlite_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db);

        let key: Jwk = serde_json::from_str(TEST_EC_JWK).unwrap();
        let issuer = "issuer-retry-sqlite";
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let v = 1000;
        let base = StatusListRecord {
            list_id: "list-retry-sqlite".to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-retry-sqlite".to_string(),
            updated_at: v,
        };
        store.insert_one(base.clone()).await.unwrap();

        let writer_a = StatusListRecord {
            status_list: StatusList {
                bits: 1,
                lst: "flip-A".to_string(),
            },
            updated_at: v + 1,
            ..base.clone()
        };
        let stale_writer_b = StatusListRecord {
            status_list: StatusList {
                bits: 1,
                lst: "flip-B-stale".to_string(),
            },
            updated_at: v + 1,
            ..base.clone()
        };

        assert!(store.update_one(&base.list_id, writer_a, v).await.unwrap());
        assert!(
            !store
                .update_one(&base.list_id, stale_writer_b, v)
                .await
                .unwrap(),
            "B should lose the stale guard first"
        );

        let reread = store.find_one_by(&base.list_id).await.unwrap().unwrap();
        assert_eq!(reread.updated_at, v + 1);

        let retry_writer_b = StatusListRecord {
            status_list: StatusList {
                bits: 1,
                lst: "flip-B-retry".to_string(),
            },
            updated_at: reread.updated_at + 1,
            ..reread.clone()
        };
        assert!(
            store
                .update_one(&base.list_id, retry_writer_b, reread.updated_at)
                .await
                .unwrap(),
            "B's retry with the fresh guard should succeed"
        );

        let final_row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
        assert_eq!(final_row.status_list.lst, "flip-B-retry");
        assert_eq!(final_row.updated_at, v + 2);
    }

    /// Cross-backend proof (#143): the optimistic guard behaves identically on
    /// MySQL, exercising the JSON `col_expr` write and `rows_affected` semantics
    /// most likely to diverge from sqlite.
    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_update_one_optimistic_guard_rejects_stale_write() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        let db = test_db.connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db);

        let key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();
        let issuer = "issuer-guard-mysql";
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let v = 1000;
        let base = StatusListRecord {
            list_id: "list-guard-mysql".to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-guard-mysql".to_string(),
            updated_at: v,
        };
        store.insert_one(base.clone()).await.unwrap();

        let writer_a = StatusListRecord {
            status_list: StatusList {
                bits: 1,
                lst: "flip-A".to_string(),
            },
            updated_at: v + 1,
            ..base.clone()
        };
        let writer_b = StatusListRecord {
            status_list: StatusList {
                bits: 1,
                lst: "flip-B".to_string(),
            },
            updated_at: v + 1,
            ..base.clone()
        };

        // First writer wins.
        let a_won = store.update_one(&base.list_id, writer_a, v).await.unwrap();
        assert!(a_won, "first guarded write should land on MySQL");

        // Second writer guarded on the now-stale V: rejected.
        let b_won = store.update_one(&base.list_id, writer_b, v).await.unwrap();
        assert!(!b_won, "stale guarded write must be rejected on MySQL");

        // A's flip survived and round-tripped through the JSON column.
        let stored = store.find_one_by(&base.list_id).await.unwrap().unwrap();
        assert_eq!(stored.status_list.lst, "flip-A");
        assert_eq!(stored.updated_at, v + 1);
    }

    /// A guarded write whose `updated_at` does not strictly advance past the
    /// guard is rejected before touching the DB, so a caller that forgets to
    /// advance the stamp fails loudly. The check precedes the query, so this
    /// runs on the mock backend.
    #[tokio::test]
    async fn test_update_one_rejects_non_advancing_stamp() {
        let db_conn = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

        let entity = StatusListRecord {
            list_id: "list-x".to_string(),
            issuer: "issuer".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "x".to_string(),
            },
            sub: "sub".to_string(),
            updated_at: 1000,
        };

        // new == expected: not advancing.
        let equal = store.update_one("list-x", entity.clone(), 1000).await;
        assert!(matches!(equal, Err(RepositoryError::UpdateError(_))));

        // new < expected: going backwards.
        let backwards = store.update_one("list-x", entity, 1001).await;
        assert!(matches!(backwards, Err(RepositoryError::UpdateError(_))));
    }

    #[tokio::test]
    async fn test_update_one_with_snapshot_rejects_non_advancing_stamp() {
        let db_conn = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

        let entity = StatusListRecord {
            list_id: "list-x".to_string(),
            issuer: "issuer".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "x".to_string(),
            },
            sub: "sub".to_string(),
            updated_at: 1000,
        };
        let snapshot = StatusListHistoryRecord {
            snapshot_id: "snapshot-x".to_string(),
            list_id: entity.list_id.clone(),
            issuer: entity.issuer.clone(),
            status_list: entity.status_list.clone(),
            sub: entity.sub.clone(),
            iat: entity.updated_at,
            exp: entity.updated_at + 900,
        };

        let equal = store
            .update_one_with_snapshot("list-x", entity.clone(), 1000, snapshot.clone())
            .await;
        assert!(matches!(equal, Err(RepositoryError::UpdateError(_))));

        let backwards = store
            .update_one_with_snapshot("list-x", entity, 1001, snapshot)
            .await;
        assert!(matches!(backwards, Err(RepositoryError::UpdateError(_))));
    }

    #[tokio::test]
    async fn test_update_one_with_snapshot_transaction_log_shape() {
        let entity = StatusListRecord {
            list_id: "list-txn".to_string(),
            issuer: "issuer-txn".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "flip".to_string(),
            },
            sub: "sub-txn".to_string(),
            updated_at: 1001,
        };
        let snapshot = StatusListHistoryRecord {
            snapshot_id: "snap-txn".to_string(),
            list_id: entity.list_id.clone(),
            issuer: entity.issuer.clone(),
            status_list: entity.status_list.clone(),
            sub: entity.sub.clone(),
            iat: entity.updated_at,
            exp: entity.updated_at + 900,
        };

        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_exec_results([
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    },
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    },
                ])
                .into_connection(),
        );
        let store = SeaOrmStore::<StatusListRecord>::new(db_conn.clone());

        assert!(
            store
                .update_one_with_snapshot("list-txn", entity.clone(), 1000, snapshot.clone())
                .await
                .unwrap()
        );

        drop(store);
        let db_conn = Arc::try_unwrap(db_conn).expect("test should own the only DB handle");
        assert_eq!(
            db_conn.into_transaction_log(),
            [Transaction::many([
                Statement::from_string(DatabaseBackend::Postgres, "BEGIN"),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "status_lists" SET "issuer" = $1, "status_list" = $2, "sub" = $3, "updated_at" = $4 WHERE "status_lists"."list_id" = $5 AND "status_lists"."updated_at" = $6"#,
                    [
                        entity.issuer.clone().into(),
                        serde_json::to_value(entity.status_list.clone())
                            .unwrap()
                            .into(),
                        entity.sub.clone().into(),
                        entity.updated_at.into(),
                        "list-txn".into(),
                        1000i64.into(),
                    ],
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "status_list_history" ("snapshot_id", "list_id", "issuer", "status_list", "sub", "iat", "exp") VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
                    [
                        snapshot.snapshot_id.clone().into(),
                        snapshot.list_id.clone().into(),
                        snapshot.issuer.clone().into(),
                        serde_json::to_value(snapshot.status_list.clone())
                            .unwrap()
                            .into(),
                        snapshot.sub.clone().into(),
                        snapshot.iat.into(),
                        snapshot.exp.into(),
                    ],
                ),
                Statement::from_string(DatabaseBackend::Postgres, "COMMIT"),
            ])]
        );

        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_exec_results([MockExecResult {
                    rows_affected: 0,
                    last_insert_id: 0,
                }])
                .into_connection(),
        );
        let store = SeaOrmStore::<StatusListRecord>::new(db_conn.clone());

        assert!(
            !store
                .update_one_with_snapshot("list-txn", entity.clone(), 1000, snapshot)
                .await
                .unwrap()
        );

        drop(store);
        let db_conn = Arc::try_unwrap(db_conn).expect("test should own the only DB handle");
        assert_eq!(
            db_conn.into_transaction_log(),
            [Transaction::many([
                Statement::from_string(DatabaseBackend::Postgres, "BEGIN"),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "status_lists" SET "issuer" = $1, "status_list" = $2, "sub" = $3, "updated_at" = $4 WHERE "status_lists"."list_id" = $5 AND "status_lists"."updated_at" = $6"#,
                    [
                        entity.issuer.into(),
                        serde_json::to_value(entity.status_list).unwrap().into(),
                        entity.sub.into(),
                        entity.updated_at.into(),
                        "list-txn".into(),
                        1000i64.into(),
                    ],
                ),
                Statement::from_string(DatabaseBackend::Postgres, "ROLLBACK"),
            ])]
        );
    }

    #[cfg(feature = "sqlite")]
    const TEST_EC_JWK: &str = crate::test_fixtures::TEST_EC_PUBLIC_JWK;

    /// failure rollback (no partial snapshot), and the conflict path — against
    /// real SQLite, since `MockDatabase` cannot model rollback.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_update_with_snapshot_is_atomic() {
        let db = sqlite_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
        let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

        let key: Jwk = serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        let issuer = "issuer-atomic-sqlite";
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let v = 1000;
        let base = StatusListRecord {
            list_id: "list-atomic-sqlite".to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-atomic-sqlite".to_string(),
            updated_at: v,
        };
        store.insert_one(base.clone()).await.unwrap();

        // --- Happy path: row update and snapshot both commit. ---
        let good_snapshot = StatusListHistoryRecord {
            snapshot_id: "snap-good".to_string(),
            list_id: base.list_id.clone(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "flip-1".to_string(),
            },
            sub: base.sub.clone(),
            iat: v + 1,
            exp: v + 1 + 900,
        };
        let committed = store
            .update_one_with_snapshot(
                &base.list_id,
                StatusListRecord {
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-1".to_string(),
                    },
                    updated_at: v + 1,
                    ..base.clone()
                },
                v,
                good_snapshot,
            )
            .await
            .unwrap();
        assert!(
            committed,
            "advancing guarded update with snapshot must commit"
        );
        let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
        assert_eq!(row.updated_at, v + 1);
        assert_eq!(row.status_list.lst, "flip-1");
        assert!(
            history
                .find_valid_at(&base.list_id, v + 1)
                .await
                .unwrap()
                .is_some(),
            "the committed snapshot must be resolvable"
        );

        // --- Rollback path: force the snapshot INSERT to fail (duplicate PK)
        // and assert the paired row update did NOT land. ---
        let colliding_snapshot = StatusListHistoryRecord {
            snapshot_id: "snap-good".to_string(), // collides with the committed row
            list_id: base.list_id.clone(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "flip-2".to_string(),
            },
            sub: base.sub.clone(),
            iat: v + 2,
            exp: v + 2 + 900,
        };
        let result = store
            .update_one_with_snapshot(
                &base.list_id,
                StatusListRecord {
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-2".to_string(),
                    },
                    updated_at: v + 2,
                    ..base.clone()
                },
                v + 1,
                colliding_snapshot,
            )
            .await;
        assert!(
            matches!(result, Err(RepositoryError::InsertError(_))),
            "a failed snapshot insert must fail the whole unit as a plain \
             insert error, got {result:?}"
        );
        let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
        assert_eq!(
            row.updated_at,
            v + 1,
            "row stamp must roll back when the snapshot insert fails"
        );
        assert_eq!(
            row.status_list.lst, "flip-1",
            "row content must roll back when the snapshot insert fails"
        );
        // No partial snapshot for the rolled-back update: what resolves at v+2 is
        // still the previously committed snapshot, not the flip-2 attempt.
        let resolved = history
            .find_valid_at(&base.list_id, v + 2)
            .await
            .unwrap()
            .expect("the earlier committed snapshot still covers v+2");
        assert_eq!(
            resolved.status_list.lst, "flip-1",
            "no partial snapshot from the rolled-back update may exist"
        );

        // --- Conflict path: a stale guard rolls back cleanly and records
        // nothing. ---
        let conflict = store
            .update_one_with_snapshot(
                &base.list_id,
                StatusListRecord {
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-3".to_string(),
                    },
                    updated_at: v + 5,
                    ..base.clone()
                },
                v, // stale: the row is at v+1 now
                StatusListHistoryRecord {
                    snapshot_id: "snap-conflict".to_string(),
                    list_id: base.list_id.clone(),
                    issuer: issuer.to_string(),
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-3".to_string(),
                    },
                    sub: base.sub.clone(),
                    iat: v + 5,
                    exp: v + 5 + 900,
                },
            )
            .await
            .unwrap();
        assert!(!conflict, "stale guard must report no rows and roll back");
        let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
        assert_eq!(row.updated_at, v + 1, "conflict must not change the row");
        let resolved = history
            .find_valid_at(&base.list_id, v + 5)
            .await
            .unwrap()
            .expect("only the committed snapshot exists");
        assert_eq!(
            resolved.status_list.lst, "flip-1",
            "conflict path must not record a snapshot"
        );
    }

    /// The publish counterpart of the atomicity proof: the row INSERT and the
    /// snapshot covering its initial state succeed or fail as a unit. A hole
    /// here is worse than on the update path — no later write repairs a missing
    /// opening snapshot, so §8.4 lookups over that window would 404 forever.
    /// Also pins that a duplicate `list_id` still classifies as `DuplicateEntry`
    /// (409), not a generic insert failure (500).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_insert_with_snapshot_is_atomic() {
        let db = sqlite_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
        let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

        let key: Jwk = serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        let issuer = "issuer-insert-atomic";
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let new_record = |list_id: &str| StatusListRecord {
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: format!("sub-{list_id}"),
            updated_at: 1000,
        };
        let new_snapshot = |snapshot_id: &str, list_id: &str| StatusListHistoryRecord {
            snapshot_id: snapshot_id.to_string(),
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: format!("sub-{list_id}"),
            iat: 1000,
            exp: 1900,
        };

        // --- Happy path: row and opening snapshot both commit. ---
        store
            .insert_one_with_snapshot(new_record("list-ok"), new_snapshot("snap-ok", "list-ok"))
            .await
            .unwrap();
        assert!(store.find_one_by("list-ok").await.unwrap().is_some());
        assert!(
            history
                .find_valid_at("list-ok", 1000)
                .await
                .unwrap()
                .is_some(),
            "the opening snapshot must be resolvable at the publish instant"
        );

        // --- Rollback path: the snapshot INSERT collides on its primary key,
        // so the paired row INSERT must not survive. ---
        let result = store
            .insert_one_with_snapshot(
                new_record("list-rolled-back"),
                // Collides with the snapshot committed above.
                new_snapshot("snap-ok", "list-rolled-back"),
            )
            .await;
        // Specifically an `InsertError`, not a `DuplicateEntry`: only the *row*
        // insert classifies duplicates (`map_insert_err`), because only a
        // duplicate `list_id` is a client-visible conflict. `snapshot_id` is a
        // fresh v4 UUID per publish, so a collision here is a server fault and
        // must stay a 500. `assert_duplicate_list_id_is_conflict`
        // reasons from this asymmetry, so it is pinned rather than assumed.
        assert!(
            matches!(result, Err(RepositoryError::InsertError(_))),
            "a failed snapshot insert must fail the whole unit as a plain \
             insert error, got {result:?}"
        );
        assert!(
            store
                .find_one_by("list-rolled-back")
                .await
                .unwrap()
                .is_none(),
            "the status list row must roll back when its snapshot insert fails"
        );

        // --- Conflict path: a duplicate list_id must stay a DuplicateEntry so
        // a racing publish keeps mapping to 409 rather than 500. ---
        let dup = store
            .insert_one_with_snapshot(new_record("list-ok"), new_snapshot("snap-dup", "list-ok"))
            .await;
        assert!(
            matches!(dup, Err(RepositoryError::DuplicateEntry)),
            "duplicate list_id must map to DuplicateEntry, got {dup:?}"
        );
        // The rolled-back publish recorded no snapshot either. This must name
        // `list-rolled-back` — the list that actually failed. Asserting against
        // a list_id that was never inserted proves nothing about rollback.
        assert!(
            history
                .find_valid_at("list-rolled-back", 1000)
                .await
                .unwrap()
                .is_none(),
            "the rolled-back publish must not leave a snapshot behind"
        );
        // ...and the duplicate attempt left the committed snapshot alone.
        let surviving = history
            .find_valid_at("list-ok", 1000)
            .await
            .unwrap()
            .expect("the first publish's snapshot must survive");
        assert_eq!(surviving.snapshot_id, "snap-ok");
    }

    /// Cross-backend proof: a duplicate `list_id` raised *inside* the open
    /// transaction must still classify as `DuplicateEntry` on MySQL. The
    /// non-transactional `insert_one` is already covered by
    /// `test_mysql_duplicate_insert_maps_to_duplicate_entry`; what is untested
    /// there is that `insert_one_with_snapshot` — which rolls back first and
    /// classifies afterwards (`map_insert_err` on the error captured *before*
    /// the rollback) — does not lose the classification along the way. Losing it
    /// turns every racing publish into a 500 instead of a 409.
    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_insert_with_snapshot_duplicate_maps_to_duplicate_entry() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        assert_duplicate_list_id_is_conflict(
            test_db.connection().await,
            "issuer-dup-txn-mysql",
            "list-dup-txn-mysql",
            "MySQL",
        )
        .await;
    }

    /// The same proof on Postgres, the production backend. Postgres is the
    /// backend where this could plausibly diverge: a failed statement poisons
    /// the transaction (`25P02`), so if the classification were ever read from
    /// the rollback rather than from the original `23505`, it would degrade to a
    /// generic insert error here and nowhere else.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn test_postgres_insert_with_snapshot_duplicate_maps_to_duplicate_entry() {
        let test_db = postgres_helpers::postgres_connection().await;
        assert_duplicate_list_id_is_conflict(
            test_db.db.clone(),
            "issuer-dup-txn-postgres",
            "list-dup-txn-postgres",
            "Postgres",
        )
        .await;
    }

    /// The same proof on SQLite. Redundant with the two container tests above on
    /// the classification question itself — but it is the only one of the three
    /// that runs under a plain `cargo test`, with no Docker and no
    /// `--all-features`. A regression in `insert_one_with_snapshot`'s error
    /// mapping therefore fails in milliseconds locally instead of waiting for
    /// the container job.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_insert_with_snapshot_duplicate_maps_to_duplicate_entry() {
        let db = sqlite_connection().await;
        assert_duplicate_list_id_is_conflict(
            db,
            "issuer-dup-txn-sqlite",
            "list-dup-txn-sqlite",
            "SQLite",
        )
        .await;
    }

    /// Publishes `list_id` once, then republishes it with a *different*
    /// `snapshot_id`, and asserts the failure is the duplicate `list_id`
    /// classified as `DuplicateEntry` — on both publish paths, transactional
    /// (`insert_one_with_snapshot`) and not (`insert_one`).
    ///
    /// The distinct `snapshot_id` keeps the assertion aimed at one constraint.
    /// A duplicate `snapshot_id` deliberately stays a plain `InsertError` rather
    /// than a `DuplicateEntry` (pinned by
    /// `test_sqlite_insert_with_snapshot_is_atomic`), so reusing the committed
    /// one would couple this test to statement *ordering*: today the row INSERT
    /// fails first and short-circuits, but if that order ever flipped, the
    /// snapshot would collide first and this test would fail for a reason that
    /// has nothing to do with the property under test. A fresh `snapshot_id`
    /// leaves the duplicate `list_id` as the only thing that can fail.
    ///
    /// Seeds its own issuer because `status_lists.issuer` is a foreign key onto
    /// `credentials.issuer`; callers pass a per-backend `issuer`/`list_id` pair
    /// so a shared database would still keep them apart.
    #[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
    async fn assert_duplicate_list_id_is_conflict(
        db: Arc<DatabaseConnection>,
        issuer: &str,
        list_id: &str,
        backend: &str,
    ) {
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
        let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

        let key: Jwk = serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let record = |updated_at: i64| StatusListRecord {
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: format!("sub-{list_id}"),
            updated_at,
        };
        let snapshot = |snapshot_id: &str, iat: i64| StatusListHistoryRecord {
            snapshot_id: snapshot_id.to_string(),
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: format!("sub-{list_id}"),
            iat,
            exp: iat + 900,
        };

        store
            .insert_one_with_snapshot(record(1000), snapshot("snap-first", 1000))
            .await
            .unwrap();

        // Racing publish: same list_id, freshly minted snapshot_id.
        let dup = store
            .insert_one_with_snapshot(record(2000), snapshot("snap-second", 2000))
            .await;
        assert!(
            matches!(dup, Err(RepositoryError::DuplicateEntry)),
            "duplicate list_id inside a transaction must map to DuplicateEntry \
             on {backend}, got {dup:?}"
        );

        // The rejected publish rolled back cleanly. Its snapshot would have
        // covered `[2000, 2900)`, and the first publish's covers `[1000, 1900)`,
        // so *anything* resolvable at 2000 could only be the leak this asserts
        // against — the windows do not overlap.
        assert!(
            history
                .find_valid_at(list_id, 2000)
                .await
                .unwrap()
                .is_none(),
            "the rejected publish must not leave a snapshot behind on {backend}"
        );

        // ...and the failed attempt did not disturb the committed one.
        let first = history
            .find_valid_at(list_id, 1000)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("the first publish's snapshot must survive on {backend}"));
        assert_eq!(first.snapshot_id, "snap-first");

        // The row itself is untouched. The two records differ only in
        // `updated_at`, so this is what catches a silent upsert: an
        // `ON CONFLICT DO UPDATE` "optimization" would leave 2000 here while
        // every assertion above still passed.
        let row = store
            .find_one_by(list_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("the committed row must survive on {backend}"));
        assert_eq!(
            row.updated_at, 1000,
            "the rejected publish must not overwrite the committed row on {backend}"
        );

        // The same conflict on the *non-transactional* path. Operators can set
        // `snapshot_retention_secs = 0`, which builds a `Service` with no
        // snapshot repo, and `publish_status_list` then calls plain `insert_one`
        // — a different `map_insert_err` call site with no transaction or
        // rollback around it. Reuses this test's backend rather than paying for
        // another container, since the row it collides with is already
        // committed.
        let plain = store.insert_one(record(3000)).await;
        assert!(
            matches!(plain, Err(RepositoryError::DuplicateEntry)),
            "duplicate list_id on the snapshot-disabled publish path must also \
             map to DuplicateEntry on {backend}, got {plain:?}"
        );
    }

    /// Cross-backend proof (#143): on MySQL a failed snapshot INSERT must roll
    /// the paired row UPDATE back. Requires InnoDB (pinned by the migration) —
    /// a non-transactional engine would silently keep the row change.
    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_update_with_snapshot_rolls_back_on_history_failure() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        let db = test_db.connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
        let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

        let key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();
        let issuer = "issuer-atomic-mysql";
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let v = 1000;
        let base = StatusListRecord {
            list_id: "list-atomic-mysql".to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-atomic-mysql".to_string(),
            updated_at: v,
        };
        store.insert_one(base.clone()).await.unwrap();

        // Commit one snapshot so its primary key exists to collide against.
        store
            .update_one_with_snapshot(
                &base.list_id,
                StatusListRecord {
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-1".to_string(),
                    },
                    updated_at: v + 1,
                    ..base.clone()
                },
                v,
                StatusListHistoryRecord {
                    snapshot_id: "snap-mysql".to_string(),
                    list_id: base.list_id.clone(),
                    issuer: issuer.to_string(),
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-1".to_string(),
                    },
                    sub: base.sub.clone(),
                    iat: v + 1,
                    exp: v + 1 + 900,
                },
            )
            .await
            .unwrap();
        let snapshot = history
            .find_valid_at(&base.list_id, v + 1)
            .await
            .unwrap()
            .expect("the committed MySQL snapshot must be resolvable");
        assert_eq!(
            snapshot.status_list.lst, "flip-1",
            "MySQL must round-trip the snapshot JSON"
        );

        // Second update whose snapshot collides on the primary key: the INSERT
        // fails, so the whole transaction must roll back.
        let result = store
            .update_one_with_snapshot(
                &base.list_id,
                StatusListRecord {
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-2".to_string(),
                    },
                    updated_at: v + 2,
                    ..base.clone()
                },
                v + 1,
                StatusListHistoryRecord {
                    snapshot_id: "snap-mysql".to_string(), // duplicate PK
                    list_id: base.list_id.clone(),
                    issuer: issuer.to_string(),
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-2".to_string(),
                    },
                    sub: base.sub.clone(),
                    iat: v + 2,
                    exp: v + 2 + 900,
                },
            )
            .await;
        assert!(result.is_err(), "duplicate snapshot PK must fail the unit");

        let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
        assert_eq!(
            row.updated_at,
            v + 1,
            "InnoDB must roll the row update back when the snapshot insert fails"
        );
        assert_eq!(
            row.status_list.lst, "flip-1",
            "the rolled-back row must retain its previously committed content"
        );
    }

    /// Postgres is the production backend, so the transactional rollback is
    /// proven directly on it, not just inferred from the SQLite and MySQL
    /// proofs: a colliding snapshot INSERT must roll the paired row UPDATE back.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn test_postgres_update_with_snapshot_rolls_back_on_history_failure() {
        let test_db = postgres_helpers::postgres_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(test_db.db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(test_db.db.clone());
        let history = SeaOrmStore::<StatusListHistoryRecord>::new(test_db.db.clone());

        let key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();
        let issuer = "issuer-atomic-postgres";
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let v = 1000;
        let base = StatusListRecord {
            list_id: "list-atomic-postgres".to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-atomic-postgres".to_string(),
            updated_at: v,
        };
        store.insert_one(base.clone()).await.unwrap();

        // Commit one snapshot so its primary key exists to collide against.
        store
            .update_one_with_snapshot(
                &base.list_id,
                StatusListRecord {
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-1".to_string(),
                    },
                    updated_at: v + 1,
                    ..base.clone()
                },
                v,
                StatusListHistoryRecord {
                    snapshot_id: "snap-postgres".to_string(),
                    list_id: base.list_id.clone(),
                    issuer: issuer.to_string(),
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-1".to_string(),
                    },
                    sub: base.sub.clone(),
                    iat: v + 1,
                    exp: v + 1 + 900,
                },
            )
            .await
            .unwrap();
        let snapshot = history
            .find_valid_at(&base.list_id, v + 1)
            .await
            .unwrap()
            .expect("the committed Postgres snapshot must be resolvable");
        assert_eq!(
            snapshot.status_list.lst, "flip-1",
            "Postgres must round-trip the snapshot JSON"
        );

        // Second update whose snapshot collides on the primary key: the INSERT
        // fails, so the whole transaction must roll back.
        let result = store
            .update_one_with_snapshot(
                &base.list_id,
                StatusListRecord {
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-2".to_string(),
                    },
                    updated_at: v + 2,
                    ..base.clone()
                },
                v + 1,
                StatusListHistoryRecord {
                    snapshot_id: "snap-postgres".to_string(), // duplicate PK
                    list_id: base.list_id.clone(),
                    issuer: issuer.to_string(),
                    status_list: StatusList {
                        bits: 1,
                        lst: "flip-2".to_string(),
                    },
                    sub: base.sub.clone(),
                    iat: v + 2,
                    exp: v + 2 + 900,
                },
            )
            .await;
        assert!(result.is_err(), "duplicate snapshot PK must fail the unit");

        let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
        assert_eq!(
            row.updated_at,
            v + 1,
            "Postgres must roll the row update back when the snapshot insert fails"
        );
        assert_eq!(
            row.status_list.lst, "flip-1",
            "the rolled-back row must retain its previously committed content"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_delete_older_than_deletes_expired_snapshots() {
        let db = sqlite_connection().await;
        let store = SeaOrmStore::<StatusListHistoryRecord>::new(db);

        let list_id = "test-list-delete-old";
        let issuer = "test-issuer";

        // Insert snapshots with different expiration times
        let old_snapshot = StatusListHistoryRecord {
            snapshot_id: "old-snapshot-001".to_string(),
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "compressed_old".to_string(),
            },
            sub: format!("https://example.com/statuslists/{}", list_id),
            iat: 1000,
            exp: 2000, // Expires at 2000
        };

        let recent_snapshot = StatusListHistoryRecord {
            snapshot_id: "recent-snapshot-002".to_string(),
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "compressed_recent".to_string(),
            },
            sub: format!("https://example.com/statuslists/{}", list_id),
            iat: 3000,
            exp: 5000, // Expires at 5000
        };

        let future_snapshot = StatusListHistoryRecord {
            snapshot_id: "future-snapshot-003".to_string(),
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "compressed_future".to_string(),
            },
            sub: format!("https://example.com/statuslists/{}", list_id),
            iat: 6000,
            exp: 8000, // Expires at 8000
        };

        // Insert all snapshots
        store.insert_one(old_snapshot).await.unwrap();
        store.insert_one(recent_snapshot).await.unwrap();
        store.insert_one(future_snapshot).await.unwrap();

        // Delete snapshots with exp < 5500 (should delete old_snapshot and recent_snapshot)
        let cutoff = 5500;
        let deleted = store.delete_older_than(cutoff).await.unwrap();
        assert_eq!(deleted, 2, "Should delete 2 snapshots with exp < 5500");

        // Verify old snapshots are gone
        let old_result = store.find_valid_at(list_id, 1500).await.unwrap();
        assert!(old_result.is_none(), "Old snapshot should be deleted");

        let recent_result = store.find_valid_at(list_id, 3500).await.unwrap();
        assert!(recent_result.is_none(), "Recent snapshot should be deleted");

        // Verify future snapshot still exists
        let future_result = store.find_valid_at(list_id, 6500).await.unwrap();
        assert!(
            future_result.is_some(),
            "Future snapshot should still exist"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_delete_older_than_with_no_matching_snapshots() {
        let db = sqlite_connection().await;
        let store = SeaOrmStore::<StatusListHistoryRecord>::new(db);

        let list_id = "test-list-no-delete";
        let issuer = "test-issuer";

        // Insert a single future snapshot
        let snapshot = StatusListHistoryRecord {
            snapshot_id: "future-snapshot-001".to_string(),
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "compressed".to_string(),
            },
            sub: format!("https://example.com/statuslists/{}", list_id),
            iat: 5000,
            exp: 8000,
        };

        store.insert_one(snapshot).await.unwrap();

        // Delete with cutoff before the snapshot's exp
        let deleted = store.delete_older_than(3000).await.unwrap();
        assert_eq!(
            deleted, 0,
            "Should delete 0 snapshots when cutoff is before any exp"
        );

        // Verify snapshot still exists
        let result = store.find_valid_at(list_id, 6500).await.unwrap();
        assert!(result.is_some(), "Future snapshot should still exist");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_delete_older_than_deletes_all_snapshots() {
        let db = sqlite_connection().await;
        let store = SeaOrmStore::<StatusListHistoryRecord>::new(db);

        let list_id = "test-list-delete-all";
        let issuer = "test-issuer";

        // Insert multiple old snapshots
        for i in 0..3 {
            let snapshot = StatusListHistoryRecord {
                snapshot_id: format!("old-snapshot-{}", i),
                list_id: list_id.to_string(),
                issuer: issuer.to_string(),
                status_list: StatusList {
                    bits: 1,
                    lst: format!("compressed_{}", i),
                },
                sub: format!("https://example.com/statuslists/{}", list_id),
                iat: 1000 + i * 100,
                exp: 2000 + i * 100,
            };
            store.insert_one(snapshot).await.unwrap();
        }

        // Delete with cutoff far in the future
        let deleted = store.delete_older_than(10000).await.unwrap();
        assert_eq!(deleted, 3, "Should delete all 3 snapshots");

        // Verify all snapshots are gone
        let result = store.find_valid_at(list_id, 1500).await.unwrap();
        assert!(result.is_none(), "All snapshots should be deleted");
    }

    /// Multi-connection contention test: proves the block-then-lose behavior
    /// for the transactional guarded update + snapshot path.
    ///
    /// This test opens two real connections to the same MySQL database and
    /// verifies that:
    /// 1. Connection A calls the production `update_one_with_snapshot` path,
    ///    which performs a guarded UPDATE plus history INSERT in one
    ///    transaction.
    /// 2. Connection B calls `update_one_with_snapshot` on the same row and
    ///    blocks behind A's row lock.
    /// 3. Once A releases the lock, B returns false (lost the guard) and records
    ///    no loser snapshot.
    ///
    /// This verifies the lock-hold behavior described in the optimistic
    /// concurrency guard documentation.
    #[cfg(feature = "mysql")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mysql_concurrent_update_loses_guarded_update() {
        use std::time::{Duration, Instant};
        use tokio::sync::oneshot;

        let test_db = mysql_helpers::mysql_connection().await;

        let pool_a = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;
        let pool_b = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;
        let pool_verify = mysql_helpers::connect_to_test_db(&test_db.url, 2).await;
        let store_a = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_a));
        let store_b = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_b));
        let store_verify = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_verify));

        // Seed a credential first (required for FK)
        let cred_key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();
        let issuer = "issuer-contention-mysql";
        let cred_store = SeaOrmStore::<Credentials>::new(store_a.db.clone());
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), cred_key))
            .await
            .unwrap();

        // Seed a status list at a known timestamp
        let base_timestamp = 1000i64;
        let list_id = "list-contention-mysql";
        let base_record = StatusListRecord {
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-contention".to_string(),
            updated_at: base_timestamp,
        };
        store_a.insert_one(base_record.clone()).await.unwrap();

        // Channels for coordination (using Instants for happens-before assertions)
        let (tx_a_ready, rx_a_ready) = oneshot::channel();
        let (tx_b_started, rx_b_started) = oneshot::channel();
        let (tx_a_release, rx_a_release) = oneshot::channel();
        let (tx_b_complete, rx_b_complete) = oneshot::channel::<(bool, Instant)>();

        snapshot_txn_test_hook::UPDATE_BEFORE_COMMIT
            .install(snapshot_txn_test_hook::Probe {
                list_id: list_id.to_string(),
                ready: tx_a_ready,
                release: rx_a_release,
            })
            .await;

        // Connection A: run the real update + snapshot method, pausing after
        // the snapshot insert and before commit while the row lock is held.
        let store_a_clone = store_a.clone();
        let base_record_a = base_record.clone();
        let handle_a = tokio::spawn(async move {
            let updated_at_a = base_timestamp + 1;
            let record_a = StatusListRecord {
                status_list: StatusList {
                    bits: 1,
                    lst: "writer-a".to_string(),
                },
                updated_at: updated_at_a,
                ..base_record_a.clone()
            };
            let snapshot_a = StatusListHistoryRecord {
                snapshot_id: "snap-contention-a".to_string(),
                list_id: list_id.to_string(),
                issuer: issuer.to_string(),
                status_list: record_a.status_list.clone(),
                sub: record_a.sub.clone(),
                iat: updated_at_a,
                exp: updated_at_a + 900,
            };

            store_a_clone
                .update_one_with_snapshot(list_id, record_a, base_timestamp, snapshot_a)
                .await
                .expect("Update A should complete")
        });

        // Connection B: Try to update concurrently
        let store_b_clone = store_b.clone();
        let base_record_b = base_record.clone();
        let b_snapshot_id = "snap-contention-b".to_string();
        let b_snapshot_id_for_task = b_snapshot_id.clone();
        let handle_b = tokio::spawn(async move {
            // Wait for A to be ready (ensuring A holds the lock)
            rx_a_ready.await.expect("Failed to receive A ready");

            // Signal that B is starting
            tx_b_started.send(()).expect("Failed to signal B started");

            // Try to update - this should BLOCK until A commits
            // because InnoDB row locks are exclusive for writes
            let updated_at_b = base_timestamp + 2;
            let record_b = StatusListRecord {
                status_list: StatusList {
                    bits: 1,
                    lst: "writer-b".to_string(),
                },
                updated_at: updated_at_b,
                ..base_record_b.clone()
            };
            let snapshot_b = StatusListHistoryRecord {
                snapshot_id: b_snapshot_id_for_task,
                list_id: list_id.to_string(),
                issuer: issuer.to_string(),
                status_list: record_b.status_list.clone(),
                sub: record_b.sub.clone(),
                iat: updated_at_b,
                exp: updated_at_b + 900,
            };

            // This update uses the ORIGINAL base_timestamp as guard
            // After A commits, the row has updated_at = base_timestamp + 1
            // So this guard (base_timestamp) should miss → returns false
            let result = store_b_clone
                .update_one_with_snapshot(list_id, record_b, base_timestamp, snapshot_b)
                .await
                .expect("Update B should complete");

            // Capture completion immediately after the repository method returns.
            // No channel ordering is allowed to manufacture this timestamp.
            let b_done = Instant::now();

            tx_b_complete
                .send((result, b_done))
                .expect("Failed to send B result");
        });

        rx_b_started.await.expect("Failed to receive B started");

        // Give B a moment to reach MySQL and block on A's row lock.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // B cannot complete before this instant if it is blocked on A's row
        // lock. Capturing before releasing A avoids a scheduler race after MySQL
        // has already released the lock but before this task resumes.
        let a_releasing_lock = Instant::now();
        tx_a_release.send(()).expect("Failed to release A");

        // Wait for both tasks with timeout, joining both handles for proper error reporting
        let timeout = Duration::from_secs(10);
        let (a_result, b_result) = tokio::join!(
            tokio::time::timeout(timeout, handle_a),
            tokio::time::timeout(timeout, handle_b)
        );

        // Unwrap results to get proper panic messages from either task
        let a_won = a_result
            .expect("Test timed out waiting for task A")
            .expect("Task A panicked");
        assert!(a_won, "Writer A should win the guarded update");
        b_result
            .expect("Test timed out waiting for task B")
            .expect("Task B panicked");

        // Receive the results from the oneshot channels
        let (b_won, b_done) = rx_b_complete.await.expect("Failed to receive B result");

        // Falsifiable ordering assertion: if B were not blocked on A's row lock,
        // it would complete during A's hold sleep, before A starts committing.
        assert!(
            b_done > a_releasing_lock,
            "B should complete only after A starts releasing the row lock (B: {:?}, A: {:?})",
            b_done,
            a_releasing_lock
        );

        // The CRITICAL assertion: B should NOT have won
        // B's guard was base_timestamp, but A changed updated_at to base_timestamp + 1
        // So B's WHERE updated_at = base_timestamp should affect 0 rows
        assert!(
            !b_won,
            "B should lose (0 rows affected) because A already advanced updated_at. \
             B blocked, then got a stale guard"
        );

        // Verify the final state has A's changes (use verify pool to avoid deadlock)
        let final_record = store_verify
            .find_one_by(list_id)
            .await
            .unwrap()
            .expect("Record should exist");
        assert_eq!(
            final_record.status_list.lst, "writer-a",
            "A's write should be persisted"
        );
        assert_eq!(
            final_record.updated_at,
            base_timestamp + 1,
            "updated_at should be A's timestamp"
        );

        // Verify A's winning snapshot was created.
        let history_store = SeaOrmStore::<StatusListHistoryRecord>::new(store_verify.db.clone());
        let winning_snapshot = history_store
            .find_valid_at(list_id, base_timestamp + 1)
            .await
            .unwrap();
        assert_eq!(
            winning_snapshot
                .expect("A's winning snapshot should have been created")
                .snapshot_id,
            "snap-contention-a"
        );

        let loser_snapshot = status_list_history::Entity::find_by_id(b_snapshot_id)
            .one(&*store_verify.db)
            .await
            .expect("Loser snapshot lookup should succeed");
        assert!(
            loser_snapshot.is_none(),
            "B's guard-miss path must not record a snapshot"
        );
    }

    /// The publish race itself, on two real connections.
    ///
    /// `assert_duplicate_list_id_is_conflict` collides with a row that is
    /// already **committed**, which is the common case but not the one the
    /// issue describes. This collides with a row that is still **uncommitted**:
    /// writer A holds the primary-key entry inside an open transaction while
    /// writer B arrives, so B blocks in the engine and only learns the outcome
    /// when A commits. That is a different code path — the driver surfaces the
    /// violation at a different point — and it is the one a real racing publish
    /// takes.
    ///
    /// Asserts three things:
    ///
    /// 1. B genuinely blocked (it cannot finish before A starts committing),
    ///    which is what makes this a race test rather than a sequential one.
    /// 2. B's failure still classifies as `DuplicateEntry` → 409, not a generic
    ///    backend error → 500. This is the property the issue is about.
    /// 3. The loser left nothing behind: no snapshot, and A's row intact.
    #[cfg(any(feature = "mysql", feature = "postgres-tests"))]
    async fn assert_concurrent_publish_loser_gets_conflict(
        pool_a: DatabaseConnection,
        pool_b: DatabaseConnection,
        pool_verify: DatabaseConnection,
        issuer: &'static str,
        list_id: &'static str,
        backend: &'static str,
    ) {
        use std::time::{Duration, Instant};
        use tokio::sync::oneshot;

        let store_a = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_a));
        let store_b = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_b));
        let store_verify = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_verify));

        // status_lists.issuer is a foreign key onto credentials.issuer, so the
        // credential has to be committed before either writer starts.
        let key: Jwk = serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        SeaOrmStore::<Credentials>::new(store_verify.db.clone())
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        // `move` so both closures capture the `&'static str`s by copy and stay
        // `Copy` themselves — each spawned writer below needs its own.
        let record = move |lst: &str, updated_at: i64| StatusListRecord {
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: lst.to_string(),
            },
            sub: format!("sub-{list_id}"),
            updated_at,
        };
        let snapshot = move |snapshot_id: &str, iat: i64| StatusListHistoryRecord {
            snapshot_id: snapshot_id.to_string(),
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: format!("sub-{list_id}"),
            iat,
            exp: iat + 900,
        };

        let (tx_a_ready, rx_a_ready) = oneshot::channel();
        let (tx_b_started, rx_b_started) = oneshot::channel();
        let (tx_a_release, rx_a_release) = oneshot::channel();
        let (tx_b_done, rx_b_done) = oneshot::channel::<(Result<(), RepositoryError>, Instant)>();

        snapshot_txn_test_hook::INSERT_BEFORE_COMMIT
            .install(snapshot_txn_test_hook::Probe {
                list_id: list_id.to_string(),
                ready: tx_a_ready,
                release: rx_a_release,
            })
            .await;

        // Writer A: the winning publish, paused just before COMMIT while its
        // primary-key entry is still uncommitted.
        let handle_a = tokio::spawn(async move {
            store_a
                .insert_one_with_snapshot(record("writer-a", 1000), snapshot("snap-race-a", 1000))
                .await
        });

        // Writer B: the losing publish. Starts only once A is known to be
        // holding the uncommitted key.
        let handle_b = tokio::spawn(async move {
            rx_a_ready.await.expect("A never reached its pause point");
            tx_b_started.send(()).expect("failed to signal B started");

            let result = store_b
                .insert_one_with_snapshot(record("writer-b", 2000), snapshot("snap-race-b", 2000))
                .await;
            // Timestamped the instant the call returns, before any channel work,
            // so nothing downstream can manufacture the ordering.
            let b_done = Instant::now();
            tx_b_done
                .send((result, b_done))
                .expect("failed to send B result");
        });

        rx_b_started.await.expect("B never started");
        // Give B time to reach the database and block on A's key.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let a_releasing = Instant::now();
        tx_a_release.send(()).expect("failed to release A");

        let timeout = Duration::from_secs(30);
        let (a_join, b_join) = tokio::join!(
            tokio::time::timeout(timeout, handle_a),
            tokio::time::timeout(timeout, handle_b)
        );
        a_join
            .unwrap_or_else(|_| panic!("timed out waiting for writer A on {backend}"))
            .expect("writer A panicked")
            .unwrap_or_else(|e| panic!("writer A should win the publish on {backend}: {e:?}"));
        b_join
            .unwrap_or_else(|_| panic!("timed out waiting for writer B on {backend}"))
            .expect("writer B panicked");

        let (b_result, b_done) = rx_b_done.await.expect("failed to receive B result");

        // Falsifiable: if B had not blocked on A's uncommitted key it would have
        // finished during the sleep above, before A began committing.
        assert!(
            b_done > a_releasing,
            "B must block until A commits on {backend} — otherwise this is not a \
             race (B: {b_done:?}, A releasing: {a_releasing:?})"
        );

        // The property under test: a genuinely concurrent duplicate is still a
        // client conflict, not a server error.
        assert!(
            matches!(b_result, Err(RepositoryError::DuplicateEntry)),
            "the losing publisher of a real race must get DuplicateEntry (409) \
             on {backend}, not a generic error (500), got {b_result:?}"
        );

        // A's row won and B disturbed nothing.
        let row = store_verify
            .find_one_by(list_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("A's row must be committed on {backend}"));
        assert_eq!(
            row.status_list.lst, "writer-a",
            "A's publish must be the one that persisted on {backend}"
        );
        assert_eq!(
            row.updated_at, 1000,
            "B must not have overwritten A's row on {backend}"
        );

        let loser_snapshot = status_list_history::Entity::find_by_id("snap-race-b")
            .one(&*store_verify.db)
            .await
            .expect("loser snapshot lookup should succeed");
        assert!(
            loser_snapshot.is_none(),
            "the losing publisher must not leave a snapshot behind on {backend}"
        );
    }

    /// The publish race on MySQL, whose driver reports duplicate keys as `1062`.
    #[cfg(feature = "mysql")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_mysql_concurrent_publish_loser_gets_conflict() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        assert_concurrent_publish_loser_gets_conflict(
            mysql_helpers::connect_to_test_db(&test_db.url, 1).await,
            mysql_helpers::connect_to_test_db(&test_db.url, 1).await,
            mysql_helpers::connect_to_test_db(&test_db.url, 2).await,
            "issuer-race-txn-mysql",
            "list-race-txn-mysql",
            "MySQL",
        )
        .await;
    }

    /// The same race on Postgres, the production backend and the one the issue
    /// singles out: a failed statement poisons the transaction (`25P02`), so a
    /// classification taken from anywhere but the original `23505` degrades to a
    /// 500 here and nowhere else.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_postgres_concurrent_publish_loser_gets_conflict() {
        let test_db = postgres_helpers::postgres_connection().await;
        assert_concurrent_publish_loser_gets_conflict(
            postgres_helpers::connect_to_test_db(&test_db.url, 1).await,
            postgres_helpers::connect_to_test_db(&test_db.url, 1).await,
            postgres_helpers::connect_to_test_db(&test_db.url, 2).await,
            "issuer-race-txn-postgres",
            "list-race-txn-postgres",
            "Postgres",
        )
        .await;
    }

    /// Blocks until at least `expected` sessions are waiting on a lock.
    ///
    /// Used instead of a fixed sleep: contention tests must interleave two
    /// sessions, and a sleep that expires early silently asserts something
    /// other than what the test claims.
    #[cfg(feature = "postgres-tests")]
    async fn await_blocked_sessions(db: &DatabaseConnection, expected: i64) {
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let blocked = db
                .query_one(Statement::from_string(
                    DatabaseBackend::Postgres,
                    "SELECT count(*) AS blocked FROM pg_stat_activity \
                     WHERE datname = current_database() \
                       AND wait_event_type = 'Lock'",
                ))
                .await
                .expect("failed to inspect pg_stat_activity")
                .expect("count(*) always returns a row")
                .try_get::<i64>("", "blocked")
                .expect("failed to read blocked-session count");

            if blocked >= expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {expected} blocked session(s); saw {blocked}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Forces a real MySQL `1205` (`ER_LOCK_WAIT_TIMEOUT`). The only way to
    /// exercise the `SqlxMySqlError` downcast, since the driver error type
    /// cannot be constructed outside its own crate.
    ///
    /// Distinct from `test_mysql_concurrent_update_loses_guarded_update`: there
    /// the blocked writer acquires the lock and reports `Ok(false)`; here it
    /// never acquires it at all.
    ///
    /// Holds the lock with raw SQL rather than the `update_snapshot_test_hook`
    /// probe, which is a process-global singleton that asserts single
    /// installation and would race the other test.
    #[cfg(feature = "mysql")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mysql_lock_wait_timeout_maps_to_contention() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;

        let conn_a = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;
        let conn_b = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;

        // Both pools are pinned to a single connection, so this session setting
        // sticks to the connection B actually uses. Without it B would wait out
        // InnoDB's 50s default and the test would hang rather than fail.
        conn_b
            .execute_unprepared("SET SESSION innodb_lock_wait_timeout = 1")
            .await
            .expect("failed to shorten B's lock wait");

        let store_b = SeaOrmStore::<StatusListRecord>::new(Arc::new(conn_b));

        let key: Jwk = serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        let issuer = "issuer-lockwait-mysql";
        let cred_store = SeaOrmStore::<Credentials>::new(Arc::new(
            mysql_helpers::connect_to_test_db(&test_db.url, 1).await,
        ));
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let v = 1000;
        let list_id = "list-lockwait-mysql";
        let base = StatusListRecord {
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-lockwait-mysql".to_string(),
            updated_at: v,
        };
        SeaOrmStore::<StatusListRecord>::new(cred_store.db.clone())
            .insert_one(base.clone())
            .await
            .unwrap();

        // A takes an exclusive row lock and holds it, uncommitted.
        let txn_a = conn_a.begin().await.expect("failed to begin A");
        txn_a
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::MySql,
                "UPDATE status_lists SET sub = 'locked-by-a' WHERE list_id = ?",
                vec![Value::from(list_id)],
            ))
            .await
            .expect("A failed to take the row lock");

        // B's guard is valid — the row really is still at `v`. B fails purely
        // because it cannot acquire the lock within its 1s budget, which is what
        // makes this contention rather than a lost race.
        let result = store_b
            .update_one(
                list_id,
                StatusListRecord {
                    status_list: StatusList {
                        bits: 1,
                        lst: "writer-b".to_string(),
                    },
                    updated_at: v + 1,
                    ..base.clone()
                },
                v,
            )
            .await;

        assert!(
            matches!(result, Err(RepositoryError::Contention { code: "1205" })),
            "MySQL 1205 must classify as Contention (409) reporting its own \
             error number, not an opaque UpdateError (500); got {result:?}"
        );

        txn_a.rollback().await.expect("failed to release A's lock");
    }

    /// Credential registration is a pinned write too, and reaches the client as
    /// `409 write_contention` via `CredentialError`, not `StatusListError`.
    #[cfg(feature = "mysql")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mysql_credential_insert_contention_is_classified() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;

        let conn_a = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;
        let conn_b = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;
        conn_b
            .execute_unprepared("SET SESSION innodb_lock_wait_timeout = 1")
            .await
            .expect("failed to shorten B's lock wait");

        let issuer = "issuer-contention-credential";
        let key: Jwk = serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();

        // A holds the primary-key entry uncommitted, so B's insert of the same
        // issuer blocks on it rather than failing fast as a duplicate.
        let txn_a = conn_a.begin().await.expect("failed to begin A");
        txn_a
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::MySql,
                "INSERT INTO credentials (issuer, public_key) VALUES (?, ?)",
                vec![
                    Value::from(issuer),
                    Value::from(serde_json::to_value(&key).unwrap()),
                ],
            ))
            .await
            .expect("A failed to claim the issuer key");

        let store_b = SeaOrmStore::<Credentials>::new(Arc::new(conn_b));
        let result = store_b
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await;

        assert!(
            matches!(result, Err(RepositoryError::Contention { code: "1205" })),
            "a blocked credential insert must classify as Contention, not \
             DuplicateEntry or an opaque InsertError; got {result:?}"
        );

        txn_a.rollback().await.expect("failed to release A's lock");
    }

    /// Forces a real Postgres `40P01` (`deadlock_detected`). The only way to
    /// exercise the `SqlxPostgresError` downcast, since the driver error type
    /// cannot be constructed outside its own crate.
    ///
    /// `40P01` rather than `40001` because a serialization failure needs a
    /// transaction above READ COMMITTED, which no pinned write can be.
    ///
    /// The cycle:
    ///
    /// ```text
    /// A: INSERT history 'snap-deadlock'          -- holds the unique key
    /// B: UPDATE status_lists (repo)              -- holds the row lock
    /// B: INSERT history 'snap-deadlock'          -- waits on A's key
    /// A: UPDATE status_lists (same row)          -- waits on B's row lock
    /// ```
    ///
    /// Postgres runs `CheckDeadLock` in a waiter when that waiter's
    /// `deadlock_timeout` fires, and a waiter finding no cycle does not
    /// re-check. B necessarily waits first, so without intervention A would be
    /// the victim and the repository call would pass straight through. Setting
    /// B's timeout to 2s and A's to 30s makes B check after the cycle closes,
    /// so B is the victim.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_postgres_deadlock_maps_to_contention() {
        use std::time::Duration;

        let test_db = postgres_helpers::postgres_connection().await;
        let conn_a = postgres_helpers::connect_to_test_db(&test_db.url, 1).await;
        let conn_b = postgres_helpers::connect_to_test_db(&test_db.url, 1).await;

        // Victim selection. Both pools are pinned to one connection, so a
        // session-scoped setting sticks to the session that uses it.
        conn_a
            .execute_unprepared("SET SESSION deadlock_timeout = '30s'")
            .await
            .expect("failed to lengthen A's deadlock timeout");
        conn_b
            .execute_unprepared("SET SESSION deadlock_timeout = '2s'")
            .await
            .expect("failed to shorten B's deadlock timeout");

        let store_b = SeaOrmStore::<StatusListRecord>::new(Arc::new(conn_b));

        let key: Jwk = serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        let issuer = "issuer-deadlock-postgres";
        let cred_store = SeaOrmStore::<Credentials>::new(test_db.db.clone());
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let v = 1000;
        let list_id = "deadlock-row";
        let snapshot_id = "snap-deadlock";
        let base = StatusListRecord {
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-deadlock".to_string(),
            updated_at: v,
        };
        SeaOrmStore::<StatusListRecord>::new(test_db.db.clone())
            .insert_one(base.clone())
            .await
            .unwrap();

        // A claims the snapshot's primary key and holds it uncommitted, so B's
        // history insert will block on it.
        let txn_a = conn_a.begin().await.expect("failed to begin A");
        txn_a
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "INSERT INTO status_list_history \
                 (snapshot_id, list_id, issuer, status_list, sub, iat, exp) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                vec![
                    Value::from(snapshot_id),
                    Value::from(list_id),
                    Value::from(issuer),
                    Value::from(serde_json::json!({ "bits": 1, "lst": "a" })),
                    Value::from("sub-deadlock"),
                    Value::from(v),
                    Value::from(v + 900),
                ],
            ))
            .await
            .expect("A failed to claim the snapshot key");

        // B takes the row lock, then blocks on A's snapshot key.
        let b_call = tokio::spawn(async move {
            store_b
                .update_one_with_snapshot(
                    list_id,
                    StatusListRecord {
                        status_list: StatusList {
                            bits: 1,
                            lst: "writer-b".to_string(),
                        },
                        updated_at: v + 1,
                        ..base
                    },
                    v,
                    StatusListHistoryRecord {
                        snapshot_id: snapshot_id.to_string(),
                        list_id: list_id.to_string(),
                        issuer: issuer.to_string(),
                        status_list: StatusList {
                            bits: 1,
                            lst: "writer-b".to_string(),
                        },
                        sub: "sub-deadlock".to_string(),
                        iat: v + 1,
                        exp: v + 901,
                    },
                )
                .await
        });

        // B must hold the row lock before A closes the cycle, or A waits on a
        // lock B has not taken yet and the test hangs for real.
        await_blocked_sessions(&test_db.db, 1).await;

        // A closes the cycle. Blocks until B is rolled back as the victim, whose
        // rollback releases the row lock A is waiting on.
        txn_a
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "UPDATE status_lists SET sub = 'a' WHERE list_id = $1",
                vec![Value::from(list_id)],
            ))
            .await
            .expect("A must acquire the row lock once B is rolled back as the deadlock victim");

        let result = tokio::time::timeout(Duration::from_secs(30), b_call)
            .await
            .expect("timed out waiting for B")
            .expect("B panicked");

        assert!(
            matches!(result, Err(RepositoryError::Contention { code: "40P01" })),
            "Postgres 40P01 must classify as Contention (409) reporting its own \
             SQLSTATE, not an opaque error (500); got {result:?}"
        );
    }

    /// Raises the session default to REPEATABLE READ and commits a racing write
    /// underneath an in-flight guarded update. Without the pin the update
    /// inherits REPEATABLE READ and fails with `40001`; with it the race
    /// degrades to a guard miss, `Ok(false)`, which the service layer turns into
    /// `409 update_conflict`. Fails if the pin is removed.
    ///
    /// Both write paths are covered because `update_one` was unpinned until
    /// recently: a deployment with `history_retention_secs = 0` reported
    /// `write_contention` where one with history reported `update_conflict` for
    /// the same race. This asserts they now agree.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_postgres_pinned_isolation_downgrades_serialization_failure() {
        use std::time::Duration;

        for with_snapshot in [false, true] {
            let test_db = postgres_helpers::postgres_connection().await;
            let conn_a = postgres_helpers::connect_to_test_db(&test_db.url, 1).await;
            let conn_b = postgres_helpers::connect_to_test_db(&test_db.url, 1).await;

            conn_b
                .execute_unprepared(
                    "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ",
                )
                .await
                .expect("failed to raise B's isolation level");

            let store_b = SeaOrmStore::<StatusListRecord>::new(Arc::new(conn_b));

            let key: Jwk = serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
            let issuer = "issuer-pinned-postgres";
            let cred_store = SeaOrmStore::<Credentials>::new(test_db.db.clone());
            cred_store
                .insert_one(Credentials::new(issuer.to_string(), key))
                .await
                .unwrap();

            let v = 1000;
            let list_id = "pinned-row";
            let base = StatusListRecord {
                list_id: list_id.to_string(),
                issuer: issuer.to_string(),
                status_list: StatusList {
                    bits: 1,
                    lst: "initial".to_string(),
                },
                sub: "sub-pinned".to_string(),
                updated_at: v,
            };
            SeaOrmStore::<StatusListRecord>::new(test_db.db.clone())
                .insert_one(base.clone())
                .await
                .unwrap();

            let txn_a = conn_a.begin().await.expect("failed to begin A");
            txn_a
                .execute(Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    "UPDATE status_lists SET sub = 'a', updated_at = $1 WHERE list_id = $2",
                    vec![Value::from(v + 5), Value::from(list_id)],
                ))
                .await
                .expect("A failed to take the row lock");

            let updated = StatusListRecord {
                status_list: StatusList {
                    bits: 1,
                    lst: "writer-b".to_string(),
                },
                updated_at: v + 1,
                ..base
            };
            let b_call = tokio::spawn(async move {
                if with_snapshot {
                    store_b
                        .update_one_with_snapshot(
                            list_id,
                            updated,
                            v,
                            StatusListHistoryRecord {
                                snapshot_id: "snap-pinned".to_string(),
                                list_id: list_id.to_string(),
                                issuer: issuer.to_string(),
                                status_list: StatusList {
                                    bits: 1,
                                    lst: "writer-b".to_string(),
                                },
                                sub: "sub-pinned".to_string(),
                                iat: v + 1,
                                exp: v + 901,
                            },
                        )
                        .await
                } else {
                    store_b.update_one(list_id, updated, v).await
                }
            });

            // Block until B is actually waiting on A's row lock, so A's commit
            // lands underneath an in-flight statement rather than before one.
            await_blocked_sessions(&test_db.db, 1).await;
            txn_a.commit().await.expect("A failed to commit");

            let result = tokio::time::timeout(Duration::from_secs(30), b_call)
                .await
                .expect("timed out waiting for B")
                .expect("B panicked");

            assert!(
                matches!(result, Ok(false)),
                "the pinned transaction must see A's committed stamp and report a \
                 clean guard miss; a serialization failure here means the pin was \
                 lost and the session default leaked in. \
                 with_snapshot={with_snapshot}, got {result:?}"
            );
        }
    }
}
