use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, TransactionTrait, sea_query::Expr,
};
use std::sync::Arc;

use super::error::RepositoryError;
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
}

/// Maps an insert failure, distinguishing a unique-constraint violation (a
/// concurrent writer won the check-then-insert race) from real storage
/// failures. `sql_err()` normalizes driver errors across all three backends.
fn map_insert_err(e: sea_orm::DbErr) -> RepositoryError {
    match e.sql_err() {
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_)) => RepositoryError::DuplicateEntry,
        _ => RepositoryError::InsertError(e.to_string()),
    }
}

impl SeaOrmStore<StatusListRecord> {
    pub async fn insert_one(&self, entity: StatusListRecord) -> Result<(), RepositoryError> {
        let active = status_lists::ActiveModel {
            list_id: Set(entity.list_id),
            issuer: Set(entity.issuer),
            status_list: Set(entity.status_list),
            sub: Set(entity.sub),
            updated_at: Set(entity.updated_at),
        };
        status_lists::Entity::insert(active)
            .exec_without_returning(&*self.db)
            .await
            .map_err(map_insert_err)?;
        Ok(())
    }

    pub async fn find_one_by(
        &self,
        value: &str,
    ) -> Result<Option<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub async fn find_all_by(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .filter(status_lists::Column::Issuer.eq(issuer))
            .all(&*self.db)
            .await
            .map(|tokens| tokens.into_iter().collect())
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    /// Optimistic-concurrency update guarded on `updated_at`:
    /// `UPDATE ... WHERE list_id = ? AND updated_at = ?`. `Ok(false)` means the
    /// guard did not match — a racing writer advanced the stamp, or the row is
    /// gone — so a lost update was prevented.
    ///
    /// Uses `rows_affected` rather than `SELECT ... FOR UPDATE` because its
    /// semantics are identical across all three sea-orm backends (#143).
    ///
    /// `entity.updated_at` MUST be strictly greater than `expected_updated_at`,
    /// enforced below: a non-advancing stamp lets two same-second writers both
    /// match the guard, silently losing a flip.
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
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }

    /// Like [`update_one`](Self::update_one), but the guarded `UPDATE` and the
    /// `status_list_history` `INSERT` run in one transaction: both commit or
    /// neither does. This closes the split the plain `update_one` leaves open,
    /// where the row changes but a failing snapshot insert leaves nothing
    /// recording it. Transaction semantics are portable across all three
    /// sea-orm backends (#143). Same `false`-on-guard-miss and
    /// strictly-advancing-stamp contract as `update_one`.
    pub async fn update_one_with_snapshot(
        &self,
        list_id: &str,
        entity: StatusListRecord,
        expected_updated_at: i64,
        snapshot: StatusListHistoryRecord,
    ) -> Result<bool, RepositoryError> {
        if entity.updated_at <= expected_updated_at {
            return Err(RepositoryError::UpdateError(format!(
                "guarded update requires a strictly newer updated_at \
                 (new={}, expected-guard={}); a non-advancing stamp would \
                 silently reintroduce the same-second lost update",
                entity.updated_at, expected_updated_at
            )));
        }

        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;

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
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;

        if result.rows_affected == 0 {
            // Guard miss: roll back so nothing is recorded.
            txn.rollback()
                .await
                .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
            return Ok(false);
        }

        let history_active: status_list_history::ActiveModel = snapshot.into();
        if let Err(insert_err) = status_list_history::Entity::insert(history_active)
            .exec(&txn)
            .await
        {
            // Snapshot INSERT failed after the row UPDATE landed: roll the row
            // back so a changed row never outlives the snapshot recording it.
            txn.rollback().await.map_err(|rollback_err| {
                RepositoryError::InsertError(format!(
                    "history snapshot insert failed ({insert_err}); \
                     rolling back the row update also failed: {rollback_err}"
                ))
            })?;
            return Err(RepositoryError::InsertError(insert_err.to_string()));
        }

        txn.commit()
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
        Ok(true)
    }

    pub async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        let result = status_lists::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }

    pub async fn find_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .filter(status_lists::Column::Sub.eq(issuer))
            .all(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub async fn find_all(&self) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .all(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub async fn find_all_status_list_uris(&self) -> Result<Vec<String>, RepositoryError> {
        status_lists::Entity::find()
            .select_only()
            .column(status_lists::Column::Sub)
            .group_by(status_lists::Column::Sub)
            .order_by_asc(status_lists::Column::Sub)
            .into_tuple::<String>()
            .all(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }
}

impl SeaOrmStore<StatusListHistoryRecord> {
    pub async fn insert_one(&self, entity: StatusListHistoryRecord) -> Result<(), RepositoryError> {
        let active: status_list_history::ActiveModel = entity.into();
        status_list_history::Entity::insert(active)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;
        Ok(())
    }

    /// Finds the snapshot whose half-open interval `iat <= time < exp` contains
    /// `time` (draft-21 §8.4). Intervals intentionally overlap — a superseded
    /// snapshot keeps its original later `exp` — so `ORDER BY iat DESC LIMIT 1`
    /// picks the newest one in effect at `time`. The memory adapter mirrors this
    /// via `max_by_key(iat)`.
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
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    /// Deletes snapshots older than the given cutoff timestamp.
    /// Returns the number of rows deleted.
    pub async fn delete_older_than(&self, cutoff: i64) -> Result<u64, RepositoryError> {
        let result = status_list_history::Entity::delete_many()
            .filter(status_list_history::Column::Exp.lt(cutoff))
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected)
    }
}

impl SeaOrmStore<Credentials> {
    pub async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        let active: credentials::ActiveModel = entity.into();
        credentials::Entity::insert(active)
            .exec_without_returning(&*self.db)
            .await
            .map_err(map_insert_err)?;
        Ok(())
    }

    pub async fn find_one_by(&self, value: &str) -> Result<Option<Credentials>, RepositoryError> {
        credentials::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map(|opt| opt.map(Credentials::from))
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub async fn update_one(
        &self,
        issuer: &str,
        entity: Credentials,
    ) -> Result<bool, RepositoryError> {
        let existing = credentials::Entity::find_by_id(issuer)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))?;
        if existing.is_none() {
            return Ok(false);
        }
        let active: credentials::ActiveModel = entity.into();
        active
            .update(&*self.db)
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
        Ok(true)
    }

    pub async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        let result = credentials::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::adapters::sea_orm::models::StatusList;
    use jsonwebtoken::jwk::Jwk;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    // `Migrator::up` is only called from the real-backend helpers below.
    #[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
    use sea_orm_migration::MigratorTrait;

    #[cfg(feature = "sqlite")]
    async fn sqlite_connection() -> Arc<DatabaseConnection> {
        let mut opt = sea_orm::ConnectOptions::new("sqlite::memory:");
        opt.max_connections(1);
        opt.map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
        let db = sea_orm::Database::connect(opt)
            .await
            .expect("Failed to connect to SQLite");
        crate::adapters::sea_orm::Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations on SQLite");
        Arc::new(db)
    }

    #[cfg(feature = "mysql")]
    mod mysql_helpers {
        use super::*;
        use sea_orm::ConnectionTrait;
        use testcontainers_modules::{
            mysql::Mysql as MysqlImage,
            testcontainers::{ContainerAsync, runners::AsyncRunner},
        };

        pub(super) struct MysqlTestDb {
            #[allow(dead_code)]
            pub(super) _container: ContainerAsync<MysqlImage>,
            pub(super) db: Arc<DatabaseConnection>,
        }

        pub(super) async fn mysql_connection() -> MysqlTestDb {
            let node = MysqlImage::default()
                .start()
                .await
                .expect("Failed to start MySQL container");
            let host = node.get_host().await.expect("Failed to resolve MySQL host");
            let port = node
                .get_host_port_ipv4(3306)
                .await
                .expect("Failed to resolve MySQL port");

            // Connect without database first to create a unique database
            let admin_url = format!("mysql://{}:{}", host, port);
            let db_name = format!("test_{}", uuid::Uuid::new_v4().simple());

            // Create the database
            let admin_conn = sea_orm::Database::connect(&admin_url)
                .await
                .expect("Failed to connect to MySQL admin");
            admin_conn
                .execute_unprepared(&format!(
                    "CREATE DATABASE {} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
                    db_name
                ))
                .await
                .expect("Failed to create test database");

            // Connect to the new database and run migrations
            let mysql_url = format!("mysql://{}:{}/{}", host, port, db_name);
            let mut opt = sea_orm::ConnectOptions::new(mysql_url);
            opt.max_connections(5);
            let db = sea_orm::Database::connect(opt)
                .await
                .expect("Failed to connect to MySQL");
            crate::adapters::sea_orm::Migrator::up(&db, None)
                .await
                .expect("Failed to run migrations on MySQL");
            MysqlTestDb {
                _container: node,
                db: Arc::new(db),
            }
        }
    }

    #[cfg(feature = "postgres-tests")]
    mod postgres_helpers {
        use super::*;
        use testcontainers_modules::{
            postgres::Postgres as PostgresImage,
            testcontainers::{ContainerAsync, runners::AsyncRunner},
        };

        pub(super) struct PostgresTestDb {
            #[allow(dead_code)]
            pub(super) _container: ContainerAsync<PostgresImage>,
            pub(super) db: Arc<DatabaseConnection>,
        }

        pub(super) async fn postgres_connection() -> PostgresTestDb {
            let node = PostgresImage::default()
                .start()
                .await
                .expect("Failed to start Postgres container");
            let host = node
                .get_host()
                .await
                .expect("Failed to resolve Postgres host");
            let port = node
                .get_host_port_ipv4(5432)
                .await
                .expect("Failed to resolve Postgres port");

            // testcontainers' Postgres image defaults to postgres/postgres/postgres.
            let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
            let mut opt = sea_orm::ConnectOptions::new(url);
            opt.max_connections(5);
            let db = sea_orm::Database::connect(opt)
                .await
                .expect("Failed to connect to Postgres");
            crate::adapters::sea_orm::Migrator::up(&db, None)
                .await
                .expect("Failed to run migrations on Postgres");
            PostgresTestDb {
                _container: node,
                db: Arc::new(db),
            }
        }
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
        let test_db = mysql_helpers::mysql_connection().await;
        let store = SeaOrmStore::<Credentials>::new(test_db.db.clone());

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
            status_list: crate::adapters::sea_orm::models::StatusList {
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
            status_list: crate::adapters::sea_orm::models::StatusList {
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
                    status_list: crate::adapters::sea_orm::models::StatusList {
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
        let test_db = mysql_helpers::mysql_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(test_db.db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(test_db.db.clone());

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

    /// Cross-backend proof (#143): the optimistic guard behaves identically on
    /// MySQL, exercising the JSON `col_expr` write and `rows_affected` semantics
    /// most likely to diverge from sqlite.
    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_update_one_optimistic_guard_rejects_stale_write() {
        let test_db = mysql_helpers::mysql_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(test_db.db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(test_db.db.clone());

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

    #[cfg(feature = "sqlite")]
    const TEST_EC_JWK: &str = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
        "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
    }"#;

    /// The core acceptance test: the guarded row UPDATE and the history INSERT
    /// succeed or fail as a unit. Covers the happy path, the forced-INSERT-
    /// failure rollback (no partial snapshot), and the conflict path — against
    /// real SQLite, since `MockDatabase` cannot model rollback.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_update_with_snapshot_is_atomic() {
        let db = sqlite_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
        let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

        let key: Jwk = serde_json::from_str(TEST_EC_JWK).unwrap();
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
            result.is_err(),
            "a failed snapshot insert must fail the whole unit"
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

    /// Cross-backend proof (#143): on MySQL a failed snapshot INSERT must roll
    /// the paired row UPDATE back. Requires InnoDB (pinned by the migration) —
    /// a non-transactional engine would silently keep the row change.
    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_update_with_snapshot_rolls_back_on_history_failure() {
        let test_db = mysql_helpers::mysql_connection().await;
        let cred_store = SeaOrmStore::<Credentials>::new(test_db.db.clone());
        let store = SeaOrmStore::<StatusListRecord>::new(test_db.db.clone());

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
}
