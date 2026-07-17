use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, Set,
};
use std::sync::Arc;

use super::error::RepositoryError;
use crate::models::{
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
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;
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

    pub async fn update_one(
        &self,
        list_id: &str,
        entity: StatusListRecord,
    ) -> Result<bool, RepositoryError> {
        let existing = status_lists::Entity::find_by_id(list_id)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))?;
        if existing.is_none() {
            return Ok(false);
        }
        let active = status_lists::ActiveModel {
            list_id: Set(entity.list_id),
            issuer: Set(entity.issuer),
            status_list: Set(entity.status_list),
            sub: Set(entity.sub),
            updated_at: Set(entity.updated_at),
        };
        active
            .update(&*self.db)
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

    /// Finds the snapshot whose half-open validity interval contains `time`.
    /// Using `iat <= time < exp` ensures the token returned to a client passes
    /// the draft-21 §8.4 `iat`/`exp` validation rule.
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
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;
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
    use crate::models::StatusList;
    use jsonwebtoken::jwk::Jwk;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use sea_orm_migration::MigratorTrait;

    #[cfg(feature = "sqlite")]
    async fn sqlite_connection() -> Arc<DatabaseConnection> {
        // Use a unique temp file database for each test to ensure complete isolation
        // when tests run concurrently. Using temp files instead of shared memory
        // avoids migration conflicts with seaql_migrations table.
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("test-{}.db", uuid::Uuid::new_v4()));
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let mut opt = sea_orm::ConnectOptions::new(db_url);
        opt.max_connections(1);
        opt.map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
        let db = sea_orm::Database::connect(opt)
            .await
            .expect("Failed to connect to SQLite");
        crate::database::Migrator::up(&db, None)
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
            crate::database::Migrator::up(&db, None)
                .await
                .expect("Failed to run migrations on MySQL");
            MysqlTestDb {
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
            status_list: crate::models::StatusList {
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
                    ..record
                },
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
            status_list: crate::models::StatusList {
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
                    status_list: crate::models::StatusList {
                        bits: 1,
                        lst: "compressed".to_string(),
                    },
                    sub: "sub-neg-sqlite".to_string(),
                    updated_at: 0,
                },
            )
            .await
            .unwrap();
        assert!(!missing, "update on missing row should report no rows");

        cred_store.delete_by("issuer-neg-sqlite").await.unwrap();
    }
}
