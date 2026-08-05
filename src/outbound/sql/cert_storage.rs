use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

use crate::cert_manager::storage::{Storage, StorageError};

use super::models::certificate_storage;

/// SeaORM-backed certificate-manager storage.
///
/// This adapter stores opaque string values in the application database. It is
/// suitable for certificate chains, ACME account state and signing keys when a
/// separate object store or secrets manager is unavailable. It deliberately
/// avoids logging stored values.
#[derive(Clone)]
pub struct SqlCertificateStorage {
    db: Arc<DatabaseConnection>,
}

impl SqlCertificateStorage {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Storage for SqlCertificateStorage {
    #[tracing::instrument(skip(self, value), fields(db.system = "sea-orm"))]
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let active = certificate_storage::ActiveModel {
            key: Set(key.to_string()),
            value: Set(value.to_string()),
            metadata: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };

        certificate_storage::Entity::insert(active)
            .on_conflict(
                sea_orm::sea_query::OnConflict::column(certificate_storage::Column::Key)
                    .update_columns([
                        certificate_storage::Column::Value,
                        certificate_storage::Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(&*self.db)
            .await
            .map_err(|e| StorageError::Sql(e.to_string()))?;
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        certificate_storage::Entity::find_by_id(key)
            .one(&*self.db)
            .await
            .map(|row| row.map(|row| row.value))
            .map_err(|e| StorageError::Sql(e.to_string()))
    }

    #[tracing::instrument(skip(self, value), fields(db.system = "sea-orm"))]
    async fn update(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let existing = certificate_storage::Entity::find_by_id(key)
            .one(&*self.db)
            .await
            .map_err(|e| StorageError::Sql(e.to_string()))?;

        if let Some(existing) = existing {
            let mut active: certificate_storage::ActiveModel = existing.into();
            active.value = Set(value.to_string());
            active.updated_at = Set(now);
            active
                .update(&*self.db)
                .await
                .map_err(|e| StorageError::Sql(e.to_string()))?;
        } else {
            self.store(key, value).await?;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        certificate_storage::Entity::delete_many()
            .filter(certificate_storage::Column::Key.eq(key))
            .exec(&*self.db)
            .await
            .map_err(|e| StorageError::Sql(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
    use super::*;
    #[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
    use sea_orm::{ConnectionTrait, FromQueryResult, Statement};
    #[cfg(feature = "sqlite")]
    use sea_orm_migration::MigratorTrait;

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

    #[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
    async fn assert_storage_contract(db: Arc<DatabaseConnection>) {
        let storage = SqlCertificateStorage::new(db.clone());

        assert_eq!(storage.load("missing").await.unwrap(), None);

        storage.store("signing-key", "first-secret").await.unwrap();
        assert_eq!(
            storage.load("signing-key").await.unwrap().as_deref(),
            Some("first-secret")
        );

        storage.store("signing-key", "second-secret").await.unwrap();
        assert_eq!(
            storage.load("signing-key").await.unwrap().as_deref(),
            Some("second-secret")
        );

        storage.update("signing-key", "third-secret").await.unwrap();
        assert_eq!(
            storage.load("signing-key").await.unwrap().as_deref(),
            Some("third-secret")
        );

        storage.update("new-key", "new-secret").await.unwrap();
        assert_eq!(
            storage.load("new-key").await.unwrap().as_deref(),
            Some("new-secret")
        );

        storage.delete("signing-key").await.unwrap();
        storage.delete("signing-key").await.unwrap();
        assert_eq!(storage.load("signing-key").await.unwrap(), None);
    }

    #[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
    #[derive(Debug, FromQueryResult)]
    struct StoredRow {
        storage_key: String,
        value: String,
        metadata: Option<serde_json::Value>,
        created_at: i64,
        updated_at: i64,
    }

    #[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
    async fn assert_schema_shape(db: Arc<DatabaseConnection>) {
        let backend = db.get_database_backend();
        let sql = match backend {
            sea_orm::DatabaseBackend::Postgres => {
                "SELECT storage_key, value, metadata, created_at, updated_at \
                 FROM certificate_storage WHERE storage_key = $1"
            }
            _ => {
                "SELECT storage_key, value, metadata, created_at, updated_at \
                 FROM certificate_storage WHERE storage_key = ?"
            }
        };
        let row = StoredRow::find_by_statement(Statement::from_sql_and_values(
            backend,
            sql,
            vec!["new-key".into()],
        ))
        .one(db.as_ref())
        .await
        .expect("schema query failed")
        .expect("stored row should exist");

        assert_eq!(row.storage_key, "new-key");
        assert_eq!(row.value, "new-secret");
        assert!(row.metadata.is_none());
        assert!(row.created_at > 0);
        assert!(row.updated_at >= row.created_at);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_certificate_storage_contract() {
        let db = sqlite_connection().await;
        assert_storage_contract(db.clone()).await;
        assert_schema_shape(db).await;
    }

    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_certificate_storage_contract() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        let db = test_db.connection().await;
        assert_storage_contract(db.clone()).await;
        assert_schema_shape(db).await;
    }

    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn test_postgres_certificate_storage_contract() {
        let test_db = postgres_helpers::postgres_connection().await;
        let db = test_db.db;
        assert_storage_contract(db.clone()).await;
        assert_schema_shape(db).await;
    }
}
