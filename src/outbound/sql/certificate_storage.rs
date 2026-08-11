use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    sea_query::OnConflict,
};

use crate::cert_manager::storage::{Storage, StorageError};

use super::models::certificate_storage;

/// SeaORM-backed certificate-manager storage.
///
/// This adapter stores opaque PEM/JSON certificate-manager values in the
/// application database. [`Storage::store`] is an upsert (insert-or-replace on
/// `name`), so the trait's default [`update`](Storage::update) — which
/// delegates to `store` — matches the replace-current-value semantics.
#[derive(Clone)]
pub struct SqlCertificateStorage {
    db: Arc<DatabaseConnection>,
}

impl SqlCertificateStorage {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }

    fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }
}

#[async_trait]
impl Storage for SqlCertificateStorage {
    #[tracing::instrument(skip(self, value), fields(db.system = "sea-orm"))]
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let now = Self::now();
        let active = certificate_storage::ActiveModel {
            name: Set(key.to_string()),
            value: Set(value.to_string()),
            created_at: Set(now),
            updated_at: Set(now),
            metadata: Set(None),
        };

        certificate_storage::Entity::insert(active)
            .on_conflict(
                OnConflict::column(certificate_storage::Column::Name)
                    .update_columns([
                        certificate_storage::Column::Value,
                        certificate_storage::Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(&*self.db)
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        let row = certificate_storage::Entity::find_by_id(key)
            .one(&*self.db)
            .await?;
        Ok(row.map(|row| row.value))
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        certificate_storage::Entity::delete_many()
            .filter(certificate_storage::Column::Name.eq(key))
            .exec(&*self.db)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    async fn assert_storage_contract(db: Arc<DatabaseConnection>) {
        let storage = SqlCertificateStorage::new(db);

        assert_eq!(storage.load("missing").await.unwrap(), None);

        storage.store("cert_data.json", "initial").await.unwrap();
        assert_eq!(
            storage.load("cert_data.json").await.unwrap().as_deref(),
            Some("initial")
        );

        storage
            .store("cert_data.json", "stored-again")
            .await
            .unwrap();
        assert_eq!(
            storage.load("cert_data.json").await.unwrap().as_deref(),
            Some("stored-again")
        );

        storage.update("cert_data.json", "updated").await.unwrap();
        assert_eq!(
            storage.load("cert_data.json").await.unwrap().as_deref(),
            Some("updated")
        );

        storage.delete("cert_data.json").await.unwrap();
        storage.delete("cert_data.json").await.unwrap();
        assert_eq!(storage.load("cert_data.json").await.unwrap(), None);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_certificate_storage_contract() {
        assert_storage_contract(sqlite_connection().await).await;
    }

    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_certificate_storage_contract() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        assert_storage_contract(test_db.connection().await).await;
    }

    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn test_postgres_certificate_storage_contract() {
        let test_db = postgres_helpers::postgres_connection().await;
        assert_storage_contract(test_db.db).await;
    }
}
