//! Proves the management-key migration against legacy rows, not new inserts.
#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

use crate::outbound::sql::models::Credentials;
use crate::outbound::sql::{Migrator, SeaOrmStore};
use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use std::sync::Arc;

fn migration_index() -> usize {
    Migrator::migrations()
        .iter()
        .position(|m| m.name() == "m20261014_000001_credentials_key_id")
        .unwrap()
}

async fn assert_key_id_backfill(db: Arc<DatabaseConnection>) {
    let backend = db.get_database_backend();
    let template: serde_json::Value =
        serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
    let at_limit = "é".repeat(255);
    let over_limit = "é".repeat(256);
    for (issuer, kid) in [
        ("existing", Some("existing-key")),
        ("missing", None),
        ("at-limit", Some(at_limit.as_str())),
        ("over-limit", Some(over_limit.as_str())),
    ] {
        let mut key = template.clone();
        if let Some(kid) = kid {
            key["kid"] = kid.into();
        } else {
            key.as_object_mut().unwrap().remove("kid");
        }
        let sql = match backend {
            sea_orm::DatabaseBackend::Postgres => {
                "INSERT INTO credentials (issuer, public_key) VALUES ($1, CAST($2 AS JSONB))"
            }
            _ => "INSERT INTO credentials (issuer, public_key) VALUES (?, ?)",
        };
        db.execute_raw(Statement::from_sql_and_values(
            backend,
            sql,
            [issuer.into(), key.to_string().into()],
        ))
        .await
        .unwrap();
    }
    Migrator::up(db.as_ref(), None).await.unwrap();
    let store = SeaOrmStore::<Credentials>::new(db.clone());
    let found = store.find_credentials_by_kid("existing-key").await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].issuer, "existing");
    assert_eq!(
        store.find_credentials_by_kid(&at_limit).await.unwrap()[0].issuer,
        "at-limit"
    );
    let rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT issuer, key_id FROM credentials ORDER BY issuer",
        ))
        .await
        .unwrap();
    for row in rows {
        let issuer: String = row.try_get("", "issuer").unwrap();
        let kid: Option<String> = row.try_get("", "key_id").unwrap();
        match issuer.as_str() {
            "existing" => assert_eq!(kid.as_deref(), Some("existing-key")),
            "at-limit" => assert_eq!(kid.as_deref(), Some(at_limit.as_str())),
            _ => assert_eq!(kid, None, "{issuer}"),
        }
    }
    // A rollback/re-upgrade must preserve the indexed values.
    Migrator::migrations()[migration_index()]
        .up(&SchemaManager::new(db.as_ref()))
        .await
        .unwrap();
    assert_eq!(
        store
            .find_credentials_by_kid("existing-key")
            .await
            .unwrap()
            .len(),
        1
    );
    let duplicate = Credentials::new(
        "duplicate".into(),
        serde_json::from_value({
            let mut key = template;
            key["kid"] = "existing-key".into();
            key
        })
        .unwrap(),
    );
    assert!(matches!(
        store.insert_one(duplicate).await,
        Err(crate::outbound::sql::RepositoryError::DuplicateEntry)
    ));
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_key_id_backfill() {
    assert_key_id_backfill(
        super::fixtures::sqlite_connection_migrated(Some(migration_index() as u32)).await,
    )
    .await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_key_id_backfill() {
    let db = crate::outbound::sql::test_containers::mysql_helpers::MysqlTestDb::start_migrated(
        Some(migration_index() as u32),
    )
    .await;
    assert_key_id_backfill(db.connection().await).await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_key_id_backfill() {
    let db = crate::outbound::sql::test_containers::postgres_helpers::postgres_connection_migrated(
        Some(migration_index() as u32),
    )
    .await;
    assert_key_id_backfill(db.db.clone()).await;
}
