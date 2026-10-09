use std::sync::Arc;

use jsonwebtoken::jwk::Jwk;
use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

#[cfg(any(feature = "sqlite", feature = "mysql"))]
mod database;

#[cfg(any(feature = "sqlite", feature = "mysql"))]
use database::{assert_credentials_round_trip, assert_duplicate_insert_maps_to_duplicate_entry};

use super::fixtures;
use crate::outbound::sql::SeaOrmStore;
use crate::outbound::sql::models::{Credentials, credentials};
#[cfg(feature = "sqlite")]
use crate::outbound::sql::{RepositoryError, models::StatusListRecord};

#[cfg(feature = "mysql")]
use crate::outbound::sql::test_containers::mysql_helpers;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_credentials_round_trip() {
    let db = fixtures::sqlite_connection().await;
    assert_credentials_round_trip(db, "issuer-cred-sqlite").await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_credentials_round_trip() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    let db = test_db.connection().await;
    assert_credentials_round_trip(db, "issuer-mysql").await;
}

#[tokio::test]
async fn test_seaorm_store() {
    let mock_db = MockDatabase::new(DatabaseBackend::Postgres);

    let public_key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();

    let entity = Credentials::new("issuer1".to_string(), public_key.clone());
    let updated_entity = Credentials::new("issuer1".to_string(), public_key.clone());

    let db_conn = Arc::new(
        mock_db
            .append_query_results::<credentials::Model, Vec<_>, _>(vec![
                vec![credentials::Model {
                    issuer: entity.issuer.clone(),
                    public_key: entity.public_key.clone().into(),
                    list_count: 0,
                    aggregation_id: None,
                }],
                vec![credentials::Model {
                    issuer: entity.issuer.clone(),
                    public_key: entity.public_key.clone().into(),
                    list_count: 0,
                    aggregation_id: None,
                }],
                vec![credentials::Model {
                    issuer: entity.issuer.clone(),
                    public_key: entity.public_key.clone().into(),
                    list_count: 0,
                    aggregation_id: None,
                }],
                vec![credentials::Model {
                    issuer: updated_entity.issuer.clone(),
                    public_key: updated_entity.public_key.clone().into(),
                    list_count: 0,
                    aggregation_id: None,
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
    let db = fixtures::sqlite_connection().await;
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db);

    let key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();

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

    let rec = fixtures::record(
        "list-neg-sqlite",
        "nonexistent-issuer",
        "compressed",
        "sub-neg-sqlite",
        0,
    );
    let fk_err = store.insert_one(rec, fixtures::NO_LIST_QUOTA).await;
    // A missing credential must stay a 500, not look like a full quota.
    assert!(
        matches!(fk_err, Err(RepositoryError::InsertError(_))),
        "insert with dangling FK must be InsertError (500), got {fk_err:?}"
    );

    let missing = store
        .update_one(
            "missing-list-sqlite",
            fixtures::record(
                "missing-list-sqlite",
                "issuer-neg-sqlite",
                "compressed",
                "sub-neg-sqlite",
                1, // must advance past the guard value below
            ),
            0,
        )
        .await
        .unwrap();
    assert!(!missing, "update on missing row should report no rows");

    cred_store.delete_by("issuer-neg-sqlite").await.unwrap();
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_duplicate_insert_maps_to_duplicate_entry() {
    let db = fixtures::sqlite_connection().await;
    assert_duplicate_insert_maps_to_duplicate_entry(db, "issuer-dup-sqlite", "list-dup-sqlite")
        .await;
}

/// Cross-backend proof (#143): MySQL's duplicate-key error must also parse
/// into `SqlErr::UniqueConstraintViolation`, where the driver format could
/// diverge from sqlite.
#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_duplicate_insert_maps_to_duplicate_entry() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    let db = test_db.connection().await;
    assert_duplicate_insert_maps_to_duplicate_entry(db, "issuer-dup-mysql", "list-dup-mysql").await;
}
