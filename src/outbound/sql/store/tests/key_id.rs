//! Proves the management-key migration against legacy rows, not new inserts.
#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

use crate::outbound::sql::models::Credentials;
use crate::outbound::sql::{Migrator, SeaOrmStore};
use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use std::sync::Arc;

// Independently calculated from the fixture's RFC 7638 canonical public members.
const FIXTURE_THUMBPRINT: &str = "tlBOuPIle0dk1Dbs1lKHGJS5yMXswT8QXuVO4RWwxgg";

async fn insert_legacy_key(db: &DatabaseConnection, issuer: &str, key: &serde_json::Value) {
    let backend = db.get_database_backend();
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
        ("literal-null", Some("null")),
        ("empty-id", Some("")),
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
        insert_legacy_key(&db, issuer, &key).await;
    }
    // Null is also a missing ID. Use a distinct key to avoid a real collision.
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let secret = jsonwebtoken::EncodingKey::from_ec_pem(pair.serialize_pem().as_bytes()).unwrap();
    let null_key =
        jsonwebtoken::jwk::Jwk::from_encoding_key(&secret, jsonwebtoken::Algorithm::ES384).unwrap();
    let null_thumbprint = null_key
        .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
        .unwrap();
    let mut null_key = serde_json::to_value(null_key).unwrap();
    null_key["kid"] = serde_json::Value::Null;
    insert_legacy_key(&db, "null-id", &null_key).await;
    // Do not guess an algorithm for legacy RSA keys.
    let rsa_secret = jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
        "../../../../../test_data/gcloud_test_key.dummy.pem"
    ))
    .unwrap();
    let rsa =
        jsonwebtoken::jwk::Jwk::from_encoding_key(&rsa_secret, jsonwebtoken::Algorithm::PS256)
            .unwrap();
    let rsa_thumbprint = rsa
        .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
        .unwrap();
    let mut rsa = serde_json::to_value(rsa).unwrap();
    rsa.as_object_mut().unwrap().remove("alg");
    insert_legacy_key(&db, "missing-alg", &rsa).await;
    let ed = crate::crypto::SigningKey::generate(crate::crypto::SigningAlgorithm::EdDsa).unwrap();
    let ed_secret =
        jsonwebtoken::EncodingKey::from_ed_pem(ed.to_pkcs8_pem().unwrap().as_bytes()).unwrap();
    let ed_jwk =
        jsonwebtoken::jwk::Jwk::from_encoding_key(&ed_secret, jsonwebtoken::Algorithm::EdDSA)
            .unwrap();
    let ed_thumbprint = ed_jwk
        .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
        .unwrap();
    insert_legacy_key(&db, "ed25519", &serde_json::to_value(ed_jwk).unwrap()).await;
    insert_legacy_key(&db, "unparsable", &serde_json::json!({})).await;
    insert_legacy_key(&db, "private", &{
        let mut key = template.clone();
        key.as_object_mut().unwrap().remove("kid");
        key["d"] = "private-material".into();
        key
    })
    .await;

    // Preflight must report both kinds of collision before writing even an
    // unrelated generated ID, including on MySQL where DDL is not transactional.
    let mut twin = template.clone();
    twin.as_object_mut().unwrap().remove("kid");
    insert_legacy_key(&db, "missing-twin", &twin).await;
    let mut reserved = template.clone();
    reserved["kid"] = null_thumbprint.clone().into();
    insert_legacy_key(&db, "reserved", &reserved).await;
    let error = Migrator::migrations()[migration_index()]
        .up(&SchemaManager::new(db.as_ref()))
        .await
        .expect_err("collisions must be reported before generated IDs are written");
    assert!(matches!(error, sea_orm::DbErr::Migration(_)), "{error}");
    let message = error.to_string();
    for detail in [
        FIXTURE_THUMBPRINT,
        null_thumbprint.as_str(),
        "\"missing\"",
        "\"missing-twin\"",
        "\"null-id\"",
        "\"reserved\"",
        "repair these registrations before retrying",
    ] {
        assert!(message.contains(detail), "missing {detail:?} in {message}");
    }
    for row in db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT public_key, key_id FROM credentials WHERE issuer IN ('missing', 'null-id', 'ed25519')",
        ))
        .await
        .unwrap()
    {
        let key: serde_json::Value = row.try_get("", "public_key").unwrap();
        assert!(key.get("kid").is_none_or(serde_json::Value::is_null));
        assert_eq!(row.try_get::<Option<String>>("", "key_id").unwrap(), None);
    }
    db.execute_unprepared("DELETE FROM credentials WHERE issuer IN ('missing-twin', 'reserved')")
        .await
        .unwrap();
    Migrator::up(db.as_ref(), None).await.unwrap();
    let store = SeaOrmStore::<Credentials>::new(db.clone());
    let found = store.find_credentials_by_kid("existing-key").await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].issuer, "existing");
    let generated = store
        .find_credentials_by_kid(FIXTURE_THUMBPRINT)
        .await
        .unwrap();
    assert_eq!(generated.len(), 1);
    assert_eq!(generated[0].issuer, "missing");
    let mut expected = template.clone();
    expected["kid"] = FIXTURE_THUMBPRINT.into();
    assert_eq!(
        serde_json::to_value(&generated[0].public_key).unwrap(),
        expected
    );
    assert_eq!(
        store
            .find_credentials_by_kid(&null_thumbprint)
            .await
            .unwrap()[0]
            .issuer,
        "null-id"
    );
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
            "literal-null" => assert_eq!(kid.as_deref(), Some("null")),
            "empty-id" => assert_eq!(kid.as_deref(), Some("")),
            "at-limit" => assert_eq!(kid.as_deref(), Some(at_limit.as_str())),
            "missing" => assert_eq!(kid.as_deref(), Some(FIXTURE_THUMBPRINT)),
            "null-id" => assert_eq!(kid.as_deref(), Some(null_thumbprint.as_str())),
            "missing-alg" => assert_eq!(kid.as_deref(), Some(rsa_thumbprint.as_str())),
            "ed25519" => assert_eq!(kid.as_deref(), Some(ed_thumbprint.as_str())),
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
    assert_eq!(
        store
            .find_credentials_by_kid(FIXTURE_THUMBPRINT)
            .await
            .unwrap()[0]
            .public_key
            .common
            .key_id
            .as_deref(),
        Some(FIXTURE_THUMBPRINT)
    );
    assert!(
        store
            .find_credentials_by_kid(&rsa_thumbprint)
            .await
            .unwrap()[0]
            .public_key
            .common
            .key_algorithm
            .is_none()
    );
    // A collision must fail closed without assigning a different ID to an issuer.
    let mut colliding_key = template.clone();
    colliding_key.as_object_mut().unwrap().remove("kid");
    insert_legacy_key(&db, "collision", &colliding_key).await;
    let error = Migrator::migrations()[migration_index()]
        .up(&SchemaManager::new(db.as_ref()))
        .await
        .expect_err("duplicate thumbprints must fail closed");
    assert!(matches!(error, sea_orm::DbErr::Migration(_)), "{error}");
    let message = error.to_string();
    assert!(message.contains("\"collision\""), "{message}");
    assert!(message.contains("\"missing\""), "{message}");
    assert_eq!(
        store.find_credentials_by_kid("existing-key").await.unwrap()[0].issuer,
        "existing"
    );
    assert_eq!(
        store
            .find_credentials_by_kid(FIXTURE_THUMBPRINT)
            .await
            .unwrap()[0]
            .issuer,
        "missing"
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

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_documented_key_inventory_matches_index_collation() {
    async fn inventory(db: &DatabaseConnection) -> Vec<String> {
        // Execute the actual operator instructions, including session setup and cleanup.
        let script = include_str!("../../../../../docs/deployment-runbook.md")
            .split_once("-- MySQL 8+\n")
            .unwrap()
            .1
            .split_once("```")
            .unwrap()
            .0;
        let mut issuers = Vec::new();
        for sql in script.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            let statement = Statement::from_string(sea_orm::DatabaseBackend::MySql, sql);
            if sql.starts_with("WITH ") {
                issuers = db
                    .query_all_raw(statement)
                    .await
                    .unwrap()
                    .iter()
                    .map(|row| row.try_get("", "issuer").unwrap())
                    .collect();
            } else {
                db.execute_raw(statement).await.unwrap();
            }
        }
        issuers.sort();
        issuers
    }

    let fixture =
        crate::outbound::sql::test_containers::mysql_helpers::MysqlTestDb::start_migrated(Some(
            migration_index() as u32,
        ))
        .await;
    let db = fixture.connection().await;
    db.execute_unprepared("ALTER TABLE credentials COLLATE utf8mb4_unicode_ci")
        .await
        .unwrap();
    for (issuer, kid) in [("upper", "Key-1"), ("lower", "key-1"), ("safe", "other")] {
        let mut key: serde_json::Value =
            serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        key["kid"] = kid.into();
        insert_legacy_key(&db, issuer, &key).await;
    }
    // Before migration the new column will inherit the table's collation.
    assert_eq!(inventory(&db).await, ["lower", "upper"]);
    // An existing column can have a different collation from the table default.
    db.execute_unprepared(
        "ALTER TABLE credentials ADD COLUMN key_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL",
    )
    .await
    .unwrap();
    assert!(inventory(&db).await.is_empty());
    let row = db
        .query_one_raw(Statement::from_string(
            sea_orm::DatabaseBackend::MySql,
            "SELECT @@session.collation_connection = @management_saved_collation AS restored",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<i32>("", "restored").unwrap(), 1);
}
