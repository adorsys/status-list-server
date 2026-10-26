//! The per-issuer aggregation ID: stored at registration, resolvable both ways,
//! kept across credential updates and rollbacks, and assigned on first lookup
//! to credentials a release that predates it registered.
#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

use std::sync::Arc;

use jsonwebtoken::jwk::Jwk;
#[cfg(feature = "sqlite")]
use sea_orm::Database;
use sea_orm::{ConnectionTrait, DatabaseConnection};
use sea_orm_migration::MigratorTrait;

use super::fixtures;
use crate::domain::models::credential::{AggregationId, Credential, Issuer, PublicJwk};
use crate::domain::ports::CredentialRepo;
use crate::outbound::sql::models::Credentials;
use crate::outbound::sql::{Migrator, SeaOrmStore, SqlCredentialRepo};

#[cfg(feature = "mysql")]
use crate::outbound::sql::test_containers::mysql_helpers;
#[cfg(feature = "postgres-tests")]
use crate::outbound::sql::test_containers::postgres_helpers;

const MIGRATION: &str = "m20260929_000001_credentials_aggregation_id";

/// Migration records removed to simulate rollback to a pre-aggregation release.
const ROLLBACK_MIGRATIONS: [&str; 3] = [
    MIGRATION,
    "m20260929_000002_status_lists_issuer_list_id_index",
    "m20261014_000001_credentials_key_id",
];

/// SQL a failed MySQL run may already have committed, in migration order.
const PARTIAL_MIGRATION: [&str; 2] = [
    "ALTER TABLE credentials ADD COLUMN aggregation_id VARCHAR(36) NULL",
    "CREATE UNIQUE INDEX idx_credentials_aggregation_id ON credentials (aggregation_id)",
];

fn migration_index() -> usize {
    Migrator::migrations()
        .iter()
        .position(|m| m.name() == MIGRATION)
        .expect("the aggregation_id migration must be registered")
}

fn credential(issuer: &str) -> Credential {
    Credential {
        issuer: Issuer(issuer.to_string()),
        public_key: PublicJwk::try_new(fixtures::TEST_EC_JWK.as_bytes().to_vec()).unwrap(),
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn registry_aggregation_mappings_survive_database_restart() {
    use crate::domain::ports::CredentialRepo;

    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("registry.db");
    let database_url = format!("sqlite://{}?mode=rwc", database_path.display());
    let first_connection = Database::connect(&database_url).await.unwrap();
    Migrator::up(&first_connection, None).await.unwrap();
    let expected = AggregationId::generate();
    let first_repo = SqlCredentialRepo::new(SeaOrmStore::new(Arc::new(first_connection)));
    first_repo
        .record_registry_aggregation_ids(&[("issuer-restart".into(), expected)])
        .await
        .unwrap();
    drop(first_repo);

    let restarted_connection = Database::connect(&database_url).await.unwrap();
    let restarted_repo = SqlCredentialRepo::new(SeaOrmStore::new(Arc::new(restarted_connection)));
    assert!(
        restarted_repo
            .record_registry_aggregation_ids(&[("issuer-restart".into(), expected)])
            .await
            .is_ok()
    );
    let changed = AggregationId::generate();
    assert_ne!(expected, changed);
    assert!(
        restarted_repo
            .record_registry_aggregation_ids(&[("issuer-restart".into(), changed)])
            .await
            .is_err(),
        "a restarted server must reject a changed registry mapping"
    );
    assert!(
        restarted_repo
            .record_registry_aggregation_ids(&[("another-issuer".into(), expected)])
            .await
            .is_err(),
        "a restarted server must reject reusing a registry aggregation ID"
    );
}

async fn assert_aggregation_id_round_trip(db: Arc<DatabaseConnection>, backend: &str) {
    let repo = SqlCredentialRepo::new(SeaOrmStore::new(db.clone()));
    let aggregation_id = AggregationId::generate();
    let registry_id = AggregationId::generate();
    repo.record_registry_aggregation_ids(&[("registry-issuer".into(), registry_id)])
        .await
        .unwrap_or_else(|e| panic!("recording a registry mapping on {backend}: {e}"));
    repo.record_registry_aggregation_ids(&[("registry-issuer".into(), registry_id)])
        .await
        .unwrap_or_else(|e| panic!("reloading an unchanged registry mapping on {backend}: {e}"));
    assert_eq!(
        repo.find_issuer_by_aggregation_id(registry_id)
            .await
            .unwrap(),
        Some(Issuer("registry-issuer".into())),
        "registry-only mappings remain resolvable from durable ownership on {backend}"
    );
    assert!(
        repo.record_registry_aggregation_ids(&[(
            "registry-issuer".into(),
            AggregationId::generate(),
        )])
        .await
        .is_err(),
        "an issuer cannot change its registry ID on {backend}"
    );
    assert!(
        repo.record_registry_aggregation_ids(&[("different-issuer".into(), registry_id)])
            .await
            .is_err(),
        "a registry ID cannot change issuers on {backend}"
    );
    let mut registry_key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
    registry_key.common.key_id = Some("registry-key".into());
    SeaOrmStore::<Credentials>::new(db.clone())
        .insert_one(
            Credentials::new("registry-issuer".into(), registry_key)
                .with_aggregation_id(registry_id.to_string()),
        )
        .await
        .unwrap_or_else(|e| {
            panic!("registering credentials for a registry-only issuer on {backend}: {e}")
        });
    assert_eq!(
        repo.find_aggregation_id("registry-issuer").await.unwrap(),
        Some(registry_id),
        "credential registration preserves the registry ID on {backend}"
    );
    repo.insert(credential("issuer-agg"), aggregation_id)
        .await
        .unwrap();

    assert_eq!(
        repo.find_aggregation_id("issuer-agg").await.unwrap(),
        Some(aggregation_id),
        "on {backend}"
    );
    assert_eq!(
        repo.find_issuer_by_aggregation_id(aggregation_id)
            .await
            .unwrap(),
        Some(Issuer("issuer-agg".into())),
        "on {backend}"
    );
    assert_eq!(repo.find_aggregation_id("nobody").await.unwrap(), None);
    assert_eq!(
        repo.find_issuer_by_aggregation_id(AggregationId::generate())
            .await
            .unwrap(),
        None,
        "on {backend}"
    );

    let key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
    SeaOrmStore::<Credentials>::new(db)
        .update_one("issuer-agg", Credentials::new("issuer-agg".into(), key))
        .await
        .unwrap();
    assert_eq!(
        repo.find_aggregation_id("issuer-agg").await.unwrap(),
        Some(aggregation_id),
        "a credential update must keep the aggregation ID on {backend}"
    );
}

/// Credentials from before the migration, and from an old pod after it, get
/// an ID on their first lookup and keep it. `already_applied` recreates a
/// failed MySQL run that committed that many statements before stopping.
async fn assert_migration_and_backfill(
    db: Arc<DatabaseConnection>,
    already_applied: usize,
    backend: &str,
) {
    for statement in &PARTIAL_MIGRATION[..already_applied] {
        db.execute_unprepared(statement).await.unwrap();
    }
    db.execute_unprepared(
        "INSERT INTO credentials (issuer, public_key) VALUES ('issuer-before', '{}')",
    )
    .await
    .unwrap();

    Migrator::up(db.as_ref(), None).await.unwrap_or_else(|e| {
        panic!("migrating (already_applied={already_applied}) on {backend}: {e}")
    });

    assert!(
        db.execute_unprepared(
            "INSERT INTO credentials (issuer, public_key) VALUES ('issuer-via-old-pod', '{}')",
        )
        .await
        .is_err(),
        "the ownership foreign key must reject registrations that omit the owner row on {backend}"
    );

    let store = SeaOrmStore::<Credentials>::new(db);
    let repo = SqlCredentialRepo::new(store.clone());
    let registry_id = AggregationId::generate();
    assert_eq!(
        repo.find_stored_aggregation_id("issuer-before")
            .await
            .unwrap(),
        Some(None),
        "the registry validation lookup must preserve a legacy NULL on {backend}"
    );
    repo.assign_aggregation_id("issuer-before", registry_id)
        .await
        .unwrap();
    assert_eq!(
        repo.find_stored_aggregation_id("issuer-before")
            .await
            .unwrap(),
        Some(Some(registry_id)),
        "the accepted registry ID must be adopted on {backend}"
    );
    let assigned = AggregationId::generate();
    repo.insert(credential("issuer-current"), assigned)
        .await
        .unwrap();

    let before = repo.find_aggregation_id("issuer-before").await.unwrap();
    let via_old_pod = repo
        .find_aggregation_id("issuer-via-old-pod")
        .await
        .unwrap();
    assert!(before.is_some(), "on {backend}");
    assert_eq!(
        via_old_pod, None,
        "old-pod registration must not persist on {backend}"
    );
    assert_eq!(
        repo.find_aggregation_id("issuer-before").await.unwrap(),
        before,
        "a second lookup must return the same ID on {backend}"
    );

    // What a pod that lost the race to assign one would write.
    store
        .assign_aggregation_id("issuer-before", &AggregationId::generate().to_string())
        .await
        .unwrap();
    assert_eq!(
        repo.find_aggregation_id("issuer-before").await.unwrap(),
        before,
        "a later assignment must not replace the ID on {backend}"
    );
    assert_eq!(
        repo.find_aggregation_id("issuer-current").await.unwrap(),
        Some(assigned),
        "a lookup must not replace an ID given at registration on {backend}"
    );
    assert_eq!(
        repo.find_issuer_by_aggregation_id(before.unwrap())
            .await
            .unwrap(),
        Some(Issuer("issuer-before".into())),
        "on {backend}"
    );
}

/// Rolling back deletes the two migrations' records and upgrading again re-runs
/// them; every ID must survive, or URIs already handed out return 404.
async fn assert_rollback_keeps_aggregation_ids(db: Arc<DatabaseConnection>, backend: &str) {
    let repo = SqlCredentialRepo::new(SeaOrmStore::new(db.clone()));
    let registered = AggregationId::generate();
    repo.insert(credential("issuer-registered"), registered)
        .await
        .unwrap();
    let mut legacy_key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
    legacy_key.common.key_id = Some("looked-up-key".into());
    SeaOrmStore::<Credentials>::new(db.clone())
        .insert_one(Credentials::new("issuer-looked-up".into(), legacy_key))
        .await
        .unwrap();
    let looked_up = repo
        .find_aggregation_id("issuer-looked-up")
        .await
        .unwrap()
        .expect("the first lookup must assign an ID");

    fixtures::forget_migrations(&db, &ROLLBACK_MIGRATIONS).await;
    Migrator::up(db.as_ref(), None)
        .await
        .unwrap_or_else(|e| panic!("upgrading again after a rollback on {backend}: {e}"));

    for (issuer, aggregation_id) in [
        ("issuer-registered", registered),
        ("issuer-looked-up", looked_up),
    ] {
        assert_eq!(
            repo.find_aggregation_id(issuer).await.unwrap(),
            Some(aggregation_id),
            "the rollback must keep {issuer}'s ID on {backend}"
        );
        assert_eq!(
            repo.find_issuer_by_aggregation_id(aggregation_id)
                .await
                .unwrap(),
            Some(Issuer(issuer.into())),
            "{issuer}'s aggregation URI must still resolve on {backend}"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_aggregation_id_round_trip() {
    assert_aggregation_id_round_trip(fixtures::sqlite_connection().await, "SQLite").await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_aggregation_id_round_trip() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_aggregation_id_round_trip(test_db.connection().await, "MySQL").await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_aggregation_id_round_trip() {
    let test_db = postgres_helpers::postgres_connection().await;
    assert_aggregation_id_round_trip(test_db.db.clone(), "Postgres").await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_aggregation_id_migration_and_backfill() {
    for already_applied in 0..=PARTIAL_MIGRATION.len() {
        let db = fixtures::sqlite_connection_migrated(Some(migration_index() as u32)).await;
        assert_migration_and_backfill(db, already_applied, "SQLite").await;
    }
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_aggregation_id_migration_and_backfill() {
    for already_applied in 0..=PARTIAL_MIGRATION.len() {
        let steps = migration_index() as u32;
        let test_db = mysql_helpers::MysqlTestDb::start_migrated(Some(steps)).await;
        assert_migration_and_backfill(test_db.connection().await, already_applied, "MySQL").await;
    }
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_aggregation_id_migration_and_backfill() {
    for already_applied in 0..=PARTIAL_MIGRATION.len() {
        let steps = migration_index() as u32;
        let test_db = postgres_helpers::postgres_connection_migrated(Some(steps)).await;
        assert_migration_and_backfill(test_db.db.clone(), already_applied, "Postgres").await;
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_rollback_keeps_aggregation_ids() {
    assert_rollback_keeps_aggregation_ids(fixtures::sqlite_connection().await, "SQLite").await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_rollback_keeps_aggregation_ids() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_rollback_keeps_aggregation_ids(test_db.connection().await, "MySQL").await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_rollback_keeps_aggregation_ids() {
    let test_db = postgres_helpers::postgres_connection().await;
    assert_rollback_keeps_aggregation_ids(test_db.db.clone(), "Postgres").await;
}
