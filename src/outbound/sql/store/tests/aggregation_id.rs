//! The per-issuer aggregation ID: stored at registration, resolvable both ways,
//! kept across credential updates and rollbacks, and assigned on first lookup
//! to credentials a release that predates it registered.
#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

use std::sync::Arc;

use jsonwebtoken::jwk::Jwk;
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

/// The migrations a release before issuer-scoped aggregation does not know.
const AGGREGATION_MIGRATIONS: [&str; 2] = [
    MIGRATION,
    "m20260929_000002_status_lists_issuer_list_id_index",
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

async fn assert_aggregation_id_round_trip(db: Arc<DatabaseConnection>, backend: &str) {
    let repo = SqlCredentialRepo::new(SeaOrmStore::new(db.clone()));
    let aggregation_id = AggregationId::generate();
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

    db.execute_unprepared(
        "INSERT INTO credentials (issuer, public_key) VALUES ('issuer-via-old-pod', '{}')",
    )
    .await
    .unwrap_or_else(|e| {
        panic!("a nullable column must let old pods keep registering on {backend}: {e}")
    });

    let store = SeaOrmStore::<Credentials>::new(db);
    let repo = SqlCredentialRepo::new(store.clone());
    let assigned = AggregationId::generate();
    repo.insert(credential("issuer-current"), assigned)
        .await
        .unwrap();

    let before = repo.find_aggregation_id("issuer-before").await.unwrap();
    let via_old_pod = repo
        .find_aggregation_id("issuer-via-old-pod")
        .await
        .unwrap();
    assert!(before.is_some() && via_old_pod.is_some(), "on {backend}");
    assert_ne!(before, via_old_pod, "on {backend}");
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
    db.execute_unprepared(
        "INSERT INTO credentials (issuer, public_key) VALUES ('issuer-looked-up', '{}')",
    )
    .await
    .unwrap();
    let looked_up = repo
        .find_aggregation_id("issuer-looked-up")
        .await
        .unwrap()
        .expect("the first lookup must assign an ID");

    fixtures::forget_migrations(&db, &AGGREGATION_MIGRATIONS).await;
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
