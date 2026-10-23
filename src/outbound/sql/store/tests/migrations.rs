//! Migrations only move forward: `down`, `reset`, `refresh` and `fresh` are
//! refused, and rolling back relies on every migration re-running once its
//! record is deleted. See "Migrations are forward-only" in
//! `src/outbound/sql/README.md`.
#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

use std::sync::Arc;

use jsonwebtoken::jwk::Jwk;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr, EntityTrait, Statement};
use sea_orm_migration::{MigrationTrait, MigratorTrait, SchemaManager};

use super::fixtures;
use crate::domain::models::credential::AggregationId;
use crate::domain::ports::CredentialRepo;
use crate::outbound::sql::Migrator;
use crate::outbound::sql::SeaOrmStore;
use crate::outbound::sql::SqlCredentialRepo;
use crate::outbound::sql::list_quota;
use crate::outbound::sql::migrations::apply_migrations;
use crate::outbound::sql::migrations::issuer_ownership;
use crate::outbound::sql::models::{Credentials, credentials};

#[cfg(feature = "mysql")]
use crate::outbound::sql::test_containers::mysql_helpers;
#[cfg(feature = "postgres-tests")]
use crate::outbound::sql::test_containers::postgres_helpers;

/// The oldest migrations, whose `up`s cannot re-run: they are unguarded, and
/// MySQL has no `CREATE INDEX IF NOT EXISTS`. Every release that can still be
/// rolled back to knows them.
const PREDATE_RERUN_RULE: [&str; 4] = [
    "mod",
    "add_updated_at",
    "m20250101_000003_status_list_history",
    "m20260727_000001_status_list_history_exp_index",
];

const OWNERSHIP_MIGRATION: &str = "m20261022_000001_issuer_ownership";
const ISSUER_AGGREGATIONS_MIGRATION: &str = "m20261020_000001_issuer_aggregations";

fn ownership_migration_index() -> usize {
    Migrator::migrations()
        .iter()
        .position(|migration| migration.name() == OWNERSHIP_MIGRATION)
        .expect("ownership migration must be registered")
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_upgrade_renames_the_develop_issuer_aggregations_table() {
    use sea_orm::ConnectionTrait;

    let db = fixtures::sqlite_connection_migrated(Some(
        Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == ISSUER_AGGREGATIONS_MIGRATION)
            .expect("historical migration must be registered") as u32
            + 1,
    ))
    .await;
    let expected = AggregationId::generate();
    db.execute_unprepared(&format!(
        "INSERT INTO issuer_aggregations (issuer, aggregation_id) VALUES ('develop-issuer', '{expected}')"
    ))
    .await
    .unwrap();

    Migrator::up(db.as_ref(), None)
        .await
        .expect("upgrade from the develop schema must succeed");

    assert!(
        !SchemaManager::new(db.as_ref())
            .has_table("issuer_aggregations")
            .await
            .unwrap()
    );
    let stored = SqlCredentialRepo::new(SeaOrmStore::new(db.clone()))
        .find_aggregation_id("develop-issuer")
        .await
        .unwrap();
    assert_eq!(stored, Some(expected));
}

/// Stands in for a release that knows only the first `N` migrations, as v1.2.0
/// knows the four oldest.
struct PreviousRelease<const N: usize>;

#[async_trait::async_trait]
impl<const N: usize> MigratorTrait for PreviousRelease<N> {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        let mut migrations = Migrator::migrations();
        migrations.truncate(N);
        migrations
    }
}

/// `down` to zero fails on the newest migration with every record kept, each
/// migration's own `down` is refused too, and so are `fresh`, `reset` and
/// `refresh`, with every table kept.
async fn assert_down_is_refused(db: Arc<DatabaseConnection>, backend: &str) {
    let migrations = Migrator::migrations();

    let message = Migrator::down(db.as_ref(), None)
        .await
        .expect_err(&format!("down must be refused on {backend}"))
        .to_string();
    let newest = migrations.last().unwrap().name();
    assert!(
        message.contains(newest) && message.contains("docs/deployment-runbook.md"),
        "the refusal must name the migration and the runbook on {backend}: {message}"
    );

    let manager = SchemaManager::new(db.as_ref());
    for migration in &migrations {
        let name = migration.name();
        match migration.down(&manager).await {
            Err(DbErr::Migration(message)) if message.contains(name) => {}
            other => panic!("{name} must refuse down on {backend}, got {other:?}"),
        }
    }

    for (operation, result) in [
        ("fresh", Migrator::fresh(db.as_ref()).await),
        ("reset", Migrator::reset(db.as_ref()).await),
        ("refresh", Migrator::refresh(db.as_ref()).await),
    ] {
        let message = result
            .expect_err(&format!("{operation} must be refused on {backend}"))
            .to_string();
        assert!(
            message.contains("docs/deployment-runbook.md"),
            "the {operation} refusal must name the runbook on {backend}: {message}"
        );
    }
    assert!(
        manager.has_table("credentials").await.unwrap(),
        "a refused fresh must keep every table on {backend}"
    );

    assert_eq!(
        Migrator::get_applied_migrations(db.as_ref())
            .await
            .unwrap()
            .len(),
        migrations.len(),
        "a refused down must keep every record on {backend}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_down_is_refused() {
    assert_down_is_refused(fixtures::sqlite_connection().await, "SQLite").await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_down_is_refused() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_down_is_refused(test_db.connection().await, "MySQL").await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_down_is_refused() {
    let test_db = postgres_helpers::postgres_connection().await;
    assert_down_is_refused(test_db.db.clone(), "Postgres").await;
}

/// Rolling back to any release after [`PREDATE_RERUN_RULE`] deletes the records
/// from some migration on. Covers every such point, so later migrations are
/// held to the rule without being listed.
async fn assert_every_migration_reruns_after_a_rollback(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    let migrations = Migrator::migrations();
    let names: Vec<&str> = migrations.iter().map(|m| m.name()).collect();
    assert_eq!(
        names[..PREDATE_RERUN_RULE.len()],
        PREDATE_RERUN_RULE,
        "only the oldest migrations may predate the rule"
    );

    fixtures::seed_credential(&db, "issuer-rerun").await;
    let aggregation_id = AggregationId::generate();
    SqlCredentialRepo::new(SeaOrmStore::new(db.clone()))
        .record_registry_aggregation_ids(&[("issuer-rerun".into(), aggregation_id)])
        .await
        .unwrap();
    fixtures::insert_list_as_old_pod(&db, "list-rerun", "issuer-rerun").await;
    db.execute_unprepared("UPDATE status_lists SET version = 7 WHERE list_id = 'list-rerun'")
        .await
        .unwrap();

    for first in PREDATE_RERUN_RULE.len()..names.len() {
        let enforced = list_quota::is_enforced(&db).await.unwrap();
        fixtures::forget_migrations(&db, &names[first..]).await;
        Migrator::up(db.as_ref(), None).await.unwrap_or_else(|e| {
            panic!(
                "upgrading again after a rollback to before {} on {backend}: {e}",
                names[first]
            )
        });
        assert_eq!(
            fixtures::list_count(&db, "issuer-rerun").await,
            1,
            "list_count must match the issuer's lists after a rollback to before {} on {backend}",
            names[first]
        );
        let version = db
            .query_one_raw(Statement::from_string(
                db.get_database_backend(),
                "SELECT version FROM status_lists WHERE list_id = 'list-rerun'",
            ))
            .await
            .unwrap()
            .expect("the list must survive the re-run")
            .try_get_by_index::<i64>(0)
            .unwrap();
        assert_eq!(
            version, 7,
            "a re-run must keep the list's version after a rollback to before {} on {backend}",
            names[first]
        );
        assert_eq!(
            SqlCredentialRepo::new(SeaOrmStore::new(db.clone()))
                .find_issuer_by_aggregation_id(aggregation_id)
                .await
                .unwrap(),
            Some(crate::domain::models::credential::Issuer(
                "issuer-rerun".into()
            )),
            "a re-run must preserve issuer aggregation ownership on {backend}"
        );
        assert_eq!(
            list_quota::is_enforced(&db).await.unwrap(),
            enforced,
            "a re-run must keep the quota switch after a rollback to before {} on {backend}",
            names[first]
        );
        fixtures::enforce_list_quota(&db).await;
    }
}

async fn assert_ownership_migration_backfills_mixed_data(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    let credential_id = AggregationId::generate();
    let registry_id = AggregationId::generate();
    let mut with_id_key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
    with_id_key.common.key_id = Some("key-with-id".into());
    let mut without_id_key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
    without_id_key.common.key_id = Some("key-without-id".into());

    db.execute_unprepared(&format!(
        "INSERT INTO issuers (issuer, aggregation_id) VALUES ('credential-with-id', '{credential_id}'), ('registry-only', '{registry_id}')"
    )).await.unwrap();
    let with_id: credentials::ActiveModel =
        Credentials::new("credential-with-id".into(), with_id_key)
            .with_aggregation_id(credential_id.to_string())
            .into();
    credentials::Entity::insert(with_id)
        .exec_without_returning(db.as_ref())
        .await
        .unwrap();
    let without_id: credentials::ActiveModel =
        Credentials::new("credential-without-id".into(), without_id_key).into();
    credentials::Entity::insert(without_id)
        .exec_without_returning(db.as_ref())
        .await
        .unwrap();
    fixtures::insert_list_as_old_pod(&db, "owned-list", "credential-with-id").await;
    fixtures::insert_list_as_old_pod(&db, "legacy-list", "credential-without-id").await;
    db.execute_unprepared(
        "INSERT INTO status_list_allocations (list_id, idx) VALUES ('owned-list', 7)",
    )
    .await
    .unwrap();

    Migrator::up(db.as_ref(), None)
        .await
        .unwrap_or_else(|error| panic!("ownership migration failed on {backend}: {error}"));

    db.execute_unprepared(
        "UPDATE credentials SET list_count = 0 WHERE issuer = 'credential-with-id'",
    )
    .await
    .unwrap();
    issuer_ownership::Migration
        .up(&SchemaManager::new(db.as_ref()))
        .await
        .unwrap_or_else(|error| panic!("ownership migration rerun failed on {backend}: {error}"));

    assert_eq!(fixtures::list_count(&db, "credential-with-id").await, 1);
    assert_eq!(fixtures::list_count(&db, "credential-without-id").await, 1);
    assert_eq!(fixtures::list_count(&db, "registry-only").await, 0);
    let repo = SqlCredentialRepo::new(SeaOrmStore::new(db.clone()));
    assert_eq!(
        repo.find_stored_aggregation_id("credential-without-id")
            .await
            .unwrap(),
        Some(None),
        "the migration must retain null aggregation IDs on {backend}"
    );
    assert_eq!(
        repo.find_issuer_by_aggregation_id(credential_id)
            .await
            .unwrap(),
        Some(crate::domain::models::credential::Issuer(
            "credential-with-id".into()
        ))
    );
    assert_eq!(
        repo.find_issuer_by_aggregation_id(registry_id)
            .await
            .unwrap(),
        Some(crate::domain::models::credential::Issuer(
            "registry-only".into()
        ))
    );
    assert_eq!(
        db.query_one_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT idx FROM status_list_allocations WHERE list_id = 'owned-list'",
        ))
        .await
        .unwrap()
        .expect("allocation must survive the ownership migration")
        .try_get_by_index::<i32>(0)
        .unwrap(),
        7
    );
    assert!(
        db.execute_unprepared("DELETE FROM issuers WHERE issuer = 'credential-with-id'")
            .await
            .is_err(),
        "owners with credentials or status lists must not be deleted on {backend}"
    );
    db.execute_unprepared(
        "INSERT INTO status_lists (list_id, issuer, status_list, sub) \
         VALUES ('default-updated-at', 'credential-with-id', '{}', 'sub-default')",
    )
    .await
    .unwrap();
    assert_eq!(
        db.query_one_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT updated_at FROM status_lists WHERE list_id = 'default-updated-at'",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index::<i64>(0)
        .unwrap(),
        0,
        "the status-list timestamp default must survive the migration on {backend}"
    );
    assert!(
        db.execute_unprepared(
            "INSERT INTO status_lists (list_id, issuer, status_list, sub, updated_at) \
             VALUES ('orphan-list', 'missing-issuer', '{}', 'sub', 0)",
        )
        .await
        .is_err(),
        "status lists must reference issuers on {backend}"
    );
    let missing_key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
    let missing: credentials::ActiveModel =
        Credentials::new("missing-owner".into(), missing_key).into();
    assert!(
        credentials::Entity::insert(missing)
            .exec_without_returning(db.as_ref())
            .await
            .is_err(),
        "credentials must reference issuers on {backend}"
    );
}

async fn assert_ownership_collision_fails_before_schema_changes(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    let conflicting_id = AggregationId::generate();
    db.execute_unprepared(&format!(
        "INSERT INTO issuers (issuer, aggregation_id) VALUES ('registry-owner', '{conflicting_id}')"
    ))
    .await
    .unwrap();
    let mut key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
    key.common.key_id = Some("collision-test-key".into());
    let credential: credentials::ActiveModel = Credentials::new("credential-owner".into(), key)
        .with_aggregation_id(conflicting_id.to_string())
        .into();
    credentials::Entity::insert(credential)
        .exec_without_returning(db.as_ref())
        .await
        .unwrap();

    let error = issuer_ownership::Migration
        .up(&SchemaManager::new(db.as_ref()))
        .await
        .expect_err("the migration must reject a conflicting public ID");
    let message = error.to_string();
    assert!(
        message.contains("registry-owner")
            && message.contains("credential-owner")
            && message.contains(&conflicting_id.to_string()),
        "the migration must name both issuers and the colliding ID on {backend}: {message}"
    );
    assert!(
        !SchemaManager::new(db.as_ref())
            .has_column("issuers", "list_count")
            .await
            .unwrap(),
        "collision detection must happen before altering the schema on {backend}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_ownership_migration_backfills_mixed_data() {
    let db = fixtures::sqlite_connection_migrated(Some(ownership_migration_index() as u32)).await;
    assert_ownership_migration_backfills_mixed_data(db, "SQLite").await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_ownership_migration_reports_aggregation_id_collisions() {
    let db = fixtures::sqlite_connection_migrated(Some(ownership_migration_index() as u32)).await;
    assert_ownership_collision_fails_before_schema_changes(db, "SQLite").await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_ownership_migration_backfills_mixed_data() {
    let test_db =
        mysql_helpers::MysqlTestDb::start_migrated(Some(ownership_migration_index() as u32)).await;
    assert_ownership_migration_backfills_mixed_data(test_db.connection().await, "MySQL").await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_ownership_migration_reports_aggregation_id_collisions() {
    let test_db =
        mysql_helpers::MysqlTestDb::start_migrated(Some(ownership_migration_index() as u32)).await;
    assert_ownership_collision_fails_before_schema_changes(test_db.connection().await, "MySQL")
        .await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_ownership_migration_backfills_mixed_data() {
    let test_db =
        postgres_helpers::postgres_connection_migrated(Some(ownership_migration_index() as u32))
            .await;
    assert_ownership_migration_backfills_mixed_data(test_db.db.clone(), "Postgres").await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_ownership_migration_reports_aggregation_id_collisions() {
    let test_db =
        postgres_helpers::postgres_connection_migrated(Some(ownership_migration_index() as u32))
            .await;
    assert_ownership_collision_fails_before_schema_changes(test_db.db.clone(), "Postgres").await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_every_migration_reruns_after_a_rollback() {
    assert_every_migration_reruns_after_a_rollback(fixtures::sqlite_connection().await, "SQLite")
        .await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_every_migration_reruns_after_a_rollback() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_every_migration_reruns_after_a_rollback(test_db.connection().await, "MySQL").await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_every_migration_reruns_after_a_rollback() {
    let test_db = postgres_helpers::postgres_connection().await;
    assert_every_migration_reruns_after_a_rollback(test_db.db.clone(), "Postgres").await;
}

/// The previous release refuses a database a newer one migrated, naming each
/// migration it does not know, and starts once their records are deleted. That
/// is the migrator's half of the rollback recovery; whether the previous release
/// then runs correctly on the newer schema is not covered by any test.
async fn assert_previous_release_starts_once_unknown_records_are_deleted(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    const KNOWN: usize = PREDATE_RERUN_RULE.len();
    let migrations = Migrator::migrations();
    let unknown: Vec<&str> = migrations[KNOWN..].iter().map(|m| m.name()).collect();

    let message = apply_migrations::<PreviousRelease<KNOWN>>(&db)
        .await
        .expect_err(&format!(
            "the previous release must refuse the newer schema on {backend}"
        ))
        .to_string();
    for version in &unknown {
        assert!(
            message.contains(version),
            "the startup error must name {version} on {backend}: {message}"
        );
    }
    assert!(
        message.contains("docs/deployment-runbook.md"),
        "the startup error must name the runbook on {backend}: {message}"
    );

    fixtures::forget_migrations(&db, &unknown).await;
    let fresh = apply_migrations::<PreviousRelease<KNOWN>>(&db)
        .await
        .unwrap_or_else(|e| {
            panic!("the previous release must start once the records are deleted on {backend}: {e}")
        });
    assert!(!fresh, "a migrated database is not fresh on {backend}");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_previous_release_starts_once_unknown_records_are_deleted() {
    assert_previous_release_starts_once_unknown_records_are_deleted(
        fixtures::sqlite_connection().await,
        "SQLite",
    )
    .await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_previous_release_starts_once_unknown_records_are_deleted() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_previous_release_starts_once_unknown_records_are_deleted(
        test_db.connection().await,
        "MySQL",
    )
    .await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_previous_release_starts_once_unknown_records_are_deleted() {
    let test_db = postgres_helpers::postgres_connection().await;
    assert_previous_release_starts_once_unknown_records_are_deleted(test_db.db.clone(), "Postgres")
        .await;
}
