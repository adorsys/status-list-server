//! Migrations only move forward: `down`, `reset`, `refresh` and `fresh` are
//! refused, and rolling back relies on every migration re-running once its
//! record is deleted. See `docs/adr/0003-schema-migrations-are-forward-only.md`.
#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

use std::sync::Arc;

use sea_orm::{DatabaseConnection, DbErr};
use sea_orm_migration::{MigrationTrait, MigratorTrait, SchemaManager};

use super::fixtures;
use crate::outbound::sql::Migrator;
use crate::outbound::sql::migrations::apply_migrations;

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
    fixtures::insert_list_as_old_pod(&db, "list-rerun", "issuer-rerun").await;

    for first in PREDATE_RERUN_RULE.len()..names.len() {
        fixtures::forget_migrations(&db, &names[first..]).await;
        Migrator::up(db.as_ref(), None).await.unwrap_or_else(|e| {
            panic!(
                "upgrading again after a rollback to before {} on {backend}: {e}",
                names[first]
            )
        });
        // The list went in uncounted. The first re-run's recount must count it,
        // and no later re-run may lose it.
        assert_eq!(
            fixtures::list_count(&db, "issuer-rerun").await,
            1,
            "list_count must match the issuer's lists after a rollback to before {} on {backend}",
            names[first]
        );
    }
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
/// then runs correctly on the newer schema is rule 1, which no test covers.
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
