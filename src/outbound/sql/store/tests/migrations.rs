//! Migrations only move forward: `down` is refused, and rolling back relies on
//! every migration re-running once its record is deleted. See
//! `docs/adr/0003-schema-migrations-are-forward-only.md`.
#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

use std::sync::Arc;

use sea_orm::DatabaseConnection;
use sea_orm_migration::{MigratorTrait, SchemaManager};

use super::fixtures;
use crate::outbound::sql::Migrator;

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

/// `down` to zero fails on the newest migration with every record kept, and
/// each migration's own `down` is refused too.
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
        assert!(
            migration.down(&manager).await.is_err(),
            "{} must refuse down on {backend}",
            migration.name()
        );
    }

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
