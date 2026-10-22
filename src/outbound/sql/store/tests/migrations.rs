#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

use std::sync::Arc;

use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr, Statement};
use sea_orm_migration::{MigrationTrait, MigratorTrait, SchemaManager};

use super::fixtures;
use crate::outbound::sql::Migrator;
use crate::outbound::sql::list_quota;
use crate::outbound::sql::migrations::apply_migrations;

#[cfg(feature = "mysql")]
use crate::outbound::sql::test_containers::mysql_helpers;
#[cfg(feature = "postgres-tests")]
use crate::outbound::sql::test_containers::postgres_helpers;

const PREDATE_RERUN_RULE: [&str; 4] = [
    "mod",
    "add_updated_at",
    "m20250101_000003_status_list_history",
    "m20260727_000001_status_list_history_exp_index",
];

struct PreviousRelease<const N: usize>;

#[async_trait::async_trait]
impl<const N: usize> MigratorTrait for PreviousRelease<N> {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        let mut migrations = Migrator::migrations();
        migrations.truncate(N);
        migrations
    }
}

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
            list_quota::is_enforced(&db).await.unwrap(),
            enforced,
            "a re-run must keep the quota switch after a rollback to before {} on {backend}",
            names[first]
        );
        fixtures::enforce_list_quota(&db).await;
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
