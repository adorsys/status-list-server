//! The list quota gate: a fresh database enforces from the first start, an
//! upgraded one needs the transition, and `enable` checks every issuer.
#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

use std::sync::Arc;

use sea_orm::DatabaseConnection;

use super::fixtures;
use crate::outbound::sql::list_quota::{self, IssuerCount, ListQuotaError, StartupState};
use crate::outbound::sql::models::StatusListRecord;
use crate::outbound::sql::{RepositoryError, SeaOrmStore};

#[cfg(feature = "mysql")]
use crate::outbound::sql::test_containers::mysql_helpers;
#[cfg(feature = "postgres-tests")]
use crate::outbound::sql::test_containers::postgres_helpers;

/// Generates one test per backend for an `assert_*` scenario.
macro_rules! on_every_backend {
    ($scenario:ident: $sqlite:ident, $mysql:ident, $postgres:ident) => {
        #[cfg(feature = "sqlite")]
        #[tokio::test]
        async fn $sqlite() {
            $scenario(fixtures::sqlite_connection().await, "SQLite").await;
        }

        #[cfg(feature = "mysql")]
        #[tokio::test]
        async fn $mysql() {
            let test_db = mysql_helpers::MysqlTestDb::start().await;
            $scenario(test_db.connection().await, "MySQL").await;
        }

        #[cfg(feature = "postgres-tests")]
        #[tokio::test]
        async fn $postgres() {
            let test_db = postgres_helpers::postgres_connection().await;
            $scenario(test_db.db.clone(), "Postgres").await;
        }
    };
}

async fn publish(
    store: &SeaOrmStore<StatusListRecord>,
    list_id: &str,
    issuer: &str,
    max: u64,
) -> Result<(), RepositoryError> {
    let record = fixtures::record(list_id, issuer, "initial", &format!("sub-{list_id}"), 0);
    store.insert_one(record, max).await
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_run_migrations_reports_whether_the_database_was_fresh() {
    use crate::outbound::sql::run_migrations;

    let empty = fixtures::sqlite_connection_migrated(Some(0)).await;
    assert!(
        run_migrations(&empty).await.unwrap(),
        "an empty database is fresh"
    );
    assert!(
        !run_migrations(&empty).await.unwrap(),
        "a restart on the same database is not"
    );

    let steps = super::status_list::list_count_migration_index() as u32;
    let upgraded = fixtures::sqlite_connection_migrated(Some(steps)).await;
    assert!(
        !run_migrations(&upgraded).await.unwrap(),
        "a database a release without the quota migrated is not fresh"
    );
    assert!(!list_quota::is_enforced(&upgraded).await.unwrap());
}

async fn assert_fresh_database_enforces_from_first_start(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    let state = list_quota::on_startup(&db, true, false, 2)
        .await
        .unwrap_or_else(|e| panic!("a fresh database must start on {backend}: {e}"));
    assert_eq!(state, StartupState::Enforced, "on {backend}");

    fixtures::seed_credential(&db, "issuer").await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    for n in 1..=2 {
        publish(&store, &format!("list-{n}"), "issuer", 2)
            .await
            .unwrap();
    }
    let refused = publish(&store, "list-3", "issuer", 2).await;
    assert!(
        matches!(
            refused,
            Err(RepositoryError::QuotaExceeded { count: 2, max: 2 })
        ),
        "a fresh install must refuse the publish past the cap on {backend}, got {refused:?}"
    );
}

on_every_backend!(assert_fresh_database_enforces_from_first_start:
    test_sqlite_fresh_database_enforces_from_first_start,
    test_mysql_fresh_database_enforces_from_first_start,
    test_postgres_fresh_database_enforces_from_first_start);

async fn assert_upgrade_refuses_to_start_without_transition(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    let refused = list_quota::on_startup(&db, false, false, 2).await;
    let message = match refused {
        Err(err @ ListQuotaError::NotEnforced) => err.to_string(),
        other => panic!("an upgrade without the transition must not start on {backend}: {other:?}"),
    };
    assert!(
        message.contains("APP_LIMITS__LIST_QUOTA_TRANSITION=true")
            && message.contains("list-quota enable"),
        "the refusal must say how to proceed on {backend}: {message}"
    );
    assert!(!list_quota::is_enforced(&db).await.unwrap(), "on {backend}");
}

on_every_backend!(assert_upgrade_refuses_to_start_without_transition:
    test_sqlite_upgrade_refuses_to_start_without_transition,
    test_mysql_upgrade_refuses_to_start_without_transition,
    test_postgres_upgrade_refuses_to_start_without_transition);

async fn assert_upgrade_with_transition_counts_until_enabled(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    let state = list_quota::on_startup(&db, false, true, 10).await.unwrap();
    assert_eq!(state, StartupState::Transition, "on {backend}");

    fixtures::seed_credential(&db, "issuer").await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    for n in 1..=3 {
        publish(&store, &format!("list-{n}"), "issuer", 2)
            .await
            .unwrap_or_else(|e| panic!("the transition must not refuse on {backend}: {e:?}"));
    }
    assert_eq!(fixtures::list_count(&db, "issuer").await, 3, "on {backend}");

    list_quota::enable(&db, 10).await.unwrap();
    assert_eq!(
        list_quota::on_startup(&db, false, true, 10).await.unwrap(),
        StartupState::EnforcedWithTransitionSet,
        "on {backend}"
    );
    assert_eq!(
        list_quota::on_startup(&db, false, false, 10).await.unwrap(),
        StartupState::Enforced,
        "on {backend}"
    );
}

on_every_backend!(assert_upgrade_with_transition_counts_until_enabled:
    test_sqlite_upgrade_with_transition_counts_until_enabled,
    test_mysql_upgrade_with_transition_counts_until_enabled,
    test_postgres_upgrade_with_transition_counts_until_enabled);

async fn assert_enable_succeeds_within_cap(db: Arc<DatabaseConnection>, backend: &str) {
    fixtures::seed_credential(&db, "issuer-full").await;
    fixtures::seed_credential(&db, "issuer-with-room").await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    for n in 1..=2 {
        publish(&store, &format!("full-{n}"), "issuer-full", 2)
            .await
            .unwrap();
    }

    list_quota::enable(&db, 2)
        .await
        .unwrap_or_else(|e| panic!("enable must succeed within the cap on {backend}: {e}"));
    assert!(list_quota::is_enforced(&db).await.unwrap(), "on {backend}");

    let refused = publish(&store, "full-3", "issuer-full", 2).await;
    assert!(
        matches!(
            refused,
            Err(RepositoryError::QuotaExceeded { count: 2, max: 2 })
        ),
        "an enforced quota must refuse on {backend}, got {refused:?}"
    );
    publish(&store, "room-1", "issuer-with-room", 2)
        .await
        .unwrap_or_else(|e| panic!("another issuer keeps its room on {backend}: {e:?}"));
}

on_every_backend!(assert_enable_succeeds_within_cap:
    test_sqlite_enable_succeeds_within_cap,
    test_mysql_enable_succeeds_within_cap,
    test_postgres_enable_succeeds_within_cap);

/// A pre-quota pod pushed the issuer past the cap during the rollout.
async fn assert_enable_refuses_and_names_over_cap_issuer(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    fixtures::seed_credential(&db, "issuer-over").await;
    fixtures::seed_credential(&db, "issuer-within").await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    for n in 1..=2 {
        publish(&store, &format!("over-{n}"), "issuer-over", 2)
            .await
            .unwrap();
    }
    publish(&store, "within-1", "issuer-within", 2)
        .await
        .unwrap();
    fixtures::insert_list_as_old_pod(&db, "over-old", "issuer-over").await;
    list_quota::recount(&db).await.unwrap();

    let err = list_quota::enable(&db, 2).await.expect_err(&format!(
        "enable must refuse an issuer over the cap on {backend}"
    ));
    let message = err.to_string();
    match err {
        ListQuotaError::Refused {
            max,
            over_quota,
            miscounted,
        } => {
            assert_eq!(max, 2, "on {backend}");
            assert_eq!(
                over_quota,
                [IssuerCount {
                    issuer: "issuer-over".to_string(),
                    list_count: 3,
                    actual: 3,
                }],
                "on {backend}"
            );
            assert!(miscounted.is_empty(), "on {backend}: {miscounted:?}");
        }
        other => panic!("expected Refused on {backend}, got {other:?}"),
    }
    assert!(
        message.contains("issuer-over (3 lists)") && !message.contains("issuer-within"),
        "the refusal must name the issuer over the cap, and only it, on {backend}: {message}"
    );
    assert!(
        !list_quota::is_enforced(&db).await.unwrap(),
        "a refused enable must leave the quota off on {backend}"
    );
}

on_every_backend!(assert_enable_refuses_and_names_over_cap_issuer:
    test_sqlite_enable_refuses_and_names_over_cap_issuer,
    test_mysql_enable_refuses_and_names_over_cap_issuer,
    test_postgres_enable_refuses_and_names_over_cap_issuer);

/// The recount was skipped, so a pre-quota pod's list is not counted.
async fn assert_enable_refuses_stale_count_until_recount(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    fixtures::seed_credential(&db, "issuer-stale").await;
    fixtures::insert_list_as_old_pod(&db, "stale-old", "issuer-stale").await;

    let err = list_quota::enable(&db, 10)
        .await
        .expect_err(&format!("enable must refuse a stale count on {backend}"));
    let message = err.to_string();
    match err {
        ListQuotaError::Refused {
            over_quota,
            miscounted,
            ..
        } => {
            assert!(over_quota.is_empty(), "on {backend}: {over_quota:?}");
            assert_eq!(
                miscounted,
                [IssuerCount {
                    issuer: "issuer-stale".to_string(),
                    list_count: 0,
                    actual: 1,
                }],
                "on {backend}"
            );
        }
        other => panic!("expected Refused on {backend}, got {other:?}"),
    }
    assert!(
        message.contains("issuer-stale") && message.contains("list-quota recount"),
        "the refusal must name the issuer and the fix on {backend}: {message}"
    );
    assert!(!list_quota::is_enforced(&db).await.unwrap(), "on {backend}");

    list_quota::recount(&db).await.unwrap();
    list_quota::enable(&db, 10)
        .await
        .unwrap_or_else(|e| panic!("enable must succeed after the recount on {backend}: {e}"));
}

on_every_backend!(assert_enable_refuses_stale_count_until_recount:
    test_sqlite_enable_refuses_stale_count_until_recount,
    test_mysql_enable_refuses_stale_count_until_recount,
    test_postgres_enable_refuses_stale_count_until_recount);

async fn assert_recount_is_refused_while_enforced(db: Arc<DatabaseConnection>, backend: &str) {
    list_quota::enable(&db, 10).await.unwrap();

    let refused = list_quota::recount(&db).await;
    assert!(
        matches!(refused, Err(ListQuotaError::Enforced)),
        "recount must be refused while enforced on {backend}, got {refused:?}"
    );

    list_quota::disable(&db).await.unwrap();
    assert!(!list_quota::is_enforced(&db).await.unwrap(), "on {backend}");
    list_quota::recount(&db)
        .await
        .unwrap_or_else(|e| panic!("recount must run once disabled on {backend}: {e}"));
}

on_every_backend!(assert_recount_is_refused_while_enforced:
    test_sqlite_recount_is_refused_while_enforced,
    test_mysql_recount_is_refused_while_enforced,
    test_postgres_recount_is_refused_while_enforced);
