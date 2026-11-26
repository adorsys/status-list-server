#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

use std::{collections::HashMap, sync::Arc};

use crate::domain::models::tier::{IssuerTier, Tiers};

use sea_orm::{ConnectionTrait, DatabaseConnection};

use super::fixtures;
use crate::outbound::sql::list_quota::{self, IssuerCount, ListQuotaError, StartupState};
use crate::outbound::sql::models::{StatusListHistoryRecord, StatusListRecord};
use crate::outbound::sql::{RepositoryError, SeaOrmStore};

#[cfg(feature = "mysql")]
use crate::outbound::sql::test_containers::mysql_helpers;
#[cfg(feature = "postgres-tests")]
use crate::outbound::sql::test_containers::postgres_helpers;

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

fn retirement_tiers(standard: u64, sandbox: u64) -> Tiers {
    let mut tiers = crate::test_utils::test_tiers();
    tiers.standard.max_lists = standard;
    tiers.sandbox.max_lists = sandbox;
    tiers
}

fn standard_registry() -> HashMap<String, IssuerTier> {
    HashMap::from([("issuer".to_string(), IssuerTier::Standard)])
}

fn sandbox_registry() -> HashMap<String, IssuerTier> {
    HashMap::from([("issuer".to_string(), IssuerTier::Sandbox)])
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

async fn seed_retirement_lists(db: &Arc<DatabaseConnection>) {
    fixtures::seed_credential(db, "issuer").await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    store
        .insert_one_with_snapshot(
            fixtures::record("first", "issuer", "initial", "sub-first", 10),
            fixtures::snapshot(
                "first-snapshot",
                "first",
                "issuer",
                "initial",
                "sub-first",
                10,
                20,
            ),
            2,
        )
        .await
        .unwrap();
    publish(&store, "second", "issuer", 2).await.unwrap();
    fixtures::insert_list_as_old_pod(db, "third", "issuer").await;
    list_quota::recount(db).await.unwrap();
}

async fn assert_retirement_releases_quota_without_losing_reads(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    seed_retirement_lists(&db).await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let history = SeaOrmStore::<StatusListHistoryRecord>::new(db.clone());
    assert!(matches!(
        list_quota::enable(&db, 2).await,
        Err(ListQuotaError::Refused { .. })
    ));

    assert!(matches!(
        list_quota::set_retired(
            &db,
            &["first".into(), "missing".into()],
            true,
            &retirement_tiers(2, 2),
            &standard_registry()
        )
        .await,
        Err(ListQuotaError::ListNotFound(_))
    ));
    assert_eq!(fixtures::list_count(&db, "issuer").await, 3, "on {backend}");
    assert!(
        !store
            .find_one_by("first")
            .await
            .unwrap()
            .unwrap()
            .retired_at
            .is_some()
    );

    list_quota::set_retired(
        &db,
        &["first".into()],
        true,
        &retirement_tiers(2, 2),
        &standard_registry(),
    )
    .await
    .unwrap();
    assert_eq!(fixtures::list_count(&db, "issuer").await, 2, "on {backend}");
    assert_eq!(
        store.count_status_lists_by_issuer("issuer").await.unwrap(),
        2
    );
    assert!(store.find_one_by("first").await.unwrap().is_some());
    assert!(history.find_valid_at("first", 15).await.unwrap().is_some());
    let uris = store
        .find_status_list_uris_after(Some("issuer"), None, 10)
        .await
        .unwrap();
    assert_eq!(uris.len(), 2, "on {backend}");
    assert!(!uris.iter().any(|(id, _)| id == "first"));
    let mut updated = store.find_one_by("first").await.unwrap().unwrap();
    updated.version += 1;
    assert!(matches!(
        store.update_one("first", updated, 1).await,
        Err(RepositoryError::Retired)
    ));
    assert!(matches!(
        store.allocate_indices("first", "issuer", 1).await,
        Err(RepositoryError::Retired)
    ));
    assert!(matches!(
        store.allocate_indices("first", "another-issuer", 1).await,
        Err(RepositoryError::IssuerMismatch)
    ));
}

on_every_backend!(assert_retirement_releases_quota_without_losing_reads:
    test_sqlite_retirement_releases_quota_without_losing_reads,
    test_mysql_retirement_releases_quota_without_losing_reads,
    test_postgres_retirement_releases_quota_without_losing_reads);

async fn assert_unretire_obeys_quota(db: Arc<DatabaseConnection>, backend: &str) {
    seed_retirement_lists(&db).await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    list_quota::set_retired(
        &db,
        &["first".into()],
        true,
        &retirement_tiers(2, 2),
        &standard_registry(),
    )
    .await
    .unwrap();
    list_quota::recount(&db).await.unwrap();
    assert_eq!(fixtures::list_count(&db, "issuer").await, 2, "on {backend}");
    list_quota::enable(&db, 2).await.unwrap();
    assert!(matches!(
        list_quota::set_retired(
            &db,
            &["first".into()],
            false,
            &retirement_tiers(2, 2),
            &standard_registry()
        )
        .await,
        Err(ListQuotaError::UnretireOverQuota { .. })
    ));
    list_quota::set_retired(
        &db,
        &["second".into()],
        true,
        &retirement_tiers(2, 2),
        &standard_registry(),
    )
    .await
    .unwrap();
    list_quota::set_retired(
        &db,
        &["first".into()],
        false,
        &retirement_tiers(2, 2),
        &standard_registry(),
    )
    .await
    .unwrap();
    assert_eq!(fixtures::list_count(&db, "issuer").await, 2, "on {backend}");
    assert!(
        store
            .find_status_list_uris_after(Some("issuer"), None, 10)
            .await
            .unwrap()
            .iter()
            .any(|(id, _)| id == "first")
    );

    db.execute_unprepared("UPDATE issuers SET tier = 'sandbox' WHERE issuer = 'issuer'")
        .await
        .unwrap();
    assert!(matches!(
        list_quota::set_retired(
            &db,
            &["second".into()],
            false,
            &retirement_tiers(3, 2),
            &sandbox_registry()
        )
        .await,
        Err(ListQuotaError::UnretireOverQuota { max: 2, .. })
    ));
}

on_every_backend!(assert_unretire_obeys_quota:
    test_sqlite_unretire_obeys_quota,
    test_mysql_unretire_obeys_quota,
    test_postgres_unretire_obeys_quota);

async fn assert_retirement_is_atomic_and_uses_registry_tier(
    db: Arc<DatabaseConnection>,
    backend: &str,
) {
    fixtures::seed_credential(&db, "issuer").await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    publish(&store, "first", "issuer", 2).await.unwrap();
    publish(&store, "second", "issuer", 2).await.unwrap();
    let tiers = retirement_tiers(2, 1);
    let registry = sandbox_registry();

    let changes = list_quota::set_retired(
        &db,
        &["first".into(), "first".into()],
        true,
        &tiers,
        &registry,
    )
    .await
    .unwrap();
    assert_eq!(
        changes.len(),
        1,
        "duplicate IDs are processed once on {backend}"
    );
    assert_eq!(changes[0].active_count, 1);
    assert!(
        store
            .find_one_by("first")
            .await
            .unwrap()
            .unwrap()
            .retired_at
            .is_some()
    );
    assert!(
        store
            .find_status_list_issuers()
            .await
            .unwrap()
            .contains(&"issuer".to_string())
    );

    assert!(matches!(
        list_quota::set_retired(&db, &["first".into()], true, &tiers, &registry).await,
        Err(ListQuotaError::AlreadyRetired(_))
    ));
    assert!(matches!(
        list_quota::set_retired(&db, &["second".into()], false, &tiers, &registry).await,
        Err(ListQuotaError::NotRetired(_))
    ));
    assert_eq!(fixtures::list_count(&db, "issuer").await, 1);

    // Simulate an older pod leaving list_count stale while enforcement is off.
    db.execute_unprepared("UPDATE issuers SET list_count = 0 WHERE issuer = 'issuer'")
        .await
        .unwrap();
    assert!(matches!(
        list_quota::set_retired(&db, &["first".into()], false, &tiers, &registry).await,
        Err(ListQuotaError::UnretireOverQuota {
            max: 1,
            count: 1,
            ..
        })
    ));
    assert!(matches!(
        list_quota::set_retired(&db, &["first".into()], false, &tiers, &HashMap::new()).await,
        Err(ListQuotaError::UnretireOverQuota { max: 1, .. })
    ));
    assert!(
        store
            .find_one_by("first")
            .await
            .unwrap()
            .unwrap()
            .retired_at
            .is_some()
    );

    let status = list_quota::issuer_status(&db).await.unwrap();
    let issuer = status.iter().find(|row| row.issuer == "issuer").unwrap();
    assert_eq!((issuer.active, issuer.retired), (1, 1));
    list_quota::set_retired(&db, &["second".into()], true, &tiers, &registry)
        .await
        .unwrap();
    assert!(
        store
            .find_status_list_issuers()
            .await
            .unwrap()
            .contains(&"issuer".to_string())
    );
}

on_every_backend!(assert_retirement_is_atomic_and_uses_registry_tier:
    test_sqlite_retirement_is_atomic_and_uses_registry_tier,
    test_mysql_retirement_is_atomic_and_uses_registry_tier,
    test_postgres_retirement_is_atomic_and_uses_registry_tier);

async fn assert_retirement_races_with_update(db: Arc<DatabaseConnection>, backend: &str) {
    fixtures::seed_credential(&db, "issuer").await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    publish(&store, "race", "issuer", 2).await.unwrap();
    let mut update = store.find_one_by("race").await.unwrap().unwrap();
    update.status_list.lst = "updated".into();
    update.version += 1;
    let previous_version = update.version - 1;
    let tiers = retirement_tiers(2, 1);
    let registry = standard_registry();
    let list_ids = ["race".into()];

    let (retire, write) = tokio::join!(
        list_quota::set_retired(&db, &list_ids, true, &tiers, &registry),
        store.update_one("race", update.clone(), previous_version),
    );
    retire.unwrap_or_else(|error| panic!("retire failed on {backend}: {error}"));
    assert!(
        matches!(&write, Ok(true) | Err(RepositoryError::Retired)),
        "the racing write has a serial result on {backend}: {write:?}"
    );
    let final_record = store.find_one_by("race").await.unwrap().unwrap();
    assert!(final_record.retired_at.is_some());
    assert_eq!(fixtures::list_count(&db, "issuer").await, 0);
    assert!(matches!(
        store.update_one("race", update, previous_version).await,
        Err(RepositoryError::Retired)
    ));
}

on_every_backend!(assert_retirement_races_with_update:
    test_sqlite_retirement_races_with_update,
    test_mysql_retirement_races_with_update,
    test_postgres_retirement_races_with_update);

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
