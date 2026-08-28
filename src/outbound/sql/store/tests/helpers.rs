use jsonwebtoken::jwk::Jwk;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

#[cfg(feature = "sqlite")]
use sea_orm_migration::MigratorTrait;

use super::super::super::error::RepositoryError;
use super::super::super::models::{
    Credentials, StatusList, StatusListHistoryRecord, StatusListRecord,
};
use super::super::SeaOrmStore;

pub(super) fn sample_jwk() -> Jwk {
    serde_json::from_str(
        r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
            "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
        }"#,
    )
    .unwrap()
}

#[cfg(feature = "sqlite")]
pub(super) async fn sqlite_connection() -> Arc<DatabaseConnection> {
    let mut opt = sea_orm::ConnectOptions::new("sqlite::memory:");
    opt.max_connections(1);
    opt.map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
    let db = sea_orm::Database::connect(opt)
        .await
        .expect("Failed to connect to SQLite");
    super::super::super::Migrator::up(&db, None)
        .await
        .expect("Failed to run migrations on SQLite");
    Arc::new(db)
}

/// Helper for testing credentials insert, find, delete round-trip across backends.
#[cfg(any(feature = "sqlite", feature = "mysql"))]
pub(super) async fn assert_credentials_round_trip(db: Arc<DatabaseConnection>, issuer: &str) {
    let store = SeaOrmStore::<Credentials>::new(db);
    let public_key = sample_jwk();
    let entity = Credentials::new(issuer.to_string(), public_key.clone());

    store.insert_one(entity.clone()).await.unwrap();

    let found = store.find_one_by(issuer).await.unwrap().unwrap();
    assert_eq!(found.issuer, issuer);
    assert_eq!(found.public_key, public_key);

    let deleted = store.delete_by(issuer).await.unwrap();
    assert!(deleted);

    let gone = store.find_one_by(issuer).await.unwrap();
    assert!(gone.is_none());
}

/// Helper for testing duplicate insert error mapping across backends.
#[cfg(any(feature = "sqlite", feature = "mysql"))]
pub(super) async fn assert_duplicate_insert_maps_to_duplicate_entry(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    list_id: &str,
) {
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db);

    let key = sample_jwk();
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key.clone()))
        .await
        .unwrap();

    // Duplicate credential (same issuer primary key).
    let dup_cred = cred_store
        .insert_one(Credentials::new(issuer.to_string(), key))
        .await;
    assert!(
        matches!(dup_cred, Err(RepositoryError::DuplicateEntry)),
        "duplicate credential insert must map to DuplicateEntry, got {dup_cred:?}"
    );

    // Duplicate status list (same list_id primary key).
    let record = StatusListRecord {
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "initial".to_string(),
        },
        sub: format!("sub-{list_id}"),
        updated_at: 0,
    };
    store.insert_one(record.clone()).await.unwrap();
    let dup_list = store.insert_one(record).await;
    assert!(
        matches!(dup_list, Err(RepositoryError::DuplicateEntry)),
        "duplicate status list insert must map to DuplicateEntry, got {dup_list:?}"
    );
}

/// Helper for testing optimistic concurrency guard rejecting stale writes across backends.
#[cfg(any(feature = "sqlite", feature = "mysql"))]
pub(super) async fn assert_update_one_optimistic_guard_rejects_stale_write(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    list_id: &str,
) {
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db);

    let key = sample_jwk();
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key))
        .await
        .unwrap();

    let v = 1000;
    let base = StatusListRecord {
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "initial".to_string(),
        },
        sub: format!("sub-{list_id}"),
        updated_at: v,
    };
    store.insert_one(base.clone()).await.unwrap();

    let writer_a = StatusListRecord {
        status_list: StatusList {
            bits: 1,
            lst: "flip-A".to_string(),
        },
        updated_at: v + 1,
        ..base.clone()
    };
    let writer_b = StatusListRecord {
        status_list: StatusList {
            bits: 1,
            lst: "flip-B".to_string(),
        },
        updated_at: v + 1,
        ..base.clone()
    };

    let a_won = store.update_one(&base.list_id, writer_a, v).await.unwrap();
    assert!(a_won, "first guarded write should land");

    let b_won = store.update_one(&base.list_id, writer_b, v).await.unwrap();
    assert!(!b_won, "stale guarded write must be rejected");

    let stored = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(stored.status_list.lst, "flip-A");
    assert_eq!(stored.updated_at, v + 1);
}

/// Helper for testing snapshot rollback on history failure across MySQL and Postgres.
#[cfg(any(feature = "mysql", feature = "postgres-tests"))]
pub(super) async fn assert_update_with_snapshot_rolls_back_on_history_failure(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    list_id: &str,
    snap_id: &str,
    backend_name: &str,
) {
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let key = sample_jwk();
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key))
        .await
        .unwrap();

    let v = 1000;
    let base = StatusListRecord {
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "initial".to_string(),
        },
        sub: format!("sub-{list_id}"),
        updated_at: v,
    };
    store.insert_one(base.clone()).await.unwrap();

    store
        .update_one_with_snapshot(
            &base.list_id,
            StatusListRecord {
                status_list: StatusList {
                    bits: 1,
                    lst: "flip-1".to_string(),
                },
                updated_at: v + 1,
                ..base.clone()
            },
            v,
            StatusListHistoryRecord {
                snapshot_id: snap_id.to_string(),
                list_id: base.list_id.clone(),
                issuer: issuer.to_string(),
                status_list: StatusList {
                    bits: 1,
                    lst: "flip-1".to_string(),
                },
                sub: base.sub.clone(),
                iat: v + 1,
                exp: v + 1 + 900,
            },
        )
        .await
        .unwrap();

    let snapshot = history
        .find_valid_at(&base.list_id, v + 1)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("the committed {backend_name} snapshot must be resolvable"));
    assert_eq!(
        snapshot.status_list.lst, "flip-1",
        "{backend_name} must round-trip the snapshot JSON"
    );

    let result = store
        .update_one_with_snapshot(
            &base.list_id,
            StatusListRecord {
                status_list: StatusList {
                    bits: 1,
                    lst: "flip-2".to_string(),
                },
                updated_at: v + 2,
                ..base.clone()
            },
            v + 1,
            StatusListHistoryRecord {
                snapshot_id: snap_id.to_string(), // duplicate PK
                list_id: base.list_id.clone(),
                issuer: issuer.to_string(),
                status_list: StatusList {
                    bits: 1,
                    lst: "flip-2".to_string(),
                },
                sub: base.sub.clone(),
                iat: v + 2,
                exp: v + 2 + 900,
            },
        )
        .await;
    assert!(result.is_err(), "duplicate snapshot PK must fail the unit");

    let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(
        row.updated_at,
        v + 1,
        "{backend_name} must roll the row update back when the snapshot insert fails"
    );
    assert_eq!(
        row.status_list.lst, "flip-1",
        "the rolled-back row must retain its previously committed content"
    );
}

/// Publishes `list_id` once, then republishes it with a *different*
/// `snapshot_id`, and asserts the failure is the duplicate `list_id`
/// classified as `DuplicateEntry`.
#[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
pub(super) async fn assert_duplicate_list_id_is_conflict(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    list_id: &str,
    backend: &str,
) {
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let key = sample_jwk();
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key))
        .await
        .unwrap();

    let record = |updated_at: i64| StatusListRecord {
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "initial".to_string(),
        },
        sub: format!("sub-{list_id}"),
        updated_at,
    };
    let snapshot = |snapshot_id: &str, iat: i64| StatusListHistoryRecord {
        snapshot_id: snapshot_id.to_string(),
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "initial".to_string(),
        },
        sub: format!("sub-{list_id}"),
        iat,
        exp: iat + 900,
    };

    store
        .insert_one_with_snapshot(record(1000), snapshot("snap-first", 1000))
        .await
        .unwrap();

    let dup = store
        .insert_one_with_snapshot(record(2000), snapshot("snap-second", 2000))
        .await;
    assert!(
        matches!(dup, Err(RepositoryError::DuplicateEntry)),
        "duplicate list_id inside a transaction must map to DuplicateEntry on {backend}, got {dup:?}"
    );

    assert!(
        history
            .find_valid_at(list_id, 2000)
            .await
            .unwrap()
            .is_none(),
        "the rejected publish must not leave a snapshot behind on {backend}"
    );

    let first = history
        .find_valid_at(list_id, 1000)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("the first publish's snapshot must survive on {backend}"));
    assert_eq!(first.snapshot_id, "snap-first");

    let row = store
        .find_one_by(list_id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("the committed row must survive on {backend}"));
    assert_eq!(
        row.updated_at, 1000,
        "the rejected publish must not overwrite the committed row on {backend}"
    );

    let plain = store.insert_one(record(3000)).await;
    assert!(
        matches!(plain, Err(RepositoryError::DuplicateEntry)),
        "duplicate list_id on the snapshot-disabled publish path must also map to DuplicateEntry on {backend}, got {plain:?}"
    );
}
