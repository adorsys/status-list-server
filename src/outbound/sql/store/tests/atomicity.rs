use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Statement, Transaction};
use std::sync::Arc;

use super::super::super::error::RepositoryError;
use super::super::super::models::{
    Credentials, StatusList, StatusListHistoryRecord, StatusListRecord,
};
use super::super::SeaOrmStore;
use super::helpers::{assert_duplicate_list_id_is_conflict, sample_jwk};

#[cfg(any(feature = "mysql", feature = "postgres-tests"))]
use super::helpers::assert_update_with_snapshot_rolls_back_on_history_failure;

#[cfg(feature = "sqlite")]
use super::helpers::sqlite_connection;

#[cfg(feature = "mysql")]
use crate::outbound::sql::test_containers::mysql_helpers;
#[cfg(feature = "postgres-tests")]
use crate::outbound::sql::test_containers::postgres_helpers;

#[tokio::test]
async fn test_update_one_with_snapshot_transaction_log_shape() {
    let entity = StatusListRecord {
        list_id: "list-txn".to_string(),
        issuer: "issuer-txn".to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "flip".to_string(),
        },
        sub: "sub-txn".to_string(),
        updated_at: 1001,
    };
    let snapshot = StatusListHistoryRecord {
        snapshot_id: "snap-txn".to_string(),
        list_id: entity.list_id.clone(),
        issuer: entity.issuer.clone(),
        status_list: entity.status_list.clone(),
        sub: entity.sub.clone(),
        iat: entity.updated_at,
        exp: entity.updated_at + 900,
    };

    let db_conn = Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([
                MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                },
                MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                },
            ])
            .into_connection(),
    );
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn.clone());

    assert!(
        store
            .update_one_with_snapshot("list-txn", entity.clone(), 1000, snapshot.clone())
            .await
            .unwrap()
    );

    drop(store);
    let db_conn = Arc::try_unwrap(db_conn).expect("test should own the only DB handle");
    assert_eq!(
        db_conn.into_transaction_log(),
        [Transaction::many([
            Statement::from_string(DatabaseBackend::Postgres, "BEGIN"),
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "status_lists" SET "issuer" = $1, "status_list" = $2, "sub" = $3, "updated_at" = $4 WHERE "status_lists"."list_id" = $5 AND "status_lists"."updated_at" = $6"#,
                [
                    entity.issuer.clone().into(),
                    serde_json::to_value(entity.status_list.clone())
                        .unwrap()
                        .into(),
                    entity.sub.clone().into(),
                    entity.updated_at.into(),
                    "list-txn".into(),
                    1000i64.into(),
                ],
            ),
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "status_list_history" ("snapshot_id", "list_id", "issuer", "status_list", "sub", "iat", "exp") VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
                [
                    snapshot.snapshot_id.clone().into(),
                    snapshot.list_id.clone().into(),
                    snapshot.issuer.clone().into(),
                    serde_json::to_value(snapshot.status_list.clone())
                        .unwrap()
                        .into(),
                    snapshot.sub.clone().into(),
                    snapshot.iat.into(),
                    snapshot.exp.into(),
                ],
            ),
            Statement::from_string(DatabaseBackend::Postgres, "COMMIT"),
        ])]
    );

    let db_conn = Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 0,
                last_insert_id: 0,
            }])
            .into_connection(),
    );
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn.clone());

    assert!(
        !store
            .update_one_with_snapshot("list-txn", entity.clone(), 1000, snapshot)
            .await
            .unwrap()
    );

    drop(store);
    let db_conn = Arc::try_unwrap(db_conn).expect("test should own the only DB handle");
    assert_eq!(
        db_conn.into_transaction_log(),
        [Transaction::many([
            Statement::from_string(DatabaseBackend::Postgres, "BEGIN"),
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "status_lists" SET "issuer" = $1, "status_list" = $2, "sub" = $3, "updated_at" = $4 WHERE "status_lists"."list_id" = $5 AND "status_lists"."updated_at" = $6"#,
                [
                    entity.issuer.into(),
                    serde_json::to_value(entity.status_list).unwrap().into(),
                    entity.sub.into(),
                    entity.updated_at.into(),
                    "list-txn".into(),
                    1000i64.into(),
                ],
            ),
            Statement::from_string(DatabaseBackend::Postgres, "ROLLBACK"),
        ])]
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_update_with_snapshot_is_atomic() {
    let db = sqlite_connection().await;
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let key = sample_jwk();
    let issuer = "issuer-atomic-sqlite";
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key))
        .await
        .unwrap();

    let v = 1000;
    let base = StatusListRecord {
        list_id: "list-atomic-sqlite".to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "initial".to_string(),
        },
        sub: "sub-atomic-sqlite".to_string(),
        updated_at: v,
    };
    store.insert_one(base.clone()).await.unwrap();

    // Happy path: row update and snapshot both commit.
    let good_snapshot = StatusListHistoryRecord {
        snapshot_id: "snap-good".to_string(),
        list_id: base.list_id.clone(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "flip-1".to_string(),
        },
        sub: base.sub.clone(),
        iat: v + 1,
        exp: v + 1 + 900,
    };
    let committed = store
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
            good_snapshot,
        )
        .await
        .unwrap();
    assert!(
        committed,
        "advancing guarded update with snapshot must commit"
    );
    let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(row.updated_at, v + 1);
    assert_eq!(row.status_list.lst, "flip-1");
    assert!(
        history
            .find_valid_at(&base.list_id, v + 1)
            .await
            .unwrap()
            .is_some(),
        "the committed snapshot must be resolvable"
    );

    // Rollback path: force snapshot INSERT failure (duplicate PK).
    let colliding_snapshot = StatusListHistoryRecord {
        snapshot_id: "snap-good".to_string(),
        list_id: base.list_id.clone(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "flip-2".to_string(),
        },
        sub: base.sub.clone(),
        iat: v + 2,
        exp: v + 2 + 900,
    };
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
            colliding_snapshot,
        )
        .await;
    assert!(
        matches!(result, Err(RepositoryError::InsertError(_))),
        "a failed snapshot insert must fail the whole unit as a plain insert error, got {result:?}"
    );
    let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(
        row.updated_at,
        v + 1,
        "row stamp must roll back when the snapshot insert fails"
    );
    assert_eq!(
        row.status_list.lst, "flip-1",
        "row content must roll back when the snapshot insert fails"
    );

    let resolved = history
        .find_valid_at(&base.list_id, v + 2)
        .await
        .unwrap()
        .expect("the earlier committed snapshot still covers v+2");
    assert_eq!(
        resolved.status_list.lst, "flip-1",
        "no partial snapshot from the rolled-back update may exist"
    );

    // Conflict path: stale guard rolls back cleanly.
    let conflict = store
        .update_one_with_snapshot(
            &base.list_id,
            StatusListRecord {
                status_list: StatusList {
                    bits: 1,
                    lst: "flip-3".to_string(),
                },
                updated_at: v + 5,
                ..base.clone()
            },
            v,
            StatusListHistoryRecord {
                snapshot_id: "snap-conflict".to_string(),
                list_id: base.list_id.clone(),
                issuer: issuer.to_string(),
                status_list: StatusList {
                    bits: 1,
                    lst: "flip-3".to_string(),
                },
                sub: base.sub.clone(),
                iat: v + 5,
                exp: v + 5 + 900,
            },
        )
        .await
        .unwrap();
    assert!(!conflict, "stale guard must report no rows and roll back");
    let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(row.updated_at, v + 1, "conflict must not change the row");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_insert_with_snapshot_is_atomic() {
    let db = sqlite_connection().await;
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let key = sample_jwk();
    let issuer = "issuer-insert-atomic";
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key))
        .await
        .unwrap();

    let new_record = |list_id: &str| StatusListRecord {
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "initial".to_string(),
        },
        sub: format!("sub-{list_id}"),
        updated_at: 1000,
    };
    let new_snapshot = |snapshot_id: &str, list_id: &str| StatusListHistoryRecord {
        snapshot_id: snapshot_id.to_string(),
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "initial".to_string(),
        },
        sub: format!("sub-{list_id}"),
        iat: 1000,
        exp: 1900,
    };

    store
        .insert_one_with_snapshot(new_record("list-ok"), new_snapshot("snap-ok", "list-ok"))
        .await
        .unwrap();
    assert!(store.find_one_by("list-ok").await.unwrap().is_some());
    assert!(
        history
            .find_valid_at("list-ok", 1000)
            .await
            .unwrap()
            .is_some(),
        "the opening snapshot must be resolvable at the publish instant"
    );

    let result = store
        .insert_one_with_snapshot(
            new_record("list-rolled-back"),
            new_snapshot("snap-ok", "list-rolled-back"),
        )
        .await;
    assert!(
        matches!(result, Err(RepositoryError::InsertError(_))),
        "a failed snapshot insert must fail the whole unit as a plain insert error, got {result:?}"
    );
    assert!(
        store
            .find_one_by("list-rolled-back")
            .await
            .unwrap()
            .is_none(),
        "the status list row must roll back when its snapshot insert fails"
    );

    let dup = store
        .insert_one_with_snapshot(new_record("list-ok"), new_snapshot("snap-dup", "list-ok"))
        .await;
    assert!(
        matches!(dup, Err(RepositoryError::DuplicateEntry)),
        "duplicate list_id must map to DuplicateEntry, got {dup:?}"
    );
    assert!(
        history
            .find_valid_at("list-rolled-back", 1000)
            .await
            .unwrap()
            .is_none(),
        "the rolled-back publish must not leave a snapshot behind"
    );

    let surviving = history
        .find_valid_at("list-ok", 1000)
        .await
        .unwrap()
        .expect("the first publish's snapshot must survive");
    assert_eq!(surviving.snapshot_id, "snap-ok");
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_insert_with_snapshot_duplicate_maps_to_duplicate_entry() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_duplicate_list_id_is_conflict(
        test_db.connection().await,
        "issuer-dup-txn-mysql",
        "list-dup-txn-mysql",
        "MySQL",
    )
    .await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_insert_with_snapshot_duplicate_maps_to_duplicate_entry() {
    let test_db = postgres_helpers::postgres_connection().await;
    assert_duplicate_list_id_is_conflict(
        test_db.db.clone(),
        "issuer-dup-txn-postgres",
        "list-dup-txn-postgres",
        "Postgres",
    )
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_insert_with_snapshot_duplicate_maps_to_duplicate_entry() {
    let db = sqlite_connection().await;
    assert_duplicate_list_id_is_conflict(
        db,
        "issuer-dup-txn-sqlite",
        "list-dup-txn-sqlite",
        "SQLite",
    )
    .await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_update_with_snapshot_rolls_back_on_history_failure() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_update_with_snapshot_rolls_back_on_history_failure(
        test_db.connection().await,
        "issuer-atomic-mysql",
        "list-atomic-mysql",
        "snap-mysql",
        "MySQL",
    )
    .await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_update_with_snapshot_rolls_back_on_history_failure() {
    let test_db = postgres_helpers::postgres_connection().await;
    assert_update_with_snapshot_rolls_back_on_history_failure(
        test_db.db.clone(),
        "issuer-atomic-postgres",
        "list-atomic-postgres",
        "snap-postgres",
        "Postgres",
    )
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_delete_older_than_deletes_expired_snapshots() {
    let db = sqlite_connection().await;
    let store = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let list_id = "test-list-delete-old";
    let issuer = "test-issuer";

    let old_snapshot = StatusListHistoryRecord {
        snapshot_id: "old-snapshot-001".to_string(),
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "compressed_old".to_string(),
        },
        sub: format!("https://example.com/statuslists/{}", list_id),
        iat: 1000,
        exp: 2000,
    };

    let recent_snapshot = StatusListHistoryRecord {
        snapshot_id: "recent-snapshot-002".to_string(),
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "compressed_recent".to_string(),
        },
        sub: format!("https://example.com/statuslists/{}", list_id),
        iat: 3000,
        exp: 5000,
    };

    let future_snapshot = StatusListHistoryRecord {
        snapshot_id: "future-snapshot-003".to_string(),
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "compressed_future".to_string(),
        },
        sub: format!("https://example.com/statuslists/{}", list_id),
        iat: 6000,
        exp: 8000,
    };

    store.insert_one(old_snapshot).await.unwrap();
    store.insert_one(recent_snapshot).await.unwrap();
    store.insert_one(future_snapshot).await.unwrap();

    let cutoff = 5500;
    let deleted = store.delete_older_than(cutoff).await.unwrap();
    assert_eq!(deleted, 2, "Should delete 2 snapshots with exp < 5500");

    let old_result = store.find_valid_at(list_id, 1500).await.unwrap();
    assert!(old_result.is_none(), "Old snapshot should be deleted");

    let recent_result = store.find_valid_at(list_id, 3500).await.unwrap();
    assert!(recent_result.is_none(), "Recent snapshot should be deleted");

    let future_result = store.find_valid_at(list_id, 6500).await.unwrap();
    assert!(
        future_result.is_some(),
        "Future snapshot should still exist"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_delete_older_than_with_no_matching_snapshots() {
    let db = sqlite_connection().await;
    let store = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let list_id = "test-list-no-delete";
    let issuer = "test-issuer";

    let snapshot = StatusListHistoryRecord {
        snapshot_id: "future-snapshot-001".to_string(),
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "compressed".to_string(),
        },
        sub: format!("https://example.com/statuslists/{}", list_id),
        iat: 5000,
        exp: 8000,
    };

    store.insert_one(snapshot).await.unwrap();

    let deleted = store.delete_older_than(3000).await.unwrap();
    assert_eq!(
        deleted, 0,
        "Should delete 0 snapshots when cutoff is before any exp"
    );

    let result = store.find_valid_at(list_id, 6500).await.unwrap();
    assert!(result.is_some(), "Future snapshot should still exist");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_delete_older_than_deletes_all_snapshots() {
    let db = sqlite_connection().await;
    let store = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let list_id = "test-list-delete-all";
    let issuer = "test-issuer";

    for i in 0..3 {
        let snapshot = StatusListHistoryRecord {
            snapshot_id: format!("old-snapshot-{}", i),
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: format!("compressed_{}", i),
            },
            sub: format!("https://example.com/statuslists/{}", list_id),
            iat: 1000 + i * 100,
            exp: 2000 + i * 100,
        };
        store.insert_one(snapshot).await.unwrap();
    }

    let deleted = store.delete_older_than(10000).await.unwrap();
    assert_eq!(deleted, 3, "Should delete all 3 snapshots");

    let result = store.find_valid_at(list_id, 1500).await.unwrap();
    assert!(result.is_none(), "All snapshots should be deleted");
}
