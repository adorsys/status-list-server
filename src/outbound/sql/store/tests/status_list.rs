use std::collections::BTreeMap;
use std::sync::Arc;

use jsonwebtoken::jwk::Jwk;
use sea_orm::{
    DatabaseBackend, DatabaseConnection, MockDatabase, MockExecResult, Statement, Transaction,
    Value,
};

use super::fixtures;
use crate::outbound::sql::models::{
    Credentials, StatusList, StatusListHistoryRecord, StatusListRecord, status_lists,
};
use crate::outbound::sql::{RepositoryError, SeaOrmStore};

#[cfg(feature = "mysql")]
use crate::outbound::sql::test_containers::mysql_helpers;
#[cfg(feature = "postgres-tests")]
use crate::outbound::sql::test_containers::postgres_helpers;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_status_list_round_trip() {
    let db = fixtures::sqlite_connection().await;

    let issuer = "issuer-list-sqlite";
    fixtures::seed_credential(&db, issuer).await;

    let store = SeaOrmStore::<StatusListRecord>::new(db);

    let record = fixtures::record(
        "list-sqlite-test",
        issuer,
        "compressed",
        "sub-sqlite-test",
        0,
    );

    store.insert_one(record.clone()).await.unwrap();

    let found = store
        .find_one_by("list-sqlite-test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.list_id, "list-sqlite-test");
    assert_eq!(found.issuer, issuer);
    assert_eq!(found.status_list, record.status_list);

    let updated = store
        .update_one(
            "list-sqlite-test",
            StatusListRecord {
                sub: "sub-2-sqlite-test".to_string(),
                updated_at: record.updated_at + 1, // guarded write must advance the stamp
                ..record.clone()
            },
            record.updated_at,
        )
        .await
        .unwrap();
    assert!(updated);

    let updated_found = store
        .find_one_by("list-sqlite-test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_found.sub, "sub-2-sqlite-test");
    assert_eq!(updated_found.updated_at, record.updated_at + 1);

    let by_issuer = store.find_by_issuer("sub-2-sqlite-test").await.unwrap();
    assert!(!by_issuer.is_empty());

    let deleted = store.delete_by("list-sqlite-test").await.unwrap();
    assert!(deleted);
}

#[tokio::test]
async fn test_status_list_find_all() {
    let models = vec![
        status_lists::Model {
            list_id: "list1".to_string(),
            issuer: "issuer1".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "abc".to_string(),
            },
            sub: "https://example.com/statuslists/list1".to_string(),
            updated_at: 0,
        },
        status_lists::Model {
            list_id: "list2".to_string(),
            issuer: "issuer2".to_string(),
            status_list: StatusList {
                bits: 8,
                lst: "xyz".to_string(),
            },
            sub: "https://example.com/statuslists/list2".to_string(),
            updated_at: 0,
        },
    ];

    let db_conn = Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<status_lists::Model, Vec<_>, _>(vec![models.clone()])
            .into_connection(),
    );

    let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

    let records = store.find_all().await.unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].list_id, "list1");
    assert_eq!(records[0].sub, "https://example.com/statuslists/list1");
    assert_eq!(records[0].status_list.bits, 1);
    assert_eq!(records[0].status_list.lst, "abc");

    assert_eq!(records[1].list_id, "list2");
    assert_eq!(records[1].sub, "https://example.com/statuslists/list2");
    assert_eq!(records[1].status_list.bits, 8);
    assert_eq!(records[1].status_list.lst, "xyz");
}

#[tokio::test]
async fn test_status_list_find_all_status_list_uris() {
    let rows = vec![
        BTreeMap::from([(
            "sub".to_string(),
            Value::from("https://example.com/statuslists/a"),
        )]),
        BTreeMap::from([(
            "sub".to_string(),
            Value::from("https://example.com/statuslists/b"),
        )]),
    ];

    let db_conn = Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<BTreeMap<String, Value>, Vec<_>, _>(vec![rows])
            .into_connection(),
    );

    let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

    let subs = store.find_all_status_list_uris().await.unwrap();

    assert_eq!(subs.len(), 2);
    assert_eq!(subs[0], "https://example.com/statuslists/a");
    assert_eq!(subs[1], "https://example.com/statuslists/b");
}

/// The lost-update proof: two writers reading the same `updated_at` cannot
/// both win. Deterministic (no threads) — first write lands, second's guard
/// misses — and the loser's flip must not overwrite the winner's.
#[cfg(any(feature = "sqlite", feature = "mysql"))]
async fn assert_guarded_update_rejects_stale_write(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    list_id: &str,
) {
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db);

    let key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key))
        .await
        .unwrap();

    // Seed a row at a known guard value V.
    let v = 1000;
    let base = fixtures::record(list_id, issuer, "initial", &format!("sub-{list_id}"), v);
    store.insert_one(base.clone()).await.unwrap();

    // Both writers read the same state, so both guard on V.
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

    // First writer wins.
    let a_won = store.update_one(&base.list_id, writer_a, v).await.unwrap();
    assert!(a_won, "first guarded write should land");

    // Second writer guarded on the now-stale V: rejected, not silently applied.
    let b_won = store.update_one(&base.list_id, writer_b, v).await.unwrap();
    assert!(!b_won, "stale guarded write must be rejected");

    // A's flip survived; B's did not overwrite it.
    let stored = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(stored.status_list.lst, "flip-A");
    assert_eq!(stored.updated_at, v + 1);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_update_one_optimistic_guard_rejects_stale_write() {
    let db = fixtures::sqlite_connection().await;
    assert_guarded_update_rejects_stale_write(db, "issuer-guard-sqlite", "list-guard-sqlite").await;
}

/// Cross-backend proof (#143): the optimistic guard behaves identically on
/// MySQL, exercising the JSON `col_expr` write and `rows_affected` semantics
/// most likely to diverge from sqlite.
#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_update_one_optimistic_guard_rejects_stale_write() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    let db = test_db.connection().await;
    assert_guarded_update_rejects_stale_write(db, "issuer-guard-mysql", "list-guard-mysql").await;
}

/// A client that loses the optimistic guard should be able to follow the
/// contract exposed at the HTTP layer: observe 409, re-read, and retry with
/// the fresh `updated_at`. If the guard ever becomes permanently
/// unmatchable, this test fails on the retry.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_update_one_conflict_loser_can_reread_and_retry() {
    let db = fixtures::sqlite_connection().await;
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db);

    let key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
    let issuer = "issuer-retry-sqlite";
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key))
        .await
        .unwrap();

    let v = 1000;
    let base = fixtures::record(
        "list-retry-sqlite",
        issuer,
        "initial",
        "sub-retry-sqlite",
        v,
    );
    store.insert_one(base.clone()).await.unwrap();

    let writer_a = StatusListRecord {
        status_list: StatusList {
            bits: 1,
            lst: "flip-A".to_string(),
        },
        updated_at: v + 1,
        ..base.clone()
    };
    let stale_writer_b = StatusListRecord {
        status_list: StatusList {
            bits: 1,
            lst: "flip-B-stale".to_string(),
        },
        updated_at: v + 1,
        ..base.clone()
    };

    assert!(store.update_one(&base.list_id, writer_a, v).await.unwrap());
    assert!(
        !store
            .update_one(&base.list_id, stale_writer_b, v)
            .await
            .unwrap(),
        "B should lose the stale guard first"
    );

    let reread = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(reread.updated_at, v + 1);

    let retry_writer_b = StatusListRecord {
        status_list: StatusList {
            bits: 1,
            lst: "flip-B-retry".to_string(),
        },
        updated_at: reread.updated_at + 1,
        ..reread.clone()
    };
    assert!(
        store
            .update_one(&base.list_id, retry_writer_b, reread.updated_at)
            .await
            .unwrap(),
        "B's retry with the fresh guard should succeed"
    );

    let final_row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(final_row.status_list.lst, "flip-B-retry");
    assert_eq!(final_row.updated_at, v + 2);
}

/// A guarded write whose `updated_at` does not strictly advance past the
/// guard is rejected before touching the DB, so a caller that forgets to
/// advance the stamp fails loudly. The check precedes the query, so this
/// runs on the mock backend.
#[tokio::test]
async fn test_update_one_rejects_non_advancing_stamp() {
    let db_conn = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

    let entity = fixtures::record("list-x", "issuer", "x", "sub", 1000);

    // new == expected: not advancing.
    let equal = store.update_one("list-x", entity.clone(), 1000).await;
    assert!(matches!(equal, Err(RepositoryError::UpdateError(_))));

    // new < expected: going backwards.
    let backwards = store.update_one("list-x", entity, 1001).await;
    assert!(matches!(backwards, Err(RepositoryError::UpdateError(_))));
}

#[tokio::test]
async fn test_update_one_with_snapshot_rejects_non_advancing_stamp() {
    let db_conn = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

    let entity = fixtures::record("list-x", "issuer", "x", "sub", 1000);
    let snapshot = fixtures::snapshot(
        "snapshot-x",
        &entity.list_id,
        &entity.issuer,
        "x",
        "sub",
        entity.updated_at,
        entity.updated_at + 900,
    );

    let equal = store
        .update_one_with_snapshot("list-x", entity.clone(), 1000, snapshot.clone())
        .await;
    assert!(matches!(equal, Err(RepositoryError::UpdateError(_))));

    let backwards = store
        .update_one_with_snapshot("list-x", entity, 1001, snapshot)
        .await;
    assert!(matches!(backwards, Err(RepositoryError::UpdateError(_))));
}

#[tokio::test]
async fn test_update_one_with_snapshot_transaction_log_shape() {
    let entity = fixtures::record("list-txn", "issuer-txn", "flip", "sub-txn", 1001);
    let snapshot = fixtures::snapshot(
        "snap-txn",
        &entity.list_id,
        &entity.issuer,
        "flip",
        "sub-txn",
        entity.updated_at,
        entity.updated_at + 900,
    );

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

/// failure rollback (no partial snapshot), and the conflict path — against
/// real SQLite, since `MockDatabase` cannot model rollback.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_update_with_snapshot_is_atomic() {
    let db = fixtures::sqlite_connection().await;
    let issuer = "issuer-atomic-sqlite";
    fixtures::seed_credential(&db, issuer).await;

    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let v = 1000;
    let base = fixtures::record(
        "list-atomic-sqlite",
        issuer,
        "initial",
        "sub-atomic-sqlite",
        v,
    );
    store.insert_one(base.clone()).await.unwrap();

    // --- Happy path: row update and snapshot both commit. ---
    let good_snapshot = fixtures::snapshot(
        "snap-good",
        &base.list_id,
        issuer,
        "flip-1",
        &base.sub,
        v + 1,
        v + 1 + 900,
    );
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

    // --- Rollback path: force the snapshot INSERT to fail (duplicate PK)
    // and assert the paired row update did NOT land. ---
    let colliding_snapshot = fixtures::snapshot(
        "snap-good", // collides with the committed row
        &base.list_id,
        issuer,
        "flip-2",
        &base.sub,
        v + 2,
        v + 2 + 900,
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
            colliding_snapshot,
        )
        .await;
    assert!(
        matches!(result, Err(RepositoryError::InsertError(_))),
        "a failed snapshot insert must fail the whole unit as a plain \
         insert error, got {result:?}"
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
    // No partial snapshot for the rolled-back update: what resolves at v+2 is
    // still the previously committed snapshot, not the flip-2 attempt.
    let resolved = history
        .find_valid_at(&base.list_id, v + 2)
        .await
        .unwrap()
        .expect("the earlier committed snapshot still covers v+2");
    assert_eq!(
        resolved.status_list.lst, "flip-1",
        "no partial snapshot from the rolled-back update may exist"
    );

    // --- Conflict path: a stale guard rolls back cleanly and records
    // nothing. ---
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
            v, // stale: the row is at v+1 now
            fixtures::snapshot(
                "snap-conflict",
                &base.list_id,
                issuer,
                "flip-3",
                &base.sub,
                v + 5,
                v + 5 + 900,
            ),
        )
        .await
        .unwrap();
    assert!(!conflict, "stale guard must report no rows and roll back");
    let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(row.updated_at, v + 1, "conflict must not change the row");
    let resolved = history
        .find_valid_at(&base.list_id, v + 5)
        .await
        .unwrap()
        .expect("only the committed snapshot exists");
    assert_eq!(
        resolved.status_list.lst, "flip-1",
        "conflict path must not record a snapshot"
    );
}

/// The publish counterpart of the atomicity proof: the row INSERT and the
/// snapshot covering its initial state succeed or fail as a unit. A hole
/// here is worse than on the update path — no later write repairs a missing
/// opening snapshot, so §8.4 lookups over that window would 404 forever.
/// Also pins that a duplicate `list_id` still classifies as `DuplicateEntry`
/// (409), not a generic insert failure (500).
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_insert_with_snapshot_is_atomic() {
    let db = fixtures::sqlite_connection().await;
    let issuer = "issuer-insert-atomic";
    fixtures::seed_credential(&db, issuer).await;

    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let new_record = |list_id: &str| {
        fixtures::record(list_id, issuer, "initial", &format!("sub-{list_id}"), 1000)
    };
    let new_snapshot = |snapshot_id: &str, list_id: &str, lst: &str| {
        fixtures::snapshot(
            snapshot_id,
            list_id,
            issuer,
            lst,
            &format!("sub-{list_id}"),
            1000,
            1900,
        )
    };

    // --- Happy path: row and opening snapshot both commit. ---
    store
        .insert_one_with_snapshot(
            new_record("list-ok"),
            new_snapshot("snap-ok", "list-ok", "initial"),
        )
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

    // --- Rollback path: the snapshot INSERT collides on its primary key,
    // so the paired row INSERT must not survive. ---
    let result = store
        .insert_one_with_snapshot(
            new_record("list-rolled-back"),
            // Collides with the snapshot committed above.
            new_snapshot("snap-ok", "list-rolled-back", "initial"),
        )
        .await;
    // Specifically an `InsertError`, not a `DuplicateEntry`: only the *row*
    // insert classifies duplicates (`map_insert_err`), because only a
    // duplicate `list_id` is a client-visible conflict. `snapshot_id` is a
    // fresh v4 UUID per publish, so a collision here is a server fault and
    // must stay a 500. `assert_duplicate_list_id_is_conflict`
    // reasons from this asymmetry, so it is pinned rather than assumed.
    assert!(
        matches!(result, Err(RepositoryError::InsertError(_))),
        "a failed snapshot insert must fail the whole unit as a plain \
         insert error, got {result:?}"
    );
    assert!(
        store
            .find_one_by("list-rolled-back")
            .await
            .unwrap()
            .is_none(),
        "the status list row must roll back when its snapshot insert fails"
    );

    // --- Conflict path: a duplicate list_id must stay a DuplicateEntry so
    // a racing publish keeps mapping to 409 rather than 500. ---
    let dup = store
        .insert_one_with_snapshot(
            new_record("list-ok"),
            new_snapshot("snap-dup", "list-ok", "initial"),
        )
        .await;
    assert!(
        matches!(dup, Err(RepositoryError::DuplicateEntry)),
        "duplicate list_id must map to DuplicateEntry, got {dup:?}"
    );
    // The rolled-back publish recorded no snapshot either. This must name
    // `list-rolled-back` — the list that actually failed. Asserting against
    // a list_id that was never inserted proves nothing about rollback.
    assert!(
        history
            .find_valid_at("list-rolled-back", 1000)
            .await
            .unwrap()
            .is_none(),
        "the rolled-back publish must not leave a snapshot behind"
    );
    // ...and the duplicate attempt left the committed snapshot alone.
    let surviving = history
        .find_valid_at("list-ok", 1000)
        .await
        .unwrap()
        .expect("the first publish's snapshot must survive");
    assert_eq!(surviving.snapshot_id, "snap-ok");
}

/// Cross-backend proof: a duplicate `list_id` raised *inside* the open
/// transaction must still classify as `DuplicateEntry` on MySQL. The
/// non-transactional `insert_one` is already covered by
/// `test_mysql_duplicate_insert_maps_to_duplicate_entry`; what is untested
/// there is that `insert_one_with_snapshot` — which rolls back first and
/// classifies afterwards (`map_insert_err` on the error captured *before*
/// the rollback) — does not lose the classification along the way. Losing it
/// turns every racing publish into a 500 instead of a 409.
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

/// The same proof on Postgres, the production backend. Postgres is the
/// backend where this could plausibly diverge: a failed statement poisons
/// the transaction (`25P02`), so if the classification were ever read from
/// the rollback rather than from the original `23505`, it would degrade to a
/// generic insert error here and nowhere else.
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

/// The same proof on SQLite. Redundant with the two container tests above on
/// the classification question itself — but it is the only one of the three
/// that runs under a plain `cargo test`, with no Docker and no
/// `--all-features`. A regression in `insert_one_with_snapshot`'s error
/// mapping therefore fails in milliseconds locally instead of waiting for
/// the container job.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_insert_with_snapshot_duplicate_maps_to_duplicate_entry() {
    let db = fixtures::sqlite_connection().await;
    assert_duplicate_list_id_is_conflict(
        db,
        "issuer-dup-txn-sqlite",
        "list-dup-txn-sqlite",
        "SQLite",
    )
    .await;
}

/// Publishes `list_id` once, then republishes it with a *different*
/// `snapshot_id`, and asserts the failure is the duplicate `list_id`
/// classified as `DuplicateEntry` — on both publish paths, transactional
/// (`insert_one_with_snapshot`) and not (`insert_one`).
///
/// The distinct `snapshot_id` keeps the assertion aimed at one constraint.
/// A duplicate `snapshot_id` deliberately stays a plain `InsertError` rather
/// than a `DuplicateEntry` (pinned by
/// `test_sqlite_insert_with_snapshot_is_atomic`), so reusing the committed
/// one would couple this test to statement *ordering*: today the row INSERT
/// fails first and short-circuits, but if that order ever flipped, the
/// snapshot would collide first and this test would fail for a reason that
/// has nothing to do with the property under test. A fresh `snapshot_id`
/// leaves the duplicate `list_id` as the only thing that can fail.
///
/// Seeds its own issuer because `status_lists.issuer` is a foreign key onto
/// `credentials.issuer`; callers pass a per-backend `issuer`/`list_id` pair
/// so a shared database would still keep them apart.
#[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
async fn assert_duplicate_list_id_is_conflict(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    list_id: &str,
    backend: &str,
) {
    fixtures::seed_credential(&db, issuer).await;

    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

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

    // Racing publish: same list_id, freshly minted snapshot_id.
    let dup = store
        .insert_one_with_snapshot(record(2000), snapshot("snap-second", 2000))
        .await;
    assert!(
        matches!(dup, Err(RepositoryError::DuplicateEntry)),
        "duplicate list_id inside a transaction must map to DuplicateEntry \
         on {backend}, got {dup:?}"
    );

    // The rejected publish rolled back cleanly. Its snapshot would have
    // covered `[2000, 2900)`, and the first publish's covers `[1000, 1900)`,
    // so *anything* resolvable at 2000 could only be the leak this asserts
    // against — the windows do not overlap.
    assert!(
        history
            .find_valid_at(list_id, 2000)
            .await
            .unwrap()
            .is_none(),
        "the rejected publish must not leave a snapshot behind on {backend}"
    );

    // ...and the failed attempt did not disturb the committed one.
    let first = history
        .find_valid_at(list_id, 1000)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("the first publish's snapshot must survive on {backend}"));
    assert_eq!(first.snapshot_id, "snap-first");

    // The row itself is untouched. The two records differ only in
    // `updated_at`, so this is what catches a silent upsert: an
    // `ON CONFLICT DO UPDATE` "optimization" would leave 2000 here while
    // every assertion above still passed.
    let row = store
        .find_one_by(list_id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("the committed row must survive on {backend}"));
    assert_eq!(
        row.updated_at, 1000,
        "the rejected publish must not overwrite the committed row on {backend}"
    );

    // The same conflict on the *non-transactional* path. Operators can set
    // `snapshot_retention_secs = 0`, which builds a `Service` with no
    // snapshot repo, and `publish_status_list` then calls plain `insert_one`
    // — a different `map_insert_err` call site with no transaction or
    // rollback around it. Reuses this test's backend rather than paying for
    // another container, since the row it collides with is already
    // committed.
    let plain = store.insert_one(record(3000)).await;
    assert!(
        matches!(plain, Err(RepositoryError::DuplicateEntry)),
        "duplicate list_id on the snapshot-disabled publish path must also \
         map to DuplicateEntry on {backend}, got {plain:?}"
    );
}

/// Cross-backend proof (#143): a failed snapshot INSERT must roll the paired
/// row UPDATE back, on both container backends.
#[cfg(any(feature = "mysql", feature = "postgres-tests"))]
async fn assert_update_snapshot_rolls_back(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    list_id: &str,
    snapshot_id: &str,
) {
    fixtures::seed_credential(&db, issuer).await;

    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let history = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let v = 1000;
    let base = fixtures::record(list_id, issuer, "initial", &format!("sub-{list_id}"), v);
    store.insert_one(base.clone()).await.unwrap();

    // Commit one snapshot so its primary key exists to collide against.
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
            fixtures::snapshot(
                snapshot_id,
                list_id,
                issuer,
                "flip-1",
                &format!("sub-{list_id}"),
                v + 1,
                v + 1 + 900,
            ),
        )
        .await
        .unwrap();
    let snapshot = history
        .find_valid_at(&base.list_id, v + 1)
        .await
        .unwrap()
        .expect("the committed snapshot must be resolvable");
    assert_eq!(
        snapshot.status_list.lst, "flip-1",
        "the backend must round-trip the snapshot JSON"
    );

    // Second update whose snapshot collides on the primary key: the INSERT
    // fails, so the whole transaction must roll back.
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
            fixtures::snapshot(
                snapshot_id,
                list_id,
                issuer,
                "flip-2",
                &format!("sub-{list_id}"),
                v + 2,
                v + 2 + 900,
            ), // duplicate PK
        )
        .await;
    assert!(result.is_err(), "duplicate snapshot PK must fail the unit");

    let row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(
        row.updated_at,
        v + 1,
        "the backend must roll the row update back when the snapshot insert fails"
    );
    assert_eq!(
        row.status_list.lst, "flip-1",
        "the rolled-back row must retain its previously committed content"
    );
}

/// Cross-backend proof (#143): on MySQL a failed snapshot INSERT must roll
/// the paired row UPDATE back. Requires InnoDB (pinned by the migration) —
/// a non-transactional engine would silently keep the row change.
#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_update_with_snapshot_rolls_back_on_history_failure() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    let db = test_db.connection().await;
    assert_update_snapshot_rolls_back(db, "issuer-atomic-mysql", "list-atomic-mysql", "snap-mysql")
        .await;
}

/// Postgres is the production backend, so the transactional rollback is
/// proven directly on it, not just inferred from the SQLite and MySQL
/// proofs: a colliding snapshot INSERT must roll the paired row UPDATE back.
#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_update_with_snapshot_rolls_back_on_history_failure() {
    let test_db = postgres_helpers::postgres_connection().await;
    let db = test_db.db.clone();
    assert_update_snapshot_rolls_back(
        db,
        "issuer-atomic-postgres",
        "list-atomic-postgres",
        "snap-postgres",
    )
    .await;
}
