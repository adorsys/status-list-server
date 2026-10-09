use std::collections::BTreeMap;
use std::sync::Arc;

#[cfg(feature = "sqlite")]
use jsonwebtoken::jwk::Jwk;
use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Statement, Transaction, Value};

#[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
mod database;

#[cfg(any(feature = "sqlite", feature = "mysql"))]
use database::assert_guarded_update_rejects_stale_write;
#[cfg(feature = "sqlite")]
pub(super) use database::list_count_migration_index;
#[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
use database::{
    assert_duplicate_list_id_is_conflict, assert_list_count_migration_backfills,
    assert_list_quota_is_exact, assert_list_uris_walk_is_complete,
    assert_list_uris_walk_survives_concurrent_publishes,
    assert_sql_allocations_are_distinct_and_rollback_exhausted,
};
#[cfg(any(feature = "mysql", feature = "postgres-tests"))]
use database::{assert_update_snapshot_rolls_back, roll_back_to_before_list_count};

use super::fixtures;
#[cfg(feature = "sqlite")]
use crate::outbound::sql::models::{Credentials, StatusListHistoryRecord};
use crate::outbound::sql::models::{StatusList, StatusListRecord, status_lists};
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

    store
        .insert_one(record.clone(), fixtures::NO_LIST_QUOTA)
        .await
        .unwrap();

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
                version: record.version + 1, // guarded write must advance the version
                ..record.clone()
            },
            record.version,
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
    assert_eq!(updated_found.version, record.version + 1);

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
                size: None,
                default_status: None,
            },
            sub: "https://example.com/statuslists/list1".to_string(),
            updated_at: 0,
            version: 0,
        },
        status_lists::Model {
            list_id: "list2".to_string(),
            issuer: "issuer2".to_string(),
            status_list: StatusList {
                bits: 8,
                lst: "xyz".to_string(),
                size: None,
                default_status: None,
            },
            sub: "https://example.com/statuslists/list2".to_string(),
            updated_at: 0,
            version: 0,
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

/// Pins the keyset shape, in particular the `LIMIT` that bounds the read.
#[tokio::test]
async fn test_find_status_list_uris_after_is_a_bounded_keyset_scan() {
    let row = |id: &str| {
        BTreeMap::from([
            ("list_id".to_string(), Value::from(id)),
            (
                "sub".to_string(),
                Value::from(format!("https://example.com/statuslists/{id}")),
            ),
        ])
    };

    let db_conn = Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<BTreeMap<String, Value>, Vec<_>, _>(vec![vec![
                row("b"),
                row("c"),
            ]])
            .into_connection(),
    );
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn.clone());

    let rows = store
        .find_status_list_uris_after(Some("a"), 3)
        .await
        .unwrap();
    assert_eq!(
        rows,
        [
            (
                "b".to_string(),
                "https://example.com/statuslists/b".to_string()
            ),
            (
                "c".to_string(),
                "https://example.com/statuslists/c".to_string()
            ),
        ]
    );

    drop(store);
    let db_conn = Arc::try_unwrap(db_conn).expect("test should own the only DB handle");
    assert_eq!(
        db_conn.into_transaction_log(),
        [Transaction::from_sql_and_values(
            DatabaseBackend::Postgres,
            r#"SELECT "status_lists"."list_id", "status_lists"."sub" FROM "status_lists" WHERE "status_lists"."list_id" > $1 ORDER BY "status_lists"."list_id" ASC LIMIT $2"#,
            ["a".into(), 3u64.into()],
        )]
    );
}

/// The quota `UPDATE` must precede the `INSERT`; reversed, InnoDB deadlocks
/// concurrent publishes for one issuer (see `reserve_list_slot`).
#[tokio::test]
async fn test_insert_with_snapshot_reserves_quota_slot_before_insert() {
    let entity = fixtures::record("list-q", "issuer-q", "initial", "sub-q", 1000);
    let snapshot = fixtures::snapshot(
        "snap-q", "list-q", "issuer-q", "initial", "sub-q", 1000, 1900,
    );
    let ok = MockExecResult {
        rows_affected: 1,
        last_insert_id: 0,
    };

    let db_conn = Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<BTreeMap<String, Value>, Vec<_>, _>(vec![vec![quota_switch(
                true,
            )]])
            .append_exec_results([ok.clone(), ok.clone(), ok])
            .into_connection(),
    );
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn.clone());

    store
        .insert_one_with_snapshot(entity.clone(), snapshot.clone(), 1000)
        .await
        .unwrap();

    drop(store);
    let db_conn = Arc::try_unwrap(db_conn).expect("test should own the only DB handle");
    assert_eq!(
        db_conn.into_transaction_log(),
        [Transaction::many([
            Statement::from_string(DatabaseBackend::Postgres, "BEGIN"),
            read_quota_switch(""),
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "credentials" SET "list_count" = "list_count" + $1 WHERE "credentials"."issuer" = $2 AND "credentials"."list_count" < $3"#,
                [1i32.into(), "issuer-q".into(), 1000i64.into()],
            ),
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "status_lists" ("list_id", "issuer", "status_list", "sub", "updated_at", "version") VALUES ($1, $2, $3, $4, $5, $6)"#,
                [
                    entity.list_id.into(),
                    entity.issuer.into(),
                    serde_json::to_value(entity.status_list).unwrap().into(),
                    entity.sub.into(),
                    entity.updated_at.into(),
                    entity.version.into(),
                ],
            ),
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "status_list_history" ("snapshot_id", "list_id", "issuer", "status_list", "sub", "iat", "exp", "version") VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
                [
                    snapshot.snapshot_id.into(),
                    snapshot.list_id.into(),
                    snapshot.issuer.into(),
                    serde_json::to_value(snapshot.status_list).unwrap().into(),
                    snapshot.sub.into(),
                    snapshot.iat.into(),
                    snapshot.exp.into(),
                    snapshot.version.into(),
                ],
            ),
            Statement::from_string(DatabaseBackend::Postgres, "COMMIT"),
        ])]
    );
}

fn quota_switch(enforced: bool) -> BTreeMap<String, Value> {
    BTreeMap::from([("enforced".to_string(), Value::from(enforced))])
}

fn read_quota_switch(lock: &str) -> Statement {
    Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        format!(r#"SELECT "enforced" FROM "list_quota" WHERE "id" = $1{lock}"#),
        [1i32.into()],
    )
}

#[tokio::test]
async fn test_unenforced_quota_rereads_switch_under_shared_lock_and_still_counts() {
    let entity = fixtures::record("list-off", "issuer-off", "initial", "sub-off", 0);
    let ok = MockExecResult {
        rows_affected: 1,
        last_insert_id: 0,
    };

    let db_conn = Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<BTreeMap<String, Value>, Vec<_>, _>(vec![
                vec![quota_switch(false)],
                vec![quota_switch(false)],
            ])
            .append_exec_results([ok.clone(), ok])
            .into_connection(),
    );
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn.clone());

    store.insert_one(entity.clone(), 2).await.unwrap();

    drop(store);
    let db_conn = Arc::try_unwrap(db_conn).expect("test should own the only DB handle");
    let log = db_conn.into_transaction_log();
    let [transaction] = log.as_slice() else {
        panic!("expected one transaction, got {log:?}");
    };
    let statements = transaction.statements();
    assert_eq!(statements[1], read_quota_switch(""), "{statements:?}");
    assert_eq!(
        statements[2],
        read_quota_switch(" FOR SHARE"),
        "{statements:?}"
    );
    assert_eq!(
        statements[3],
        Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            r#"UPDATE "credentials" SET "list_count" = "list_count" + $1 WHERE "credentials"."issuer" = $2 AND "credentials"."list_count" < $3"#,
            [1i32.into(), "issuer-off".into(), i64::MAX.into()],
        ),
        "the guard must be lifted, not the count: {statements:?}"
    );
}

#[tokio::test]
async fn test_insert_at_quota_refuses_without_inserting() {
    let entity = fixtures::record("list-full", "issuer-full", "initial", "sub-full", 0);

    let db_conn = Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 0,
                last_insert_id: 0,
            }])
            .append_query_results::<BTreeMap<String, Value>, Vec<_>, _>(vec![
                vec![quota_switch(true)],
                vec![BTreeMap::from([(
                    "list_count".to_string(),
                    Value::from(2i64),
                )])],
                // The `list_id` lookup: not taken.
                vec![],
            ])
            .into_connection(),
    );
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn.clone());

    let refused = store.insert_one(entity, 2).await;
    assert!(
        matches!(
            refused,
            Err(RepositoryError::QuotaExceeded { count: 2, max: 2 })
        ),
        "a full quota must be QuotaExceeded, got {refused:?}"
    );

    drop(store);
    let db_conn = Arc::try_unwrap(db_conn).expect("test should own the only DB handle");
    let log = db_conn.into_transaction_log();
    let statements = format!("{log:?}");
    assert!(
        !statements.contains("INSERT"),
        "a refused publish must not reach its INSERT: {statements}"
    );
    assert!(
        statements.contains("ROLLBACK"),
        "a refused publish must roll back: {statements}"
    );
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

/// A client that loses the optimistic guard must be able to observe 409,
/// re-read, and retry with the fresh `updated_at`; if the guard were ever
/// permanently unmatchable, this test would fail on the retry.
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
    store
        .insert_one(base.clone(), fixtures::NO_LIST_QUOTA)
        .await
        .unwrap();

    let writer_a = StatusListRecord {
        status_list: StatusList {
            bits: 1,
            lst: "flip-A".to_string(),
            size: None,
            default_status: None,
        },
        version: base.version + 1,
        ..base.clone()
    };
    let stale_writer_b = StatusListRecord {
        status_list: StatusList {
            bits: 1,
            lst: "flip-B-stale".to_string(),
            size: None,
            default_status: None,
        },
        version: base.version + 1,
        ..base.clone()
    };

    assert!(
        store
            .update_one(&base.list_id, writer_a, base.version)
            .await
            .unwrap()
    );
    assert!(
        !store
            .update_one(&base.list_id, stale_writer_b, base.version)
            .await
            .unwrap(),
        "B should lose the stale guard first"
    );

    let reread = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(reread.version, base.version + 1);

    let retry_writer_b = StatusListRecord {
        status_list: StatusList {
            bits: 1,
            lst: "flip-B-retry".to_string(),
            size: None,
            default_status: None,
        },
        version: reread.version + 1,
        ..reread.clone()
    };
    assert!(
        store
            .update_one(&base.list_id, retry_writer_b, reread.version)
            .await
            .unwrap(),
        "B's retry with the fresh guard should succeed"
    );

    let final_row = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(final_row.status_list.lst, "flip-B-retry");
    assert_eq!(final_row.version, base.version + 2);
}

/// A guarded write whose `version` does not strictly advance past the
/// guard is rejected before touching the DB, so a caller that forgets to
/// advance the version fails loudly. The check precedes the query, so this
/// runs on the mock backend.
#[tokio::test]
async fn test_update_one_rejects_non_advancing_stamp() {
    let db_conn = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

    let entity = fixtures::record("list-x", "issuer", "x", "sub", 1000);

    // new == expected: not advancing.
    let equal = store.update_one("list-x", entity.clone(), 1).await;
    assert!(matches!(equal, Err(RepositoryError::UpdateError(_))));

    // new < expected: going backwards.
    let backwards = store.update_one("list-x", entity, 2).await;
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
        .update_one_with_snapshot("list-x", entity.clone(), 1, snapshot.clone())
        .await;
    assert!(matches!(equal, Err(RepositoryError::UpdateError(_))));

    let backwards = store
        .update_one_with_snapshot("list-x", entity, 2, snapshot)
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
    let writer = StatusListRecord {
        version: entity.version + 1,
        ..entity.clone()
    };

    assert!(
        store
            .update_one_with_snapshot("list-txn", writer.clone(), entity.version, snapshot.clone())
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
                r#"UPDATE "status_lists" SET "issuer" = $1, "status_list" = $2, "sub" = $3, "updated_at" = $4, "version" = $5 WHERE "status_lists"."list_id" = $6 AND "status_lists"."version" = $7"#,
                [
                    writer.issuer.clone().into(),
                    serde_json::to_value(writer.status_list.clone())
                        .unwrap()
                        .into(),
                    writer.sub.clone().into(),
                    writer.updated_at.into(),
                    writer.version.into(),
                    "list-txn".into(),
                    entity.version.into(),
                ],
            ),
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "status_list_history" ("snapshot_id", "list_id", "issuer", "status_list", "sub", "iat", "exp", "version") VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
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
                    snapshot.version.into(),
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
            .update_one_with_snapshot("list-txn", writer.clone(), entity.version, snapshot)
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
                r#"UPDATE "status_lists" SET "issuer" = $1, "status_list" = $2, "sub" = $3, "updated_at" = $4, "version" = $5 WHERE "status_lists"."list_id" = $6 AND "status_lists"."version" = $7"#,
                [
                    writer.issuer.into(),
                    serde_json::to_value(writer.status_list).unwrap().into(),
                    writer.sub.into(),
                    writer.updated_at.into(),
                    writer.version.into(),
                    "list-txn".into(),
                    entity.version.into(),
                ],
            ),
            Statement::from_string(DatabaseBackend::Postgres, "ROLLBACK"),
        ])]
    );
}

/// The update + snapshot pair is atomic: a colliding snapshot INSERT rolls the
/// row UPDATE back (no partial snapshot), against real SQLite since
/// `MockDatabase` cannot model rollback.
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
    store
        .insert_one(base.clone(), fixtures::NO_LIST_QUOTA)
        .await
        .unwrap();

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
                    size: None,
                    default_status: None,
                },
                updated_at: v + 1,
                version: base.version + 1,
                ..base.clone()
            },
            base.version,
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
                    size: None,
                    default_status: None,
                },
                updated_at: v + 2,
                version: base.version + 2,
                ..base.clone()
            },
            base.version + 1,
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
                    size: None,
                    default_status: None,
                },
                updated_at: v + 5,
                version: base.version + 4,
                ..base.clone()
            },
            base.version, // stale: the row is at version base.version + 1 now
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

/// The row INSERT and its opening snapshot must commit atomically — a missing
/// opening snapshot can never be repaired by a later write. Also pins that a
/// duplicate `list_id` classifies as `DuplicateEntry` (409), not a 500.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_insert_with_snapshot_is_atomic() {
    let db = fixtures::sqlite_connection().await;
    let issuer = "issuer-insert-atomic";
    fixtures::seed_credential(&db, issuer).await;

    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let history = SeaOrmStore::<StatusListHistoryRecord>::new(db.clone());

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
            fixtures::NO_LIST_QUOTA,
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
    assert_eq!(fixtures::list_count(&db, issuer).await, 1);

    // --- Rollback path: the snapshot INSERT collides on its primary key,
    // so the paired row INSERT must not survive. ---
    let result = store
        .insert_one_with_snapshot(
            new_record("list-rolled-back"),
            // Collides with the snapshot committed above.
            new_snapshot("snap-ok", "list-rolled-back", "initial"),
            fixtures::NO_LIST_QUOTA,
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

    assert_eq!(
        fixtures::list_count(&db, issuer).await,
        1,
        "a publish whose snapshot insert fails must give its quota slot back"
    );

    // --- Conflict path: a duplicate list_id must stay a DuplicateEntry so
    // a racing publish keeps mapping to 409 rather than 500. ---
    let dup = store
        .insert_one_with_snapshot(
            new_record("list-ok"),
            new_snapshot("snap-dup", "list-ok", "initial"),
            fixtures::NO_LIST_QUOTA,
        )
        .await;
    assert!(
        matches!(dup, Err(RepositoryError::DuplicateEntry)),
        "duplicate list_id must map to DuplicateEntry, got {dup:?}"
    );
    assert_eq!(fixtures::list_count(&db, issuer).await, 1);
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

/// A duplicate `list_id` raised inside the open transaction of
/// `insert_one_with_snapshot` must still classify as `DuplicateEntry` on
/// MySQL — the rollback-first-then-classify path must not lose it.
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

/// The same proof on Postgres, the production backend where a failed
/// statement poisons the transaction (`25P02`); the classification must come
/// from the original `23505`, not the rollback.
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

/// The same proof on SQLite so a regression in the error mapping fails in
/// milliseconds under a plain `cargo test`, without Docker or
/// `--all-features`.
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

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_allocations_are_distinct_and_rollback_exhausted() {
    let db = fixtures::sqlite_connection().await;
    assert_sql_allocations_are_distinct_and_rollback_exhausted(
        db,
        "issuer-allocation-sqlite",
        "SQLite",
    )
    .await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_allocations_are_distinct_and_rollback_exhausted() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_sql_allocations_are_distinct_and_rollback_exhausted(
        test_db.connection().await,
        "issuer-allocation-mysql",
        "MySQL",
    )
    .await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_allocations_are_distinct_and_rollback_exhausted() {
    let test_db = postgres_helpers::postgres_connection().await;
    assert_sql_allocations_are_distinct_and_rollback_exhausted(
        test_db.db.clone(),
        "issuer-allocation-postgres",
        "Postgres",
    )
    .await;
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

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_list_quota_is_exact() {
    let db = fixtures::sqlite_connection().await;
    assert_list_quota_is_exact(db, "issuer-quota-sqlite", "SQLite").await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_list_quota_is_exact() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    let db = test_db.connection().await;
    assert_list_quota_is_exact(db, "issuer-quota-mysql", "MySQL").await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_list_quota_is_exact() {
    let test_db = postgres_helpers::postgres_connection().await;
    let db = test_db.db.clone();
    assert_list_quota_is_exact(db, "issuer-quota-postgres", "Postgres").await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_list_uris_walk_is_complete() {
    let db = fixtures::sqlite_connection().await;
    assert_list_uris_walk_is_complete(db, "issuer-walk-sqlite", "SQLite").await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_list_uris_walk_is_complete() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    let db = test_db.connection().await;
    assert_list_uris_walk_is_complete(db, "issuer-walk-mysql", "MySQL").await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_list_uris_walk_is_complete() {
    let test_db = postgres_helpers::postgres_connection().await;
    let db = test_db.db.clone();
    assert_list_uris_walk_is_complete(db, "issuer-walk-postgres", "Postgres").await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_list_uris_walk_survives_concurrent_publishes() {
    let db = fixtures::sqlite_connection().await;
    assert_list_uris_walk_survives_concurrent_publishes(db, "issuer-midwalk-sqlite", "SQLite")
        .await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_list_uris_walk_survives_concurrent_publishes() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    let db = test_db.connection().await;
    assert_list_uris_walk_survives_concurrent_publishes(db, "issuer-midwalk-mysql", "MySQL").await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_list_uris_walk_survives_concurrent_publishes() {
    let test_db = postgres_helpers::postgres_connection().await;
    let db = test_db.db.clone();
    assert_list_uris_walk_survives_concurrent_publishes(db, "issuer-midwalk-postgres", "Postgres")
        .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_list_count_migration_backfills_and_accepts_old_pod_writes() {
    for column_already_added in [false, true] {
        let steps = list_count_migration_index() as u32;
        let db = fixtures::sqlite_connection_migrated(Some(steps)).await;
        assert_list_count_migration_backfills(&db, column_already_added, "SQLite").await;
    }
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_list_count_migration_backfills_and_accepts_old_pod_writes() {
    for column_already_added in [false, true] {
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        let db = test_db.connection().await;
        roll_back_to_before_list_count(&db).await;
        assert_list_count_migration_backfills(&db, column_already_added, "MySQL").await;
    }
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_list_count_migration_backfills_and_accepts_old_pod_writes() {
    for column_already_added in [false, true] {
        let test_db = postgres_helpers::postgres_connection().await;
        roll_back_to_before_list_count(&test_db.db).await;
        assert_list_count_migration_backfills(&test_db.db, column_already_added, "Postgres").await;
    }
}
