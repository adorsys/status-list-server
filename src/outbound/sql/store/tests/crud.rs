use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
use std::sync::Arc;

use super::super::super::error::RepositoryError;
use super::super::super::models::{Credentials, StatusList, StatusListRecord, status_lists};
use super::super::SeaOrmStore;
use super::helpers::{
    assert_credentials_round_trip, assert_duplicate_insert_maps_to_duplicate_entry,
    assert_update_one_optimistic_guard_rejects_stale_write, sample_jwk,
};

#[cfg(feature = "sqlite")]
use super::helpers::sqlite_connection;

#[cfg(feature = "mysql")]
use crate::outbound::sql::test_containers::mysql_helpers;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_credentials_round_trip() {
    let db = sqlite_connection().await;
    assert_credentials_round_trip(db, "issuer-cred-sqlite").await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_credentials_round_trip() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_credentials_round_trip(test_db.connection().await, "issuer-mysql").await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_status_list_round_trip() {
    let db = sqlite_connection().await;
    let issuer = "issuer-list-sqlite";
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), sample_jwk()))
        .await
        .unwrap();

    let store = SeaOrmStore::<StatusListRecord>::new(db);

    let record = StatusListRecord {
        list_id: "list-sqlite-test".to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "compressed".to_string(),
        },
        sub: "sub-sqlite-test".to_string(),
        updated_at: 0,
    };

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
                updated_at: record.updated_at + 1,
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
        std::collections::BTreeMap::from([(
            "sub".to_string(),
            sea_orm::Value::from("https://example.com/statuslists/a"),
        )]),
        std::collections::BTreeMap::from([(
            "sub".to_string(),
            sea_orm::Value::from("https://example.com/statuslists/b"),
        )]),
    ];

    let db_conn = Arc::new(
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<std::collections::BTreeMap<String, sea_orm::Value>, Vec<_>, _>(
                vec![rows],
            )
            .into_connection(),
    );

    let store = SeaOrmStore::<StatusListRecord>::new(db_conn);
    let subs = store.find_all_status_list_uris().await.unwrap();

    assert_eq!(subs.len(), 2);
    assert_eq!(subs[0], "https://example.com/statuslists/a");
    assert_eq!(subs[1], "https://example.com/statuslists/b");
}

#[tokio::test]
async fn test_seaorm_store() {
    let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
    let public_key = sample_jwk();

    let entity = Credentials::new("issuer1".to_string(), public_key.clone());
    let updated_entity = Credentials::new("issuer1".to_string(), public_key.clone());

    let db_conn = Arc::new(
        mock_db
            .append_query_results::<crate::outbound::sql::models::credentials::Model, Vec<_>, _>(
                vec![
                    vec![crate::outbound::sql::models::credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone().into(),
                    }],
                    vec![crate::outbound::sql::models::credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone().into(),
                    }],
                    vec![crate::outbound::sql::models::credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone().into(),
                    }],
                    vec![crate::outbound::sql::models::credentials::Model {
                        issuer: updated_entity.issuer.clone(),
                        public_key: updated_entity.public_key.clone().into(),
                    }],
                ],
            )
            .append_exec_results(vec![
                MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                },
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

    let store = SeaOrmStore::<Credentials>::new(db_conn);

    store.insert_one(entity.clone()).await.unwrap();

    let credential = store.find_one_by("issuer1").await.unwrap().unwrap();
    assert_eq!(credential.issuer, "issuer1");
    assert_eq!(credential.public_key, public_key);

    let updated = store
        .update_one("issuer1", updated_entity.clone())
        .await
        .unwrap();
    assert!(updated);

    let deleted = store.delete_by("issuer1").await.unwrap();
    assert!(deleted);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_negative_paths() {
    let db = sqlite_connection().await;
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db);

    let key = sample_jwk();
    cred_store
        .insert_one(Credentials::new(
            "issuer-neg-sqlite".to_string(),
            key.clone(),
        ))
        .await
        .unwrap();
    let dup = cred_store
        .insert_one(Credentials::new(
            "issuer-neg-sqlite".to_string(),
            key.clone(),
        ))
        .await;
    assert!(dup.is_err(), "duplicate PK insert should fail");

    let rec = StatusListRecord {
        list_id: "list-neg-sqlite".to_string(),
        issuer: "nonexistent-issuer".to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "compressed".to_string(),
        },
        sub: "sub-neg-sqlite".to_string(),
        updated_at: 0,
    };
    let fk_err = store.insert_one(rec).await;
    assert!(fk_err.is_err(), "insert with dangling FK should fail");

    let missing = store
        .update_one(
            "missing-list-sqlite",
            StatusListRecord {
                list_id: "missing-list-sqlite".to_string(),
                issuer: "issuer-neg-sqlite".to_string(),
                status_list: StatusList {
                    bits: 1,
                    lst: "compressed".to_string(),
                },
                sub: "sub-neg-sqlite".to_string(),
                updated_at: 1,
            },
            0,
        )
        .await
        .unwrap();
    assert!(!missing, "update on missing row should report no rows");

    cred_store.delete_by("issuer-neg-sqlite").await.unwrap();
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_duplicate_insert_maps_to_duplicate_entry() {
    let db = sqlite_connection().await;
    assert_duplicate_insert_maps_to_duplicate_entry(db, "issuer-dup-sqlite", "list-dup-sqlite")
        .await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_duplicate_insert_maps_to_duplicate_entry() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_duplicate_insert_maps_to_duplicate_entry(
        test_db.connection().await,
        "issuer-dup-mysql",
        "list-dup-mysql",
    )
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_update_one_optimistic_guard_rejects_stale_write() {
    let db = sqlite_connection().await;
    assert_update_one_optimistic_guard_rejects_stale_write(
        db,
        "issuer-guard-sqlite",
        "list-guard-sqlite",
    )
    .await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_update_one_optimistic_guard_rejects_stale_write() {
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    assert_update_one_optimistic_guard_rejects_stale_write(
        test_db.connection().await,
        "issuer-guard-mysql",
        "list-guard-mysql",
    )
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_update_one_conflict_loser_can_reread_and_retry() {
    let db = sqlite_connection().await;
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db);

    let key = sample_jwk();
    let issuer = "issuer-retry-sqlite";
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key))
        .await
        .unwrap();

    let v = 1000;
    let base = StatusListRecord {
        list_id: "list-retry-sqlite".to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "initial".to_string(),
        },
        sub: "sub-retry-sqlite".to_string(),
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

#[tokio::test]
async fn test_update_one_rejects_non_advancing_stamp() {
    let db_conn = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

    let entity = StatusListRecord {
        list_id: "list-x".to_string(),
        issuer: "issuer".to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "x".to_string(),
        },
        sub: "sub".to_string(),
        updated_at: 1000,
    };

    let equal = store.update_one("list-x", entity.clone(), 1000).await;
    assert!(matches!(equal, Err(RepositoryError::UpdateError(_))));

    let backwards = store.update_one("list-x", entity, 1001).await;
    assert!(matches!(backwards, Err(RepositoryError::UpdateError(_))));
}

#[tokio::test]
async fn test_update_one_with_snapshot_rejects_non_advancing_stamp() {
    let db_conn = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
    let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

    let entity = StatusListRecord {
        list_id: "list-x".to_string(),
        issuer: "issuer".to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "x".to_string(),
        },
        sub: "sub".to_string(),
        updated_at: 1000,
    };
    let snapshot = crate::outbound::sql::models::StatusListHistoryRecord {
        snapshot_id: "snapshot-x".to_string(),
        list_id: entity.list_id.clone(),
        issuer: entity.issuer.clone(),
        status_list: entity.status_list.clone(),
        sub: entity.sub.clone(),
        iat: entity.updated_at,
        exp: entity.updated_at + 900,
    };

    let equal = store
        .update_one_with_snapshot("list-x", entity.clone(), 1000, snapshot.clone())
        .await;
    assert!(matches!(equal, Err(RepositoryError::UpdateError(_))));

    let backwards = store
        .update_one_with_snapshot("list-x", entity, 1001, snapshot)
        .await;
    assert!(matches!(backwards, Err(RepositoryError::UpdateError(_))));
}
