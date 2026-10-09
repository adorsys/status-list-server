use std::collections::BTreeSet;
use std::sync::Arc;

#[cfg(any(feature = "sqlite", feature = "mysql"))]
use jsonwebtoken::jwk::Jwk;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect};

use super::super::fixtures;
#[cfg(any(feature = "sqlite", feature = "mysql"))]
use crate::outbound::sql::models::Credentials;
use crate::outbound::sql::models::{
    StatusList, StatusListHistoryRecord, StatusListRecord, status_list_allocations,
};
use crate::outbound::sql::{RepositoryError, SeaOrmStore};

/// The lost-update proof: two writers reading the same `updated_at` cannot
/// both win. Deterministic (no threads) — first write lands, second's guard
/// misses — and the loser's flip must not overwrite the winner's.
#[cfg(any(feature = "sqlite", feature = "mysql"))]
pub(super) async fn assert_guarded_update_rejects_stale_write(
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
    store
        .insert_one(base.clone(), fixtures::NO_LIST_QUOTA)
        .await
        .unwrap();

    // Both writers read the same state, so both guard on the same version.
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
    let writer_b = StatusListRecord {
        status_list: StatusList {
            bits: 1,
            lst: "flip-B".to_string(),
            size: None,
            default_status: None,
        },
        version: base.version + 1,
        ..base.clone()
    };

    // First writer wins.
    let a_won = store
        .update_one(&base.list_id, writer_a, base.version)
        .await
        .unwrap();
    assert!(a_won, "first guarded write should land");

    // Second writer guarded on the now-stale version: rejected, not silently
    // applied.
    let b_won = store
        .update_one(&base.list_id, writer_b, base.version)
        .await
        .unwrap();
    assert!(!b_won, "stale guarded write must be rejected");

    // A's flip survived; B's did not overwrite it.
    let stored = store.find_one_by(&base.list_id).await.unwrap().unwrap();
    assert_eq!(stored.status_list.lst, "flip-A");
    assert_eq!(stored.version, base.version + 1);
}

async fn persisted_allocations(db: &Arc<DatabaseConnection>, list_id: &str) -> BTreeSet<i32> {
    status_list_allocations::Entity::find()
        .select_only()
        .column(status_list_allocations::Column::Idx)
        .filter(status_list_allocations::Column::ListId.eq(list_id))
        .order_by_asc(status_list_allocations::Column::Idx)
        .into_tuple::<i32>()
        .all(&**db)
        .await
        .unwrap()
        .into_iter()
        .collect()
}

pub(super) async fn assert_sql_allocations_are_distinct_and_rollback_exhausted(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    backend: &str,
) {
    fixtures::seed_credential(&db, issuer).await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());

    let list_id = format!("list-allocation-{backend}").to_lowercase();
    let mut record = fixtures::record(
        &list_id,
        issuer,
        "allocation",
        &format!("sub-{list_id}"),
        10,
    );
    record.status_list.size = Some(6);
    store
        .insert_one_with_allocations(record, &[0, 2], fixtures::NO_LIST_QUOTA)
        .await
        .unwrap();

    let missing_list_id = format!("list-allocation-missing-{backend}").to_lowercase();
    let missing = store.allocate_indices(&missing_list_id, issuer, 1).await;
    assert!(
        matches!(missing, Err(RepositoryError::NotFound)),
        "allocating from a missing list must return not found on {backend}, got {missing:?}"
    );

    let wrong_issuer = store
        .allocate_indices(&list_id, "issuer-allocation-other", 1)
        .await;
    assert!(
        matches!(wrong_issuer, Err(RepositoryError::IssuerMismatch)),
        "allocating with the wrong issuer must be rejected on {backend}, got {wrong_issuer:?}"
    );
    assert_eq!(
        persisted_allocations(&db, &list_id).await,
        BTreeSet::from([0, 2]),
        "failed wrong-issuer allocation must leave no partial reservation on {backend}"
    );

    let dynamic_list_id = format!("list-allocation-dynamic-{backend}").to_lowercase();
    let dynamic = fixtures::record(
        &dynamic_list_id,
        issuer,
        "allocation-dynamic",
        &format!("sub-{dynamic_list_id}"),
        15,
    );
    store
        .insert_one_with_allocations(dynamic, &[], fixtures::NO_LIST_QUOTA)
        .await
        .unwrap();
    let dynamic_result = store.allocate_indices(&dynamic_list_id, issuer, 1).await;
    assert!(
        matches!(dynamic_result, Err(RepositoryError::ListNotFixedSize)),
        "allocating from a dynamic list must be rejected on {backend}, got {dynamic_result:?}"
    );
    assert_eq!(
        persisted_allocations(&db, &dynamic_list_id).await,
        BTreeSet::new(),
        "failed dynamic-list allocation must leave no partial reservation on {backend}"
    );

    let store_a = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let store_b = SeaOrmStore::<StatusListRecord>::new(db.clone());
    // SQLite's test pool has one connection, so these serialize there; the
    // MySQL and Postgres variants exercise the row lock with real concurrency.
    let (first, second) = tokio::join!(
        store_a.allocate_indices(&list_id, issuer, 2),
        store_b.allocate_indices(&list_id, issuer, 2),
    );
    let first = first.unwrap();
    let second = second.unwrap();

    let mut all = BTreeSet::from([0, 2]);
    all.extend(first.iter().copied());
    all.extend(second.iter().copied());
    assert_eq!(
        all.len(),
        6,
        "initial and concurrently allocated indices must be distinct on {backend}: first={first:?}, second={second:?}"
    );
    assert_eq!(
        persisted_allocations(&db, &list_id).await,
        all,
        "every allocated index must be durably recorded on {backend}"
    );

    let partial_list_id = format!("list-allocation-partial-{backend}").to_lowercase();
    let mut partial = fixtures::record(
        &partial_list_id,
        issuer,
        "allocation-partial",
        &format!("sub-{partial_list_id}"),
        20,
    );
    partial.status_list.size = Some(4);
    store
        .insert_one_with_allocations(partial, &[0, 1, 2], fixtures::NO_LIST_QUOTA)
        .await
        .unwrap();

    let exhausted = store.allocate_indices(&partial_list_id, issuer, 2).await;
    assert!(
        matches!(exhausted, Err(RepositoryError::AllocationExhausted)),
        "exhausted allocation must fail without partial reservation on {backend}, got {exhausted:?}"
    );
    assert_eq!(
        persisted_allocations(&db, &partial_list_id).await,
        BTreeSet::from([0, 1, 2]),
        "failed exhausted allocation must leave no partial reservation on {backend}"
    );

    let last = store
        .allocate_indices(&partial_list_id, issuer, 1)
        .await
        .unwrap();
    assert_eq!(last, vec![3]);
    assert_eq!(
        persisted_allocations(&db, &partial_list_id).await,
        BTreeSet::from([0, 1, 2, 3]),
        "the remaining index must still be available after the failed request on {backend}"
    );
}

/// Publishes `list_id`, then republishes it under a different `snapshot_id`,
/// asserting the failure is the duplicate `list_id` classified as
/// `DuplicateEntry`, on both the transactional and non-transactional publish
/// paths. The distinct `snapshot_id` keeps the assertion aimed at one
/// constraint — a duplicate `snapshot_id` is intentionally a plain
/// `InsertError`, and reusing the committed one would couple this test to
/// statement ordering.
pub(super) async fn assert_duplicate_list_id_is_conflict(
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
            size: None,
            default_status: None,
        },
        sub: format!("sub-{list_id}"),
        updated_at,
        version: 1,
    };
    let snapshot = |snapshot_id: &str, iat: i64| StatusListHistoryRecord {
        snapshot_id: snapshot_id.to_string(),
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: "initial".to_string(),
            size: None,
            default_status: None,
        },
        sub: format!("sub-{list_id}"),
        iat,
        exp: iat + 900,
        version: 1,
    };

    store
        .insert_one_with_snapshot(
            record(1000),
            snapshot("snap-first", 1000),
            fixtures::NO_LIST_QUOTA,
        )
        .await
        .unwrap();

    // Racing publish: same list_id, freshly minted snapshot_id.
    let dup = store
        .insert_one_with_snapshot(
            record(2000),
            snapshot("snap-second", 2000),
            fixtures::NO_LIST_QUOTA,
        )
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
    let plain = store
        .insert_one(record(3000), fixtures::NO_LIST_QUOTA)
        .await;
    assert!(
        matches!(plain, Err(RepositoryError::DuplicateEntry)),
        "duplicate list_id on the snapshot-disabled publish path must also \
         map to DuplicateEntry on {backend}, got {plain:?}"
    );
}

/// Cross-backend proof (#143): a failed snapshot INSERT must roll the paired
/// row UPDATE back, on both container backends.
#[cfg(any(feature = "mysql", feature = "postgres-tests"))]
pub(super) async fn assert_update_snapshot_rolls_back(
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
    store
        .insert_one(base.clone(), fixtures::NO_LIST_QUOTA)
        .await
        .unwrap();

    // Commit one snapshot so its primary key exists to collide against.
    store
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
                    size: None,
                    default_status: None,
                },
                updated_at: v + 2,
                version: base.version + 2,
                ..base.clone()
            },
            base.version + 1,
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

/// The quota is exact on both publish paths, and a publish that fails after
/// taking a slot gives it back.
pub(super) async fn assert_list_quota_is_exact(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    backend: &str,
) {
    fixtures::seed_credential(&db, issuer).await;
    fixtures::enforce_list_quota(&db).await;
    let store = SeaOrmStore::<StatusListRecord>::new(db.clone());
    let list_id = |n: u32| format!("{issuer}-list-{n}");
    let record = |n: u32| {
        fixtures::record(
            &list_id(n),
            issuer,
            "initial",
            &format!("sub-{}", list_id(n)),
            0,
        )
    };

    store.insert_one(record(1), 2).await.unwrap();
    let dup = store.insert_one(record(1), 2).await;
    assert!(
        matches!(dup, Err(RepositoryError::DuplicateEntry)),
        "a taken list_id must still be a 409 on {backend}, got {dup:?}"
    );
    assert_eq!(
        fixtures::list_count(&db, issuer).await,
        1,
        "a publish that failed after taking its slot must give it back on {backend}"
    );

    store
        .insert_one_with_snapshot(
            record(2),
            fixtures::snapshot(
                &format!("snap-{}", list_id(2)),
                &list_id(2),
                issuer,
                "initial",
                &format!("sub-{}", list_id(2)),
                0,
                900,
            ),
            2,
        )
        .await
        .unwrap();
    assert_eq!(fixtures::list_count(&db, issuer).await, 2);

    let refused = store.insert_one(record(3), 2).await;
    assert!(
        matches!(
            refused,
            Err(RepositoryError::QuotaExceeded { count: 2, max: 2 })
        ),
        "the publish past the quota must be refused on {backend}, got {refused:?}"
    );
    assert!(
        store.find_one_by(&list_id(3)).await.unwrap().is_none(),
        "a refused publish must not be stored on {backend}"
    );
    assert_eq!(fixtures::list_count(&db, issuer).await, 2);

    let retried = store.insert_one(record(2), 2).await;
    assert!(
        matches!(retried, Err(RepositoryError::DuplicateEntry)),
        "a taken list_id at a full quota must still be a 409 on {backend}, got {retried:?}"
    );
    let retried = store
        .insert_one_with_snapshot(
            record(2),
            fixtures::snapshot(
                &format!("snap-retry-{}", list_id(2)),
                &list_id(2),
                issuer,
                "initial",
                &format!("sub-{}", list_id(2)),
                0,
                900,
            ),
            2,
        )
        .await;
    assert!(
        matches!(retried, Err(RepositoryError::DuplicateEntry)),
        "the snapshot path must agree on {backend}, got {retried:?}"
    );
    assert_eq!(fixtures::list_count(&db, issuer).await, 2);
}

/// A full walk returns every list exactly once. Mixed-case IDs sort differently
/// per backend collation, so this asserts completeness, not order.
pub(super) async fn assert_list_uris_walk_is_complete(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    backend: &str,
) {
    use std::collections::BTreeSet;

    use crate::domain::ports::StatusListRepo;
    use crate::outbound::sql::SqlStatusListRepo;

    async fn walk(repo: &SqlStatusListRepo, issuer: Option<&str>) -> (Vec<usize>, Vec<String>) {
        let mut seen = Vec::new();
        let mut page_sizes = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = repo.list_uris(issuer, after.as_deref(), 2).await.unwrap();
            page_sizes.push(page.status_lists.len());
            seen.extend(page.status_lists);
            match page.next_after {
                Some(next) => after = Some(next),
                None => return (page_sizes, seen),
            }
        }
    }

    let other_issuer = format!("{issuer}-other");
    fixtures::seed_credential(&db, issuer).await;
    fixtures::seed_credential(&db, &other_issuer).await;
    let store = SeaOrmStore::<StatusListRecord>::new(db);
    let ids = ["c", "A", "e", "b", "D"];
    let other_ids = ["f", "G"];
    for (id, owner) in ids
        .iter()
        .map(|id| (id, issuer))
        .chain(other_ids.iter().map(|id| (id, other_issuer.as_str())))
    {
        store
            .insert_one(
                fixtures::record(id, owner, "initial", &format!("sub-{id}"), 0),
                fixtures::NO_LIST_QUOTA,
            )
            .await
            .unwrap();
    }
    let repo = SqlStatusListRepo::new(store);

    let (page_sizes, seen) = walk(&repo, Some(issuer)).await;
    assert_eq!(page_sizes, [2, 2, 1], "scoped page sizes on {backend}");
    let unique: BTreeSet<_> = seen.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        seen.len(),
        "no list may appear twice on {backend}"
    );
    let expected: BTreeSet<_> = ids.iter().map(|id| format!("sub-{id}")).collect();
    assert_eq!(
        unique, expected,
        "a scoped walk returns every list of that issuer and no other on {backend}"
    );

    let (_, seen) = walk(&repo, None).await;
    let unique: BTreeSet<_> = seen.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        seen.len(),
        "no list may appear twice on {backend}"
    );
    let expected: BTreeSet<_> = ids
        .iter()
        .chain(&other_ids)
        .map(|id| format!("sub-{id}"))
        .collect();
    assert_eq!(
        unique, expected,
        "an unscoped walk returns every list on {backend}"
    );
}

/// Lists that existed when a walk started appear exactly once, even with
/// publishes mid-walk. Lowercase IDs sort the same under every collation.
pub(super) async fn assert_list_uris_walk_survives_concurrent_publishes(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    backend: &str,
) {
    use std::collections::BTreeSet;

    use crate::domain::ports::StatusListRepo;
    use crate::outbound::sql::SqlStatusListRepo;

    fixtures::seed_credential(&db, issuer).await;
    let store = SeaOrmStore::<StatusListRecord>::new(db);
    let publish = |id: &'static str| {
        let store = store.clone();
        async move {
            store
                .insert_one(
                    fixtures::record(id, issuer, "initial", &format!("sub-{id}"), 0),
                    fixtures::NO_LIST_QUOTA,
                )
                .await
                .unwrap();
        }
    };
    for id in ["list-b", "list-d", "list-f"] {
        publish(id).await;
    }
    let repo = SqlStatusListRepo::new(store.clone());

    let first = repo.list_uris(None, None, 1).await.unwrap();
    assert_eq!(
        first.status_lists,
        ["sub-list-b"],
        "first page on {backend}"
    );
    // One list behind the cursor, one ahead of it.
    publish("list-a").await;
    publish("list-z").await;

    let mut seen = first.status_lists;
    let mut after = first.next_after;
    while let Some(cursor) = after {
        let page = repo.list_uris(None, Some(&cursor), 1).await.unwrap();
        seen.extend(page.status_lists);
        after = page.next_after;
    }

    let unique: BTreeSet<_> = seen.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        seen.len(),
        "no list may appear twice on {backend}: {seen:?}"
    );
    for existing in ["sub-list-b", "sub-list-d", "sub-list-f"] {
        assert!(
            unique.contains(existing),
            "{existing} existed when the walk started and must appear on {backend}: {seen:?}"
        );
    }
    // Beyond the contract, which allows missing either; pins keyset behaviour.
    assert!(
        unique.contains("sub-list-z") && !unique.contains("sub-list-a"),
        "keyset paging sees lists ahead of the cursor, not behind it, on {backend}: {seen:?}"
    );
}

pub(in super::super) fn list_count_migration_index() -> usize {
    use sea_orm_migration::MigratorTrait;

    crate::outbound::sql::Migrator::migrations()
        .iter()
        .position(|m| m.name() == "m20260923_000001_credentials_list_count")
        .expect("the list_count migration must be registered")
}

#[cfg(any(feature = "mysql", feature = "postgres-tests"))]
pub(super) async fn roll_back_to_before_list_count(db: &DatabaseConnection) {
    use sea_orm_migration::MigratorTrait;

    use crate::outbound::sql::Migrator;

    let steps = Migrator::migrations().len() - list_count_migration_index();
    Migrator::down(db, Some(steps as u32))
        .await
        .expect("rolling back to before list_count must succeed");
}

/// The backfill counts existing lists, and old-pod credential inserts still
/// work. `column_already_added` recreates a failed MySQL backfill: column
/// present, migration unrecorded.
pub(super) async fn assert_list_count_migration_backfills(
    db: &DatabaseConnection,
    column_already_added: bool,
    backend: &str,
) {
    use sea_orm::ConnectionTrait;
    use sea_orm_migration::MigratorTrait;

    use crate::outbound::sql::Migrator;

    if column_already_added {
        db.execute_unprepared(
            "ALTER TABLE credentials ADD COLUMN list_count BIGINT NOT NULL DEFAULT 0",
        )
        .await
        .unwrap();
    }

    db.execute_unprepared(
        "INSERT INTO credentials (issuer, public_key) \
         VALUES ('issuer-old', '{}'), ('issuer-empty', '{}')",
    )
    .await
    .unwrap();
    for id in ["old-1", "old-2"] {
        db.execute_unprepared(&format!(
            "INSERT INTO status_lists (list_id, issuer, status_list, sub, updated_at) \
             VALUES ('{id}', 'issuer-old', '{{\"bits\":1,\"lst\":\"\"}}', 'sub-{id}', 0)"
        ))
        .await
        .unwrap();
    }

    Migrator::up(db, None).await.unwrap_or_else(|e| {
        panic!("migrating (column_already_added={column_already_added}) on {backend}: {e}")
    });

    assert_eq!(
        fixtures::list_count(db, "issuer-old").await,
        2,
        "on {backend}"
    );
    assert_eq!(
        fixtures::list_count(db, "issuer-empty").await,
        0,
        "on {backend}"
    );

    db.execute_unprepared(
        "INSERT INTO credentials (issuer, public_key) VALUES ('issuer-via-old-pod', '{}')",
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "NOT NULL DEFAULT 0 must let pods on the previous release keep registering \
             on {backend}: {e}"
        )
    });
    assert_eq!(fixtures::list_count(db, "issuer-via-old-pod").await, 0);
}
