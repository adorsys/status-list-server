use super::fixtures;
use crate::outbound::sql::SeaOrmStore;
use crate::outbound::sql::models::StatusListHistoryRecord;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_delete_older_than_deletes_expired_snapshots() {
    let db = fixtures::sqlite_connection().await;
    let store = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let list_id = "test-list-delete-old";
    let issuer = "test-issuer";

    // Insert snapshots with different expiration times
    let old_snapshot = fixtures::snapshot(
        "old-snapshot-001",
        list_id,
        issuer,
        "compressed_old",
        &format!("https://example.com/statuslists/{list_id}"),
        1000,
        2000, // Expires at 2000
    );

    let recent_snapshot = fixtures::snapshot(
        "recent-snapshot-002",
        list_id,
        issuer,
        "compressed_recent",
        &format!("https://example.com/statuslists/{list_id}"),
        3000,
        5000, // Expires at 5000
    );

    let future_snapshot = fixtures::snapshot(
        "future-snapshot-003",
        list_id,
        issuer,
        "compressed_future",
        &format!("https://example.com/statuslists/{list_id}"),
        6000,
        8000, // Expires at 8000
    );

    // Insert all snapshots
    store.insert_one(old_snapshot).await.unwrap();
    store.insert_one(recent_snapshot).await.unwrap();
    store.insert_one(future_snapshot).await.unwrap();

    // Delete snapshots with exp < 5500 (should delete old_snapshot and recent_snapshot)
    let cutoff = 5500;
    let deleted = store.delete_older_than(cutoff).await.unwrap();
    assert_eq!(deleted, 2, "Should delete 2 snapshots with exp < 5500");

    // Verify old snapshots are gone
    let old_result = store.find_valid_at(list_id, 1500).await.unwrap();
    assert!(old_result.is_none(), "Old snapshot should be deleted");

    let recent_result = store.find_valid_at(list_id, 3500).await.unwrap();
    assert!(recent_result.is_none(), "Recent snapshot should be deleted");

    // Verify future snapshot still exists
    let future_result = store.find_valid_at(list_id, 6500).await.unwrap();
    assert!(
        future_result.is_some(),
        "Future snapshot should still exist"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_delete_older_than_with_no_matching_snapshots() {
    let db = fixtures::sqlite_connection().await;
    let store = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let list_id = "test-list-no-delete";
    let issuer = "test-issuer";

    // Insert a single future snapshot
    let snapshot = fixtures::snapshot(
        "future-snapshot-001",
        list_id,
        issuer,
        "compressed",
        &format!("https://example.com/statuslists/{list_id}"),
        5000,
        8000,
    );

    store.insert_one(snapshot).await.unwrap();

    // Delete with cutoff before the snapshot's exp
    let deleted = store.delete_older_than(3000).await.unwrap();
    assert_eq!(
        deleted, 0,
        "Should delete 0 snapshots when cutoff is before any exp"
    );

    // Verify snapshot still exists
    let result = store.find_valid_at(list_id, 6500).await.unwrap();
    assert!(result.is_some(), "Future snapshot should still exist");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_delete_older_than_deletes_all_snapshots() {
    let db = fixtures::sqlite_connection().await;
    let store = SeaOrmStore::<StatusListHistoryRecord>::new(db);

    let list_id = "test-list-delete-all";
    let issuer = "test-issuer";

    // Insert multiple old snapshots
    for i in 0..3 {
        let snapshot = fixtures::snapshot(
            &format!("old-snapshot-{i}"),
            list_id,
            issuer,
            &format!("compressed_{i}"),
            &format!("https://example.com/statuslists/{list_id}"),
            1000 + i * 100,
            2000 + i * 100,
        );
        store.insert_one(snapshot).await.unwrap();
    }

    // Delete with cutoff far in the future
    let deleted = store.delete_older_than(10000).await.unwrap();
    assert_eq!(deleted, 3, "Should delete all 3 snapshots");

    // Verify all snapshots are gone
    let result = store.find_valid_at(list_id, 1500).await.unwrap();
    assert!(result.is_none(), "All snapshots should be deleted");
}
