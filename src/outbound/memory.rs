use async_trait::async_trait;
use std::{
    collections::{BTreeMap, HashMap},
    ops::Bound,
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "acme")]
use crate::cert_manager::storage::StorageError;
use crate::domain::models::credential::{Credential, CredentialError};
use crate::domain::models::status_list::{
    StatusListError, StatusListRecord, StatusListSnapshot, StatusListUriPage,
};
use crate::domain::ports::{
    CredentialRepo, StatusListCache, StatusListRepo, StatusListSnapshotRepo,
};

/// Lists ordered by `list_id`, so `list_uris` reads one page with a range scan,
/// plus each issuer's list count, so the quota check does not scan every list.
#[derive(Default)]
struct ListStore {
    by_id: BTreeMap<String, StatusListRecord>,
    per_issuer: HashMap<String, u64>,
}

impl ListStore {
    /// A taken `list_id` wins over a full quota, as in the SQL adapter.
    fn check_insert(
        &self,
        record: &StatusListRecord,
        max_lists_per_issuer: u64,
    ) -> Result<(), StatusListError> {
        if self.by_id.contains_key(&record.list_id) {
            return Err(StatusListError::AlreadyExists);
        }
        let count = self.per_issuer.get(&record.issuer.0).copied().unwrap_or(0);
        if count >= max_lists_per_issuer {
            return Err(StatusListError::QuotaExceeded {
                count,
                max: max_lists_per_issuer,
            });
        }
        Ok(())
    }

    /// Callers run `check_insert` first, under the same write lock.
    fn insert(&mut self, record: StatusListRecord) {
        *self.per_issuer.entry(record.issuer.0.clone()).or_default() += 1;
        self.by_id.insert(record.list_id.clone(), record);
    }

    /// Replaces an existing list, moving its count if the issuer changed.
    fn replace(&mut self, record: StatusListRecord) {
        let issuer = record.issuer.0.clone();
        let Some(previous) = self.by_id.insert(record.list_id.clone(), record) else {
            return;
        };
        if previous.issuer.0 != issuer {
            *self.per_issuer.entry(issuer).or_default() += 1;
            if let Some(count) = self.per_issuer.get_mut(&previous.issuer.0) {
                *count = count.saturating_sub(1);
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct MemoryStatusLists {
    values: Arc<RwLock<ListStore>>,
    snapshot: Option<Arc<RwLock<HashMap<String, StatusListSnapshot>>>>,
}

impl MemoryStatusLists {
    pub fn with_snapshot(mut self, snapshot_repo: &MemoryStatusListSnapshotRepo) -> Self {
        self.snapshot = Some(snapshot_repo.values.clone());
        self
    }

    fn require_snapshot(
        &self,
    ) -> Result<&Arc<RwLock<HashMap<String, StatusListSnapshot>>>, StatusListError> {
        self.snapshot.as_ref().ok_or_else(|| {
            StatusListError::Backend(
                "MemoryStatusLists was built without shared snapshot storage; construct it with `.with_snapshot(..)`"
                    .into(),
            )
        })
    }
}

#[async_trait]
impl StatusListRepo for MemoryStatusLists {
    async fn find(&self, id: &str) -> Result<Option<StatusListRecord>, StatusListError> {
        crate::utils::metrics_db::time_query("find", "status_list", async {
            Ok(self.values.read().await.by_id.get(id).cloned())
        })
        .await
    }

    async fn insert(
        &self,
        record: StatusListRecord,
        max_lists_per_issuer: u64,
    ) -> Result<(), StatusListError> {
        let mut values = self.values.write().await;
        values.check_insert(&record, max_lists_per_issuer)?;
        values.insert(record);
        Ok(())
    }

    async fn update(
        &self,
        record: StatusListRecord,
        expected_updated_at: i64,
    ) -> Result<bool, StatusListError> {
        let mut values = self.values.write().await;
        match values.by_id.get(&record.list_id) {
            Some(current) if current.updated_at == expected_updated_at => {}
            _ => return Ok(false),
        }
        values.replace(record);
        Ok(true)
    }

    async fn update_with_snapshot(
        &self,
        record: StatusListRecord,
        expected_updated_at: i64,
        snapshot: StatusListSnapshot,
    ) -> Result<bool, StatusListError> {
        let snapshot_store = self.require_snapshot()?;
        let mut values = self.values.write().await;
        match values.by_id.get(&record.list_id) {
            Some(current) if current.updated_at == expected_updated_at => {}
            _ => return Ok(false),
        }
        snapshot_store
            .write()
            .await
            .insert(snapshot.snapshot_id.clone(), snapshot);
        values.replace(record);
        Ok(true)
    }

    async fn insert_with_snapshot(
        &self,
        record: StatusListRecord,
        snapshot: StatusListSnapshot,
        max_lists_per_issuer: u64,
    ) -> Result<(), StatusListError> {
        let snapshot_store = self.require_snapshot()?;
        let mut values = self.values.write().await;
        values.check_insert(&record, max_lists_per_issuer)?;
        snapshot_store
            .write()
            .await
            .insert(snapshot.snapshot_id.clone(), snapshot);
        values.insert(record);
        Ok(())
    }

    /// Reads at most `limit + 1` lists, however many exist.
    async fn list_uris(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<StatusListUriPage, StatusListError> {
        let values = self.values.read().await;
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let rows: Vec<(String, String)> = values
            .by_id
            .range::<str, _>((start, Bound::Unbounded))
            .take(limit.saturating_add(1))
            .map(|(id, r)| (id.clone(), r.sub.clone()))
            .collect();
        Ok(StatusListUriPage::from_rows(rows, limit))
    }
}

#[derive(Clone, Default)]
pub struct MemoryStatusListCache {
    values: Arc<RwLock<HashMap<String, StatusListRecord>>>,
}

#[async_trait]
impl StatusListCache for MemoryStatusListCache {
    async fn get(&self, id: &str) -> Result<Option<StatusListRecord>, StatusListError> {
        Ok(self.values.read().await.get(id).cloned())
    }

    async fn put(&self, record: StatusListRecord) -> Result<(), StatusListError> {
        self.values
            .write()
            .await
            .insert(record.list_id.clone(), record);
        Ok(())
    }

    async fn invalidate(&self, id: &str) -> Result<(), StatusListError> {
        self.values.write().await.remove(id);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MemoryCredentials {
    values: Arc<RwLock<HashMap<String, Credential>>>,
}

#[async_trait]
impl CredentialRepo for MemoryCredentials {
    async fn find(&self, issuer: &str) -> Result<Option<Credential>, CredentialError> {
        Ok(self.values.read().await.get(issuer).cloned())
    }

    async fn insert(&self, credential: Credential) -> Result<(), CredentialError> {
        let mut values = self.values.write().await;
        use std::collections::hash_map::Entry;
        match values.entry(credential.issuer.0.clone()) {
            Entry::Occupied(_) => Err(CredentialError::AlreadyExists),
            Entry::Vacant(e) => {
                e.insert(credential);
                Ok(())
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct MemoryStatusListSnapshotRepo {
    values: Arc<RwLock<HashMap<String, StatusListSnapshot>>>,
}

#[async_trait]
impl StatusListSnapshotRepo for MemoryStatusListSnapshotRepo {
    async fn insert(&self, record: StatusListSnapshot) -> Result<(), StatusListError> {
        self.values
            .write()
            .await
            .insert(record.snapshot_id.clone(), record);
        Ok(())
    }

    async fn find_valid_at(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<Option<StatusListSnapshot>, StatusListError> {
        crate::utils::metrics_db::time_query("find_valid_at", "snapshot", async {
            let values = self.values.read().await;
            let result = values
                .values()
                .filter(|r| r.list_id == list_id && r.iat <= time && r.exp > time)
                .max_by_key(|r| r.iat)
                .cloned();
            Ok(result)
        })
        .await
    }

    async fn delete_older_than(&self, cutoff: i64) -> Result<u64, StatusListError> {
        let mut values = self.values.write().await;
        let to_remove: Vec<String> = values
            .values()
            .filter(|r| r.exp < cutoff)
            .map(|r| r.snapshot_id.clone())
            .collect();
        let count = to_remove.len() as u64;
        for id in to_remove {
            values.remove(&id);
        }
        Ok(count)
    }
}

#[cfg(feature = "acme")]
#[derive(Clone, Default)]
pub struct MemoryStorage {
    values: Arc<RwLock<HashMap<String, String>>>,
}

#[cfg(feature = "acme")]
#[async_trait]
impl crate::utils::cert_manager::storage::Storage for MemoryStorage {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.values
            .write()
            .await
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        Ok(self.values.read().await.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.values.write().await.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::domain::models::status_list::{Status, StatusEntry, StatusListError};
    use crate::domain::ports::CertificateProvider;
    use crate::domain::service::Service;

    struct DummyCertProvider;

    #[async_trait]
    impl CertificateProvider for DummyCertProvider {
        async fn signing_material(
            &self,
        ) -> Result<crate::domain::ports::SigningMaterial, StatusListError> {
            Ok(crate::domain::ports::SigningMaterial {
                certificate_chain: None,
                signing_key_pem: "".into(),
            })
        }
    }

    fn create_test_service(
        repo: MemoryStatusLists,
        cache: MemoryStatusListCache,
        snapshot_repo: Option<MemoryStatusListSnapshotRepo>,
    ) -> Service {
        let snapshot_arc: Option<Arc<dyn crate::domain::ports::StatusListSnapshotRepo>> =
            snapshot_repo.map(|h| Arc::new(h) as _);
        Service::from_arcs(
            Arc::new(repo),
            Arc::new(MemoryCredentials::default()),
            Arc::new(cache),
            snapshot_arc,
            Arc::new(DummyCertProvider),
        )
    }

    #[tokio::test]
    async fn domain_service_works_without_infrastructure() {
        let repo = MemoryStatusLists::default();
        let cache = MemoryStatusListCache::default();
        let service = create_test_service(repo, cache, None);

        service
            .publish_status_list(
                "id".into(),
                Issuer("issuer".into()),
                "https://example/id".into(),
                Vec::new(),
                900,
                100_000,
                5_000,
                usize::MAX,
                u64::MAX,
            )
            .await
            .unwrap();

        assert!(matches!(
            service
                .publish_status_list(
                    "id".into(),
                    Issuer("issuer".into()),
                    "https://example/id".into(),
                    Vec::new(),
                    900,
                    100_000,
                    5_000,
                    usize::MAX,
                    u64::MAX,
                )
                .await,
            Err(StatusListError::AlreadyExists)
        ));

        let fetched = service.get_status_list("id").await.unwrap();
        assert_eq!(fetched.list_id, "id");
    }

    #[tokio::test]
    async fn publish_status_list_enforces_bounds() {
        let repo = MemoryStatusLists::default();
        let cache = MemoryStatusListCache::default();
        let service = create_test_service(repo, cache, None);

        // Test out of bounds index
        let result = service
            .publish_status_list(
                "id1".into(),
                Issuer("issuer".into()),
                "https://example/id1".into(),
                vec![StatusEntry {
                    index: 500,
                    status: Status::Valid,
                }],
                900,
                100, // max_status_index = 100
                5_000,
                usize::MAX,
                u64::MAX,
            )
            .await;
        assert!(matches!(
            result,
            Err(StatusListError::IndexTooLarge {
                index: 500,
                max: 100
            })
        ));

        // Test too many statuses per request
        let result = service
            .publish_status_list(
                "id2".into(),
                Issuer("issuer".into()),
                "https://example/id2".into(),
                vec![
                    StatusEntry {
                        index: 0,
                        status: Status::Valid,
                    },
                    StatusEntry {
                        index: 1,
                        status: Status::Valid,
                    },
                ],
                900,
                100_000,
                1, // max_statuses_per_request = 1
                usize::MAX,
                u64::MAX,
            )
            .await;
        assert!(matches!(
            result,
            Err(StatusListError::TooManyStatuses { count: 2, max: 1 })
        ));
    }

    #[tokio::test]
    async fn update_statuses_rejects_wrong_issuer() {
        let repo = MemoryStatusLists::default();
        let cache = MemoryStatusListCache::default();
        let service = create_test_service(repo, cache, None);

        service
            .publish_status_list(
                "id".into(),
                Issuer("issuer".into()),
                "https://example/id".into(),
                Vec::new(),
                900,
                100_000,
                5_000,
                usize::MAX,
                u64::MAX,
            )
            .await
            .unwrap();

        let result = service
            .update_statuses(
                &Issuer("other-issuer".into()),
                "id",
                Vec::new(),
                900,
                100_000,
                5000,
                usize::MAX,
            )
            .await;

        assert!(matches!(result, Err(StatusListError::IssuerMismatch)));
    }

    fn list_record(list_id: &str, issuer: &str) -> StatusListRecord {
        StatusListRecord {
            list_id: list_id.to_string(),
            issuer: Issuer(issuer.to_string()),
            status_list: crate::domain::models::status_list::StatusList {
                bits: 1,
                lst: String::new(),
            },
            sub: format!("https://example/{list_id}"),
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn insert_enforces_quota_per_issuer() {
        let repo = MemoryStatusLists::default();

        repo.insert(list_record("a1", "issuer-a"), 2).await.unwrap();
        repo.insert(list_record("a2", "issuer-a"), 2).await.unwrap();
        assert!(matches!(
            repo.insert(list_record("a3", "issuer-a"), 2).await,
            Err(StatusListError::QuotaExceeded { count: 2, max: 2 })
        ));
        assert!(
            repo.find("a3").await.unwrap().is_none(),
            "a refused publish must not be stored"
        );
        assert!(
            matches!(
                repo.insert(list_record("a2", "issuer-a"), 2).await,
                Err(StatusListError::AlreadyExists)
            ),
            "a retried publish at a full quota must still be a 409"
        );

        repo.insert(list_record("b1", "issuer-b"), 2).await.unwrap();
    }

    #[tokio::test]
    async fn insert_with_snapshot_enforces_quota() {
        let snapshots = MemoryStatusListSnapshotRepo::default();
        let repo = MemoryStatusLists::default().with_snapshot(&snapshots);
        let snapshot = |id: &str| StatusListSnapshot {
            snapshot_id: format!("snap-{id}"),
            list_id: id.to_string(),
            issuer: Issuer("issuer".into()),
            status_list: crate::domain::models::status_list::StatusList {
                bits: 1,
                lst: String::new(),
            },
            sub: format!("https://example/{id}"),
            iat: 0,
            exp: 900,
        };

        repo.insert_with_snapshot(list_record("l1", "issuer"), snapshot("l1"), 1)
            .await
            .unwrap();
        assert!(matches!(
            repo.insert_with_snapshot(list_record("l2", "issuer"), snapshot("l2"), 1)
                .await,
            Err(StatusListError::QuotaExceeded { count: 1, max: 1 })
        ));
        assert!(
            !snapshots.values.read().await.contains_key("snap-l2"),
            "a refused publish must not leave a snapshot behind"
        );
    }

    /// Asserts completeness, not order: SQL collations order mixed-case IDs
    /// differently from byte order.
    #[tokio::test]
    async fn list_uris_pages_cover_every_list_exactly_once() {
        let repo = MemoryStatusLists::default();
        let ids = ["c", "A", "e", "b", "D"];
        for id in ids {
            repo.insert(list_record(id, "issuer"), u64::MAX)
                .await
                .unwrap();
        }

        let mut seen = Vec::new();
        let mut page_sizes = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = repo.list_uris(after.as_deref(), 2).await.unwrap();
            page_sizes.push(page.status_lists.len());
            seen.extend(page.status_lists);
            match page.next_after {
                Some(next) => after = Some(next),
                None => break,
            }
        }

        assert_eq!(page_sizes, [2, 2, 1]);
        let unique: std::collections::BTreeSet<_> = seen.iter().cloned().collect();
        assert_eq!(unique.len(), seen.len(), "no list may appear twice");
        let expected: std::collections::BTreeSet<_> = ids
            .iter()
            .map(|id| format!("https://example/{id}"))
            .collect();
        assert_eq!(unique, expected, "every list must appear");
    }

    #[tokio::test]
    async fn list_uris_after_the_last_list_is_empty() {
        let repo = MemoryStatusLists::default();
        repo.insert(list_record("a", "issuer"), u64::MAX)
            .await
            .unwrap();

        let page = repo.list_uris(Some("z"), 10).await.unwrap();
        assert!(page.status_lists.is_empty());
        assert_eq!(page.next_after, None);
    }

    #[tokio::test]
    async fn list_uris_pages_in_list_id_order_from_the_cursor() {
        let repo = MemoryStatusLists::default();
        for id in ["d", "a", "c", "b", "e"] {
            repo.insert(list_record(id, "issuer"), u64::MAX)
                .await
                .unwrap();
        }

        let page = repo.list_uris(Some("a"), 2).await.unwrap();
        assert_eq!(
            page.status_lists,
            ["https://example/b", "https://example/c"]
        );
        assert_eq!(page.next_after.as_deref(), Some("c"));
    }

    #[tokio::test]
    async fn update_neither_takes_nor_frees_a_quota_slot() {
        let snapshots = MemoryStatusListSnapshotRepo::default();
        let repo = MemoryStatusLists::default().with_snapshot(&snapshots);
        repo.insert(list_record("l1", "issuer"), 2).await.unwrap();

        let mut updated = list_record("l1", "issuer");
        updated.updated_at = 1;
        assert!(repo.update(updated, 0).await.unwrap());

        repo.insert(list_record("l2", "issuer"), 2).await.unwrap();
        assert!(matches!(
            repo.insert(list_record("l3", "issuer"), 2).await,
            Err(StatusListError::QuotaExceeded { count: 2, max: 2 })
        ));
    }
}
