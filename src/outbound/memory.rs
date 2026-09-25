use async_trait::async_trait;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, btree_map::Entry},
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

/// Ordered by `list_id` for range-scanned pages, with per-issuer counts for the quota.
#[derive(Default)]
struct ListStore {
    by_id: BTreeMap<String, StatusListRecord>,
    per_issuer: HashMap<String, u64>,
}

impl ListStore {
    /// A taken `list_id` wins over a full quota, as in the SQL adapter.
    fn try_insert(
        &mut self,
        record: StatusListRecord,
        max_lists_per_issuer: u64,
    ) -> Result<(), StatusListError> {
        let Entry::Vacant(slot) = self.by_id.entry(record.list_id.clone()) else {
            return Err(StatusListError::AlreadyExists);
        };
        let count = self.per_issuer.entry(record.issuer.0.clone()).or_default();
        if *count >= max_lists_per_issuer {
            return Err(StatusListError::QuotaExceeded {
                count: *count,
                max: max_lists_per_issuer,
            });
        }
        *count += 1;
        slot.insert(record);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MemoryStatusLists {
    values: Arc<RwLock<ListStore>>,
    snapshot: Option<Arc<RwLock<HashMap<String, StatusListSnapshot>>>>,
    allocations: Arc<RwLock<HashMap<String, BTreeSet<i32>>>>,
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
        self.values
            .write()
            .await
            .try_insert(record, max_lists_per_issuer)
    }

    async fn update(
        &self,
        record: StatusListRecord,
        expected_updated_at: i64,
    ) -> Result<bool, StatusListError> {
        let mut values = self.values.write().await;
        match values.by_id.get_mut(&record.list_id) {
            // The service rejects issuer changes, so the per-issuer counts hold.
            Some(current) if current.updated_at == expected_updated_at => *current = record,
            _ => return Ok(false),
        }
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
        match values.by_id.get_mut(&record.list_id) {
            Some(current) if current.updated_at == expected_updated_at => *current = record,
            _ => return Ok(false),
        }
        snapshot_store
            .write()
            .await
            .insert(snapshot.snapshot_id.clone(), snapshot);
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
        values.try_insert(record, max_lists_per_issuer)?;
        snapshot_store
            .write()
            .await
            .insert(snapshot.snapshot_id.clone(), snapshot);
        Ok(())
    }

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

    async fn allocate_indices(
        &self,
        list_id: &str,
        count: u32,
        size: Option<u32>,
    ) -> Result<Vec<i32>, StatusListError> {
        if count == 0 {
            return Ok(Vec::new());
        }

        let mut allocations = self.allocations.write().await;
        let allocated = allocations.entry(list_id.to_string()).or_default();
        let mut result = Vec::with_capacity(count as usize);
        let limit = size.unwrap_or(u32::MAX);

        for candidate in 0..limit {
            let candidate = i32::try_from(candidate).map_err(|_| {
                StatusListError::InvalidStatusList("allocation index exceeds i32".to_string())
            })?;
            if allocated.insert(candidate) {
                result.push(candidate);
                if result.len() == count as usize {
                    return Ok(result);
                }
            }
        }

        for index in &result {
            allocated.remove(index);
        }
        Err(StatusListError::AllocationExhausted)
    }

    async fn record_allocated_indices(
        &self,
        list_id: &str,
        indices: &[i32],
    ) -> Result<(), StatusListError> {
        let mut allocations = self.allocations.write().await;
        let allocated = allocations.entry(list_id.to_string()).or_default();
        for index in indices {
            if !allocated.insert(*index) {
                return Err(StatusListError::DuplicateIndex { index: *index });
            }
        }
        Ok(())
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
            let key = crate::utils::crypto::SigningKey::generate(
                crate::domain::models::token::SigningAlgorithm::Es256,
            )
            .map_err(|e| StatusListError::Backend(Box::new(e)))?;
            Ok(crate::domain::ports::SigningMaterial::new(
                None,
                std::sync::Arc::new(key),
            ))
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
                vec![StatusEntry {
                    index: 0,
                    status: Status::Invalid,
                }],
                900,
                100_000,
                5000,
                usize::MAX,
            )
            .await;

        assert!(matches!(result, Err(StatusListError::IssuerMismatch)));
    }

    /// An empty PATCH is a successful no-op: it must not advance the status
    /// list version (`updated_at`) and must not insert a duplicate history
    /// snapshot. Re-submitting the current value at an existing index behaves
    /// the same way (see `noop_update_with_identical_values`).
    #[tokio::test]
    async fn empty_update_is_noop_without_version_advance_or_snapshot() {
        let repo = MemoryStatusLists::default();
        let cache = MemoryStatusListCache::default();
        // Keep a handle to the same backing map the service will share with the
        // lists repo, so we can count snapshots after the no-op update.
        let snapshot_repo = MemoryStatusListSnapshotRepo::default();
        let snapshots = snapshot_repo.values.clone();
        let lists = repo.clone().with_snapshot(&snapshot_repo);
        let service = create_test_service(lists, cache, Some(snapshot_repo));

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

        let published = service
            .status_list_repo()
            .find("id")
            .await
            .unwrap()
            .unwrap();

        let result = service
            .update_statuses(
                &Issuer("issuer".into()),
                "id",
                Vec::new(),
                900,
                100_000,
                5_000,
                usize::MAX,
            )
            .await;

        let landed = result.expect("an empty update must succeed as a no-op");

        let after = service
            .status_list_repo()
            .find("id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.updated_at, published.updated_at,
            "an empty update must not advance the status list version"
        );
        assert_eq!(
            landed.updated_at, published.updated_at,
            "the returned record must carry the unchanged version"
        );
        assert_eq!(
            snapshots.read().await.len(),
            1,
            "only the publish snapshot may exist; an empty update must not insert a duplicate"
        );
    }

    /// The redundant-write guard must catch value-identical updates too, not
    /// just the literal empty array: re-submitting the current status at an
    /// existing index must be a successful no-op and must not insert a snapshot.
    #[tokio::test]
    async fn noop_update_with_identical_values() {
        let repo = MemoryStatusLists::default();
        let cache = MemoryStatusListCache::default();
        let snapshot_repo = MemoryStatusListSnapshotRepo::default();
        let snapshots = snapshot_repo.values.clone();
        let lists = repo.clone().with_snapshot(&snapshot_repo);
        let service = create_test_service(lists, cache, Some(snapshot_repo));

        service
            .publish_status_list(
                "id".into(),
                Issuer("issuer".into()),
                "https://example/id".into(),
                vec![StatusEntry {
                    index: 0,
                    status: Status::Valid,
                }],
                900,
                100_000,
                5_000,
                usize::MAX,
                u64::MAX,
            )
            .await
            .unwrap();

        let before = service
            .status_list_repo()
            .find("id")
            .await
            .unwrap()
            .unwrap();

        // Re-submitting index 0 = VALID, which is already its current value.
        service
            .update_statuses(
                &Issuer("issuer".into()),
                "id",
                vec![StatusEntry {
                    index: 0,
                    status: Status::Valid,
                }],
                900,
                100_000,
                5_000,
                usize::MAX,
            )
            .await
            .expect("an identical update must succeed as a no-op");

        let after = service
            .status_list_repo()
            .find("id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.updated_at, before.updated_at,
            "re-submitting identical values must not advance the version"
        );
        assert_eq!(after.status_list, before.status_list);
        assert_eq!(
            snapshots.read().await.len(),
            1,
            "an identical update must not insert a redundant snapshot"
        );
    }

    /// The redundant-write guard must only swallow updates that leave the list
    /// byte-for-byte identical. A mixed payload — one entry unchanged, one
    /// changed — must still land: `updated_at` advances and a second snapshot is
    /// written. This pins the behaviour so a later "optimisation" that skips the
    /// write when *any* entry is unchanged would fail.
    #[tokio::test]
    async fn mixed_update_advances_version_and_writes_snapshot() {
        let repo = MemoryStatusLists::default();
        let cache = MemoryStatusListCache::default();
        let snapshot_repo = MemoryStatusListSnapshotRepo::default();
        let snapshots = snapshot_repo.values.clone();
        let lists = repo.clone().with_snapshot(&snapshot_repo);
        let service = create_test_service(lists, cache, Some(snapshot_repo));

        service
            .publish_status_list(
                "id".into(),
                Issuer("issuer".into()),
                "https://example/id".into(),
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
                5_000,
                usize::MAX,
                u64::MAX,
            )
            .await
            .unwrap();

        let before = service
            .status_list_repo()
            .find("id")
            .await
            .unwrap()
            .unwrap();

        // Keep index 0 = VALID but change index 1 to INVALID.
        service
            .update_statuses(
                &Issuer("issuer".into()),
                "id",
                vec![
                    StatusEntry {
                        index: 0,
                        status: Status::Valid,
                    },
                    StatusEntry {
                        index: 1,
                        status: Status::Invalid,
                    },
                ],
                900,
                100_000,
                5_000,
                usize::MAX,
            )
            .await
            .expect("a mixed update that changes the list must land");

        let after = service
            .status_list_repo()
            .find("id")
            .await
            .unwrap()
            .unwrap();
        assert!(
            after.updated_at > before.updated_at,
            "a mixed update that changes the list must advance the version"
        );
        assert_ne!(after.status_list, before.status_list);
        assert_eq!(
            snapshots.read().await.len(),
            2,
            "the publish snapshot plus the changed update must both be retained"
        );
    }

    /// Patching an index past the end of the list with VALID grows the list, so
    /// the write must land and the version must bump. Readers treat an index
    /// outside the list differently from an index whose value is 0, so this must
    /// not collapse into a no-op even though the new slot's value is 0.
    #[tokio::test]
    async fn patch_past_end_grows_list_and_bumps_version() {
        let repo = MemoryStatusLists::default();
        let cache = MemoryStatusListCache::default();
        let snapshot_repo = MemoryStatusListSnapshotRepo::default();
        let snapshots = snapshot_repo.values.clone();
        let lists = repo.clone().with_snapshot(&snapshot_repo);
        let service = create_test_service(lists, cache, Some(snapshot_repo));

        service
            .publish_status_list(
                "id".into(),
                Issuer("issuer".into()),
                "https://example/id".into(),
                vec![StatusEntry {
                    index: 0,
                    status: Status::Valid,
                }],
                900,
                100_000,
                5_000,
                usize::MAX,
                u64::MAX,
            )
            .await
            .unwrap();

        let before = service
            .status_list_repo()
            .find("id")
            .await
            .unwrap()
            .unwrap();

        service
            .update_statuses(
                &Issuer("issuer".into()),
                "id",
                vec![StatusEntry {
                    index: 100,
                    status: Status::Valid,
                }],
                900,
                100_000,
                5_000,
                usize::MAX,
            )
            .await
            .expect("growing the list with a padding write must land");

        let after = service
            .status_list_repo()
            .find("id")
            .await
            .unwrap()
            .unwrap();
        assert!(
            after.updated_at > before.updated_at,
            "growing the list must advance the version, not become a no-op"
        );
        assert_ne!(after.status_list, before.status_list, "the list must grow");
        assert_eq!(
            snapshots.read().await.len(),
            2,
            "the growth write must produce a second snapshot"
        );
    }

    /// Duplicate indices in a single update payload must be rejected outright.
    #[tokio::test]
    async fn update_rejects_duplicate_indices() {
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
                &Issuer("issuer".into()),
                "id",
                vec![
                    StatusEntry {
                        index: 0,
                        status: Status::Invalid,
                    },
                    StatusEntry {
                        index: 0,
                        status: Status::Suspended,
                    },
                ],
                900,
                100_000,
                5_000,
                usize::MAX,
            )
            .await;

        assert!(matches!(
            result,
            Err(StatusListError::DuplicateIndex { index: 0 })
        ));
    }

    /// The request-shape bound (index bound) is checked before duplicate indices
    /// in `update_statuses`, so a payload that is both over `max_status_index`
    /// and internally duplicated must surface `index_too_large`, never
    /// `duplicate_index`. This pins the ordering so reordering those two calls
    /// becomes a deliberate, test-breaking change.
    #[tokio::test]
    async fn update_reorders_duplicate_after_index_bound() {
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
                &Issuer("issuer".into()),
                "id",
                vec![
                    StatusEntry {
                        index: 999_999,
                        status: Status::Valid,
                    },
                    StatusEntry {
                        index: 999_999,
                        status: Status::Invalid,
                    },
                ],
                900,
                10, // max_status_index
                5_000,
                usize::MAX,
            )
            .await;

        assert!(matches!(
            result,
            Err(StatusListError::IndexTooLarge {
                index: 999_999,
                max: 10
            })
        ));
    }

    fn list_record(list_id: &str, issuer: &str) -> StatusListRecord {
        StatusListRecord {
            list_id: list_id.to_string(),
            issuer: Issuer(issuer.to_string()),
            status_list: crate::domain::models::status_list::StatusList {
                bits: 1,
                lst: String::new(),
                size: None,
                default_status: None,
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
                size: None,
                default_status: None,
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
