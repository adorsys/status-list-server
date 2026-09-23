use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "acme")]
use crate::cert_manager::storage::StorageError;
use crate::domain::models::credential::{Credential, CredentialError};
use crate::domain::models::status_list::{StatusListError, StatusListRecord, StatusListSnapshot};
use crate::domain::ports::{
    CredentialRepo, StatusListCache, StatusListRepo, StatusListSnapshotRepo,
};

#[derive(Clone, Default)]
pub struct MemoryStatusLists {
    values: Arc<RwLock<HashMap<String, StatusListRecord>>>,
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
            Ok(self.values.read().await.get(id).cloned())
        })
        .await
    }

    async fn insert(&self, record: StatusListRecord) -> Result<(), StatusListError> {
        let mut values = self.values.write().await;
        use std::collections::hash_map::Entry;
        match values.entry(record.list_id.clone()) {
            Entry::Occupied(_) => Err(StatusListError::AlreadyExists),
            Entry::Vacant(e) => {
                e.insert(record);
                Ok(())
            }
        }
    }

    async fn update(
        &self,
        record: StatusListRecord,
        expected_updated_at: i64,
    ) -> Result<bool, StatusListError> {
        let mut values = self.values.write().await;
        match values.get(&record.list_id) {
            Some(current) if current.updated_at == expected_updated_at => {}
            _ => return Ok(false),
        }
        values.insert(record.list_id.clone(), record);
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
        match values.get(&record.list_id) {
            Some(current) if current.updated_at == expected_updated_at => {}
            _ => return Ok(false),
        }
        snapshot_store
            .write()
            .await
            .insert(snapshot.snapshot_id.clone(), snapshot);
        values.insert(record.list_id.clone(), record);
        Ok(true)
    }

    async fn insert_with_snapshot(
        &self,
        record: StatusListRecord,
        snapshot: StatusListSnapshot,
    ) -> Result<(), StatusListError> {
        let snapshot_store = self.require_snapshot()?;
        let mut values = self.values.write().await;
        use std::collections::hash_map::Entry;
        match values.entry(record.list_id.clone()) {
            Entry::Occupied(_) => Err(StatusListError::AlreadyExists),
            Entry::Vacant(e) => {
                snapshot_store
                    .write()
                    .await
                    .insert(snapshot.snapshot_id.clone(), snapshot);
                e.insert(record);
                Ok(())
            }
        }
    }

    async fn list_uris(&self) -> Result<Vec<String>, StatusListError> {
        let uris: std::collections::BTreeSet<String> = self
            .values
            .read()
            .await
            .values()
            .map(|r| r.sub.clone())
            .collect();
        Ok(uris.into_iter().collect())
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
            )
            .await
            .unwrap();

        let published = service.status_list_repo().find("id").await.unwrap().unwrap();

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

        let after = service.status_list_repo().find("id").await.unwrap().unwrap();
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
            )
            .await
            .unwrap();

        let before = service.status_list_repo().find("id").await.unwrap().unwrap();

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

        let after = service.status_list_repo().find("id").await.unwrap().unwrap();
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
}
