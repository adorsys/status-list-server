//! In-memory adapters for application-service unit tests and memory-only use.
#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
use crate::domain::StatusListSnapshot;
#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
use crate::ports::StatusListHistoryRepository;
use crate::{
    domain::{Credential, StatusListRecord},
    ports::{CredentialRepository, PortError, StatusListCache, StatusListRepository},
};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct MemoryStatusLists {
    values: Arc<RwLock<HashMap<String, StatusListRecord>>>,
}
#[async_trait]
impl StatusListRepository for MemoryStatusLists {
    async fn find(&self, id: &str) -> Result<Option<Arc<StatusListRecord>>, PortError> {
        Ok(self.values.read().await.get(id).cloned().map(Arc::new))
    }
    async fn insert(&self, record: StatusListRecord) -> Result<(), PortError> {
        self.values
            .write()
            .await
            .insert(record.list_id.clone(), record);
        Ok(())
    }
    /// Mirrors the SQL adapter's optimistic guard so use-case concurrency
    /// behavior is testable without a database: the write lands only if the
    /// stored stamp is still `expected_updated_at`.
    async fn update(
        &self,
        record: StatusListRecord,
        expected_updated_at: i64,
    ) -> Result<bool, PortError> {
        let mut values = self.values.write().await;
        match values.get(&record.list_id) {
            Some(current) if current.updated_at == expected_updated_at => {}
            _ => return Ok(false),
        }
        values.insert(record.list_id.clone(), record);
        Ok(true)
    }
    async fn list_uris(&self) -> Result<Vec<String>, PortError> {
        Ok(self
            .values
            .read()
            .await
            .values()
            .map(|r| r.sub.clone())
            .collect())
    }
}
#[derive(Clone, Default)]
pub struct MemoryStatusListCache {
    values: Arc<RwLock<HashMap<String, StatusListRecord>>>,
}
#[async_trait]
impl StatusListCache for MemoryStatusListCache {
    async fn get(&self, id: &str) -> Result<Option<Arc<StatusListRecord>>, PortError> {
        Ok(self.values.read().await.get(id).cloned().map(Arc::new))
    }
    async fn put(&self, record: StatusListRecord) -> Result<(), PortError> {
        self.values
            .write()
            .await
            .insert(record.list_id.clone(), record);
        Ok(())
    }
    async fn invalidate(&self, id: &str) -> Result<(), PortError> {
        self.values.write().await.remove(id);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MemoryCredentials {
    values: Arc<RwLock<HashMap<String, Credential>>>,
}

#[async_trait]
impl CredentialRepository for MemoryCredentials {
    async fn find(&self, issuer: &str) -> Result<Option<Credential>, PortError> {
        Ok(self.values.read().await.get(issuer).cloned())
    }

    async fn insert(&self, credential: Credential) -> Result<(), PortError> {
        self.values
            .write()
            .await
            .insert(credential.issuer.0.clone(), credential);
        Ok(())
    }
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
#[derive(Clone, Default)]
pub struct MemoryStatusListHistory {
    values: Arc<RwLock<HashMap<String, StatusListSnapshot>>>,
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
#[async_trait]
impl StatusListHistoryRepository for MemoryStatusListHistory {
    async fn insert(&self, record: StatusListSnapshot) -> Result<(), PortError> {
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
    ) -> Result<Option<StatusListSnapshot>, PortError> {
        let values = self.values.read().await;
        let result = values
            .values()
            .filter(|r| r.list_id == list_id && r.iat <= time && r.exp > time)
            .max_by_key(|r| r.iat)
            .cloned();
        Ok(result)
    }

    async fn delete_older_than(&self, cutoff: i64) -> Result<u64, PortError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application::{GetStatusListToken, PublishStatusList, UpdateStatuses, UseCaseError},
        domain::{DomainError, Issuer, Status, StatusEntry, StatusList, StatusListRecord},
        ports::StatusListCache,
    };
    fn record() -> StatusListRecord {
        StatusListRecord {
            list_id: "id".into(),
            issuer: Issuer("issuer".into()),
            status_list: StatusList {
                bits: 1,
                lst: "".into(),
            },
            sub: "https://example/id".into(),
            updated_at: 1672531200,
        }
    }

    #[tokio::test]
    async fn application_services_work_without_infrastructure() {
        let repo = Arc::new(MemoryStatusLists::default());
        let cache = Arc::new(MemoryStatusListCache::default());
        PublishStatusList::new(repo.clone())
            .execute(record())
            .await
            .unwrap();
        assert!(matches!(
            PublishStatusList::new(repo.clone()).execute(record()).await,
            Err(UseCaseError::AlreadyExists)
        ));
        let fetched = GetStatusListToken::new(repo.clone(), cache.clone())
            .execute("id")
            .await
            .unwrap();
        assert_eq!(fetched.list_id, "id");
        UpdateStatuses::new(repo, cache.clone())
            .execute(&Issuer("issuer".into()), "id", Vec::new())
            .await
            .unwrap();
        assert!(cache.get("id").await.unwrap().is_none());
    }

    #[cfg(any(
        feature = "server",
        feature = "postgres",
        feature = "sqlite",
        feature = "mysql"
    ))]
    #[tokio::test]
    async fn application_services_work_with_history() {
        use crate::application::{PublishStatusListWithHistory, UpdateStatusesWithHistory};
        let repo = Arc::new(MemoryStatusLists::default());
        let cache = Arc::new(MemoryStatusListCache::default());
        let history = Arc::new(MemoryStatusListHistory::default());
        let token_exp_secs = 900u64;
        PublishStatusListWithHistory::new(repo.clone(), history.clone(), token_exp_secs)
            .execute(record())
            .await
            .unwrap();
        assert!(matches!(
            PublishStatusListWithHistory::new(repo.clone(), history.clone(), token_exp_secs)
                .execute(record())
                .await,
            Err(UseCaseError::AlreadyExists)
        ));
        let fetched = GetStatusListToken::new(repo.clone(), cache.clone())
            .execute("id")
            .await
            .unwrap();
        assert_eq!(fetched.list_id, "id");
        UpdateStatusesWithHistory::new(repo, cache.clone(), history)
            .execute(&Issuer("issuer".into()), "id", Vec::new(), token_exp_secs)
            .await
            .unwrap();
        assert!(cache.get("id").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn update_statuses_rejects_wrong_issuer() {
        let repo = Arc::new(MemoryStatusLists::default());
        let cache = Arc::new(MemoryStatusListCache::default());
        PublishStatusList::new(repo.clone())
            .execute(record())
            .await
            .unwrap();

        let result = UpdateStatuses::new(repo, cache)
            .execute(&Issuer("other-issuer".into()), "id", Vec::new())
            .await;

        assert!(matches!(result, Err(UseCaseError::IssuerMismatch)));
    }

    #[tokio::test]
    async fn get_status_list_reports_not_found() {
        let repo = Arc::new(MemoryStatusLists::default());
        let cache = Arc::new(MemoryStatusListCache::default());

        let result = GetStatusListToken::new(repo, cache)
            .execute("missing")
            .await;

        assert!(matches!(result, Err(UseCaseError::NotFound)));
    }

    #[tokio::test]
    async fn update_statuses_propagates_domain_errors() {
        let repo = Arc::new(MemoryStatusLists::default());
        let cache = Arc::new(MemoryStatusListCache::default());
        PublishStatusList::new(repo.clone())
            .execute(record())
            .await
            .unwrap();

        let result = UpdateStatuses::new(repo, cache)
            .execute(
                &Issuer("issuer".into()),
                "id",
                vec![StatusEntry {
                    index: 0,
                    status: Status::ApplicationSpecific(3),
                }],
            )
            .await;

        assert!(matches!(
            result,
            Err(UseCaseError::Domain(DomainError::InvalidStatusList(_)))
        ));
    }

    /// Serves a stale `updated_at` from `find` while delegating everything
    /// else, modeling a racing writer that advanced the stamp between this
    /// writer's read and its guarded write.
    struct StaleReadStatusLists {
        inner: MemoryStatusLists,
        stale_updated_at: i64,
    }

    #[async_trait]
    impl StatusListRepository for StaleReadStatusLists {
        async fn find(&self, id: &str) -> Result<Option<Arc<StatusListRecord>>, PortError> {
            Ok(self.inner.find(id).await?.map(|record| {
                let mut stale = record.as_ref().clone();
                stale.updated_at = self.stale_updated_at;
                Arc::new(stale)
            }))
        }
        async fn insert(&self, record: StatusListRecord) -> Result<(), PortError> {
            self.inner.insert(record).await
        }
        async fn update(
            &self,
            record: StatusListRecord,
            expected_updated_at: i64,
        ) -> Result<bool, PortError> {
            self.inner.update(record, expected_updated_at).await
        }
        async fn list_uris(&self) -> Result<Vec<String>, PortError> {
            self.inner.list_uris().await
        }
    }

    /// The memory adapter's CAS must reproduce the SQL guard semantics: a
    /// write guarded on a stale stamp is rejected as `Conflict`, and the
    /// rejected write leaves no trace — the cache entry survives untouched.
    #[tokio::test]
    async fn update_statuses_returns_conflict_when_write_races() {
        let inner = MemoryStatusLists::default();
        inner.insert(record()).await.unwrap();
        let repo = Arc::new(StaleReadStatusLists {
            inner,
            stale_updated_at: 100,
        });
        let cache = Arc::new(MemoryStatusListCache::default());
        cache.put(record()).await.unwrap();

        let result = UpdateStatuses::new(repo, cache.clone())
            .execute(&Issuer("issuer".into()), "id", Vec::new())
            .await;

        assert!(matches!(result, Err(UseCaseError::Conflict)));
        assert!(
            cache.get("id").await.unwrap().is_some(),
            "a rejected write must not invalidate the cache"
        );
    }

    /// Same race through the history-aware use case: nothing may be persisted
    /// for a write that never landed — no snapshot, no cache invalidation.
    #[cfg(any(
        feature = "server",
        feature = "postgres",
        feature = "sqlite",
        feature = "mysql"
    ))]
    #[tokio::test]
    async fn update_statuses_with_history_writes_nothing_on_conflict() {
        use crate::application::UpdateStatusesWithHistory;
        let inner = MemoryStatusLists::default();
        inner.insert(record()).await.unwrap();
        let repo = Arc::new(StaleReadStatusLists {
            inner,
            stale_updated_at: 100,
        });
        let cache = Arc::new(MemoryStatusListCache::default());
        cache.put(record()).await.unwrap();
        let history = Arc::new(MemoryStatusListHistory::default());
        let token_exp_secs = 900u64;

        let result = UpdateStatusesWithHistory::new(repo, cache.clone(), history.clone())
            .execute(&Issuer("issuer".into()), "id", Vec::new(), token_exp_secs)
            .await;

        assert!(matches!(result, Err(UseCaseError::Conflict)));
        assert!(cache.get("id").await.unwrap().is_some());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            history.find_valid_at("id", now).await.unwrap().is_none(),
            "a rejected write must not record a historical snapshot"
        );
    }

    /// End-to-end pin of the stamp monotonicity through the use case and the
    /// memory adapter: two updates inside the same wall-clock second must both
    /// advance `updated_at`, or the second writer's guard could not move.
    #[tokio::test]
    async fn update_statuses_advances_updated_at_within_same_second() {
        let repo = Arc::new(MemoryStatusLists::default());
        let cache = Arc::new(MemoryStatusListCache::default());
        PublishStatusList::new(repo.clone())
            .execute(record())
            .await
            .unwrap();
        let initial = repo.find("id").await.unwrap().unwrap().updated_at;

        let update = UpdateStatuses::new(repo.clone(), cache);
        update
            .execute(&Issuer("issuer".into()), "id", Vec::new())
            .await
            .unwrap();
        let first = repo.find("id").await.unwrap().unwrap().updated_at;
        update
            .execute(&Issuer("issuer".into()), "id", Vec::new())
            .await
            .unwrap();
        let second = repo.find("id").await.unwrap().unwrap().updated_at;

        assert!(first > initial, "update must advance the stamp");
        assert!(
            second > first,
            "a same-second update must still advance the stamp"
        );
    }
}
