//! In-memory adapters for application-service unit tests and memory-only use.
use crate::{
    domain::{Credential, StatusListRecord},
    ports::{
        CredentialRepository, DnsProvider, MetricsCollector, PortError, SecretStore,
        StatusListCache, StatusListRepository,
    },
};
#[cfg(any(feature = "server", feature = "postgres"))]
use crate::{models::StatusListHistoryRecord, ports::StatusListHistoryRepository};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct MemoryStatusLists {
    values: Arc<RwLock<HashMap<String, StatusListRecord>>>,
}
#[async_trait]
impl StatusListRepository for MemoryStatusLists {
    async fn find(&self, id: &str) -> Result<Option<StatusListRecord>, PortError> {
        Ok(self.values.read().await.get(id).cloned())
    }
    async fn insert(&self, record: StatusListRecord) -> Result<(), PortError> {
        self.values
            .write()
            .await
            .insert(record.list_id.clone(), record);
        Ok(())
    }
    async fn update(&self, record: StatusListRecord) -> Result<bool, PortError> {
        let mut values = self.values.write().await;
        if !values.contains_key(&record.list_id) {
            return Ok(false);
        };
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
    async fn get(&self, id: &str) -> Result<Option<StatusListRecord>, PortError> {
        Ok(self.values.read().await.get(id).cloned())
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

#[derive(Clone, Default)]
pub struct MemorySecretStore {
    values: Arc<RwLock<HashMap<String, String>>>,
}

#[async_trait]
impl SecretStore for MemorySecretStore {
    async fn get(&self, name: &str) -> Result<Option<String>, PortError> {
        Ok(self.values.read().await.get(name).cloned())
    }

    async fn put(&self, name: &str, value: &str) -> Result<(), PortError> {
        self.values
            .write()
            .await
            .insert(name.to_string(), value.to_string());
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MemoryDnsProvider;

#[async_trait]
impl DnsProvider for MemoryDnsProvider {
    async fn present_txt(&self, _name: &str, _value: &str) -> Result<(), PortError> {
        Ok(())
    }

    async fn remove_txt(&self, _name: &str, _value: &str) -> Result<(), PortError> {
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MemoryMetricsCollector;

impl MetricsCollector for MemoryMetricsCollector {
    fn increment(&self, _name: &'static str) {}
}

#[cfg(any(feature = "server", feature = "postgres"))]
#[derive(Clone, Default)]
pub struct MemoryStatusListHistory {
    values: Arc<RwLock<HashMap<String, StatusListHistoryRecord>>>,
}

#[cfg(any(feature = "server", feature = "postgres"))]
#[async_trait]
impl StatusListHistoryRepository for MemoryStatusListHistory {
    async fn insert(&self, record: StatusListHistoryRecord) -> Result<(), PortError> {
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
    ) -> Result<Option<StatusListHistoryRecord>, PortError> {
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
        domain::{Issuer, StatusList, StatusListRecord},
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

    #[cfg(any(feature = "server", feature = "postgres"))]
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
}
