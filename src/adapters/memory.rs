//! In-memory adapters for application-service unit tests and memory-only use.
use crate::{
    domain::StatusListRecord,
    ports::{PortError, StatusListCache, StatusListRepository},
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
            .execute(&Issuer("issuer".into()), record())
            .await
            .unwrap();
        assert!(cache.get("id").await.unwrap().is_none());
    }
}
