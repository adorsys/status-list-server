use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use crate::domain::models::credential::{Credential, CredentialError};
use crate::domain::models::status_list::{StatusListError, StatusListRecord, StatusListSnapshot};
use crate::domain::ports::{
    CredentialRepo, StatusListCache, StatusListHistoryRepo, StatusListRepo,
};

#[derive(Clone, Default)]
pub struct MemoryStatusLists {
    values: Arc<RwLock<HashMap<String, StatusListRecord>>>,
    history: Option<Arc<RwLock<HashMap<String, StatusListSnapshot>>>>,
}

impl MemoryStatusLists {
    pub fn with_history(mut self, history: &MemoryStatusListHistory) -> Self {
        self.history = Some(history.values.clone());
        self
    }

    fn require_history(
        &self,
    ) -> Result<&Arc<RwLock<HashMap<String, StatusListSnapshot>>>, StatusListError> {
        self.history.as_ref().ok_or_else(|| {
            StatusListError::Backend(
                "MemoryStatusLists was built without shared history storage; construct it with `.with_history(..)`"
                    .into(),
            )
        })
    }
}

#[async_trait]
impl StatusListRepo for MemoryStatusLists {
    async fn find(&self, id: &str) -> Result<Option<Arc<StatusListRecord>>, StatusListError> {
        Ok(self.values.read().await.get(id).cloned().map(Arc::new))
    }

    async fn insert(&self, record: StatusListRecord) -> Result<(), StatusListError> {
        self.values
            .write()
            .await
            .insert(record.list_id.clone(), record);
        Ok(())
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
        let history = self.require_history()?;
        let mut values = self.values.write().await;
        match values.get(&record.list_id) {
            Some(current) if current.updated_at == expected_updated_at => {}
            _ => return Ok(false),
        }
        history
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
        let history = self.require_history()?;
        let mut values = self.values.write().await;
        history
            .write()
            .await
            .insert(snapshot.snapshot_id.clone(), snapshot);
        values.insert(record.list_id.clone(), record);
        Ok(())
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
    async fn get(&self, id: &str) -> Result<Option<Arc<StatusListRecord>>, StatusListError> {
        Ok(self.values.read().await.get(id).cloned().map(Arc::new))
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
        self.values
            .write()
            .await
            .insert(credential.issuer.0.clone(), credential);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MemoryStatusListHistory {
    values: Arc<RwLock<HashMap<String, StatusListSnapshot>>>,
}

#[async_trait]
impl StatusListHistoryRepo for MemoryStatusListHistory {
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
        let values = self.values.read().await;
        let result = values
            .values()
            .filter(|r| r.list_id == list_id && r.iat <= time && r.exp > time)
            .max_by_key(|r| r.iat)
            .cloned();
        Ok(result)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::domain::service::Service;

    struct DummyCertProvider;
    #[async_trait]
    impl crate::domain::ports::CertificateProvider for DummyCertProvider {
        async fn certificate_chain(&self) -> Result<Option<Vec<String>>, StatusListError> {
            Ok(None)
        }
        async fn signing_key_pem(&self) -> Result<String, StatusListError> {
            Ok("".into())
        }
    }

    fn create_test_service(
        repo: MemoryStatusLists,
        cache: MemoryStatusListCache,
        history: Option<Arc<dyn StatusListHistoryRepo>>,
    ) -> Service {
        let creds = MemoryCredentials::default();
        let cert_provider = DummyCertProvider;
        Service::new(repo, creds, cache, history, cert_provider)
    }

    #[tokio::test]
    async fn domain_service_works_without_infrastructure() {
        let repo = MemoryStatusLists::default();
        let cache = MemoryStatusListCache::default();
        let service = create_test_service(repo, cache, None);

        StatusListRecord::publish(
            service.status_list_repo(),
            service.history_repo(),
            "id".into(),
            Issuer("issuer".into()),
            "https://example/id".into(),
            Vec::new(),
            900,
            usize::MAX,
        )
        .await
        .unwrap();

        assert!(matches!(
            StatusListRecord::publish(
                service.status_list_repo(),
                service.history_repo(),
                "id".into(),
                Issuer("issuer".into()),
                "https://example/id".into(),
                Vec::new(),
                900,
                usize::MAX,
            )
            .await,
            Err(StatusListError::AlreadyExists)
        ));

        let fetched = StatusListRecord::get(
            service.status_list_repo(),
            service.status_list_cache(),
            "id",
        )
        .await
        .unwrap();
        assert_eq!(fetched.list_id, "id");
    }

    #[tokio::test]
    async fn update_statuses_rejects_wrong_issuer() {
        let repo = MemoryStatusLists::default();
        let cache = MemoryStatusListCache::default();
        let service = create_test_service(repo, cache, None);

        StatusListRecord::publish(
            service.status_list_repo(),
            service.history_repo(),
            "id".into(),
            Issuer("issuer".into()),
            "https://example/id".into(),
            Vec::new(),
            900,
            usize::MAX,
        )
        .await
        .unwrap();

        let result = StatusListRecord::update_statuses(
            service.status_list_repo(),
            service.status_list_cache(),
            service.history_repo(),
            &Issuer("other-issuer".into()),
            "id",
            Vec::new(),
            900,
            10000,
            1000,
            usize::MAX,
        )
        .await;

        assert!(matches!(result, Err(StatusListError::IssuerMismatch)));
    }
}
