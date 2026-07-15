//! Inbound use cases. They are generic over outbound ports and can therefore
//! be unit-tested with the memory adapters.
use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    domain::{Credential, DomainError, Issuer, StatusEntry, StatusList, StatusListRecord},
    ports::{CredentialRepository, PortError, StatusListCache, StatusListRepository},
};

#[derive(Debug, thiserror::Error)]
pub enum UseCaseError {
    #[error("status list already exists")]
    AlreadyExists,
    #[error("status list was not found")]
    NotFound,
    #[error("issuer does not own the status list")]
    IssuerMismatch,
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Port(#[from] PortError),
}

#[async_trait]
pub trait CredentialService: Send + Sync {
    async fn publish_credential(&self, credential: Credential) -> Result<(), UseCaseError>;
    async fn find_credential(&self, issuer: &str) -> Result<Option<Credential>, UseCaseError>;
}

#[async_trait]
pub trait StatusListService: Send + Sync {
    async fn publish_status_list(
        &self,
        list_id: String,
        issuer: Issuer,
        sub: String,
        statuses: Vec<StatusEntry>,
    ) -> Result<(), UseCaseError>;

    async fn update_statuses(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
    ) -> Result<(), UseCaseError>;

    async fn get_status_list(&self, list_id: &str) -> Result<StatusListRecord, UseCaseError>;

    async fn list_status_list_uris(&self) -> Result<Vec<String>, UseCaseError>;
}

pub struct PublishCredential<R: ?Sized> {
    repository: Arc<R>,
}
impl<R: CredentialRepository + ?Sized> PublishCredential<R> {
    pub fn new(repository: Arc<R>) -> Self {
        Self { repository }
    }
    pub async fn execute(&self, credential: Credential) -> Result<(), UseCaseError> {
        if self.repository.find(&credential.issuer.0).await?.is_some() {
            return Err(UseCaseError::AlreadyExists);
        }
        self.repository.insert(credential).await?;
        Ok(())
    }
}

pub struct CredentialApplicationService<R: ?Sized> {
    repository: Arc<R>,
}

impl<R: CredentialRepository + ?Sized> CredentialApplicationService<R> {
    pub fn new(repository: Arc<R>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl<R: CredentialRepository + ?Sized> CredentialService for CredentialApplicationService<R> {
    async fn publish_credential(&self, credential: Credential) -> Result<(), UseCaseError> {
        PublishCredential::new(self.repository.clone())
            .execute(credential)
            .await
    }

    async fn find_credential(&self, issuer: &str) -> Result<Option<Credential>, UseCaseError> {
        Ok(self.repository.find(issuer).await?)
    }
}

pub struct PublishStatusList<R: ?Sized> {
    repository: Arc<R>,
}
impl<R: StatusListRepository + ?Sized> PublishStatusList<R> {
    pub fn new(repository: Arc<R>) -> Self {
        Self { repository }
    }
    pub async fn execute(&self, record: StatusListRecord) -> Result<(), UseCaseError> {
        if self.repository.find(&record.list_id).await?.is_some() {
            return Err(UseCaseError::AlreadyExists);
        }
        self.repository.insert(record).await?;
        Ok(())
    }

    pub async fn execute_new(
        &self,
        list_id: String,
        issuer: Issuer,
        sub: String,
        statuses: Vec<StatusEntry>,
    ) -> Result<(), UseCaseError> {
        let record = StatusListRecord {
            list_id,
            issuer,
            status_list: StatusList::create(statuses)?,
            sub,
        };
        self.execute(record).await
    }
}

pub struct StatusListApplicationService<R: ?Sized, C: ?Sized> {
    repository: Arc<R>,
    cache: Arc<C>,
}

impl<R: StatusListRepository + ?Sized, C: StatusListCache + ?Sized>
    StatusListApplicationService<R, C>
{
    pub fn new(repository: Arc<R>, cache: Arc<C>) -> Self {
        Self { repository, cache }
    }
}

#[async_trait]
impl<R: StatusListRepository + ?Sized, C: StatusListCache + ?Sized> StatusListService
    for StatusListApplicationService<R, C>
{
    async fn publish_status_list(
        &self,
        list_id: String,
        issuer: Issuer,
        sub: String,
        statuses: Vec<StatusEntry>,
    ) -> Result<(), UseCaseError> {
        PublishStatusList::new(self.repository.clone())
            .execute_new(list_id, issuer, sub, statuses)
            .await
    }

    async fn update_statuses(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
    ) -> Result<(), UseCaseError> {
        UpdateStatuses::new(self.repository.clone(), self.cache.clone())
            .execute(issuer, list_id, statuses)
            .await
    }

    async fn get_status_list(&self, list_id: &str) -> Result<StatusListRecord, UseCaseError> {
        GetStatusListToken::new(self.repository.clone(), self.cache.clone())
            .execute(list_id)
            .await
    }

    async fn list_status_list_uris(&self) -> Result<Vec<String>, UseCaseError> {
        Ok(self.repository.list_uris().await?)
    }
}

pub struct UpdateStatuses<R: ?Sized, C: ?Sized> {
    repository: Arc<R>,
    cache: Arc<C>,
}
impl<R: StatusListRepository + ?Sized, C: StatusListCache + ?Sized> UpdateStatuses<R, C> {
    pub fn new(repository: Arc<R>, cache: Arc<C>) -> Self {
        Self { repository, cache }
    }
    pub async fn execute(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
    ) -> Result<(), UseCaseError> {
        let mut existing = self
            .repository
            .find(list_id)
            .await?
            .ok_or(UseCaseError::NotFound)?;
        if &existing.issuer != issuer {
            return Err(UseCaseError::IssuerMismatch);
        }
        existing.status_list = existing.status_list.update(statuses)?;
        self.repository.update(existing.clone()).await?;
        self.cache.invalidate(&existing.list_id).await?;
        Ok(())
    }
}

pub struct GetStatusListToken<R: ?Sized, C: ?Sized> {
    repository: Arc<R>,
    cache: Arc<C>,
}
impl<R: StatusListRepository + ?Sized, C: StatusListCache + ?Sized> GetStatusListToken<R, C> {
    pub fn new(repository: Arc<R>, cache: Arc<C>) -> Self {
        Self { repository, cache }
    }
    pub async fn execute(&self, list_id: &str) -> Result<StatusListRecord, UseCaseError> {
        if let Some(record) = self.cache.get(list_id).await? {
            return Ok(record);
        }
        let record = self
            .repository
            .find(list_id)
            .await?
            .ok_or(UseCaseError::NotFound)?;
        self.cache.put(record.clone()).await?;
        Ok(record)
    }
}
