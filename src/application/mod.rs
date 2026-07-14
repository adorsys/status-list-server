//! Inbound use cases. They are generic over outbound ports and can therefore
//! be unit-tested with the memory adapters.
use std::sync::Arc;

use crate::{
    domain::{Issuer, StatusListRecord},
    ports::{PortError, StatusListCache, StatusListRepository},
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
    Port(#[from] PortError),
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
        record: StatusListRecord,
    ) -> Result<(), UseCaseError> {
        let existing = self
            .repository
            .find(&record.list_id)
            .await?
            .ok_or(UseCaseError::NotFound)?;
        if &existing.issuer != issuer {
            return Err(UseCaseError::IssuerMismatch);
        }
        self.repository.update(record.clone()).await?;
        self.cache.invalidate(&record.list_id).await?;
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
