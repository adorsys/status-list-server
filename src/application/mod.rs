//! Inbound use cases. They are generic over outbound ports and can therefore
//! be unit-tested with the memory adapters.
use std::sync::Arc;

use async_trait::async_trait;

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
use crate::ports::StatusListHistoryRepository;
use crate::{
    domain::{
        Credential, DomainError, Issuer, StatusEntry, StatusList, StatusListRecord,
        StatusListSnapshot,
    },
    ports::{CredentialRepository, PortError, StatusListCache, StatusListRepository},
};

fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Debug, thiserror::Error)]
pub enum UseCaseError {
    #[error("status list already exists")]
    AlreadyExists,
    #[error("status list was not found")]
    NotFound,
    #[error("issuer does not own the status list")]
    IssuerMismatch,
    #[error("serialized status list exceeds configured maximum")]
    StatusListTooLarge,
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

    async fn update_statuses_with_max_serialized_list_size(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
        max_serialized_list_size: usize,
    ) -> Result<(), UseCaseError>;

    async fn get_status_list(&self, list_id: &str) -> Result<StatusListRecord, UseCaseError>;

    async fn list_status_list_uris(&self) -> Result<Vec<String>, UseCaseError>;

    /// Get a historical snapshot valid at the given time (draft-21 §8.4).
    #[cfg(any(
        feature = "server",
        feature = "postgres",
        feature = "sqlite",
        feature = "mysql"
    ))]
    async fn get_historical_status_list(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<StatusListSnapshot, UseCaseError>;

    /// Delete historical snapshots older than the cutoff.
    #[cfg(any(
        feature = "server",
        feature = "postgres",
        feature = "sqlite",
        feature = "mysql"
    ))]
    async fn cleanup_history(&self, cutoff: i64) -> Result<u64, UseCaseError>;
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
            updated_at: current_unix_timestamp(),
        };
        self.execute(record).await
    }
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
async fn persist_snapshot<H: StatusListHistoryRepository + ?Sized>(
    history: &H,
    record: &StatusListRecord,
    token_exp_secs: u64,
) -> Result<(), UseCaseError> {
    let iat = time::OffsetDateTime::now_utc().unix_timestamp();
    let snapshot = StatusListSnapshot {
        snapshot_id: uuid::Uuid::new_v4().to_string(),
        list_id: record.list_id.clone(),
        issuer: record.issuer.clone(),
        status_list: record.status_list.clone(),
        sub: record.sub.clone(),
        iat,
        exp: iat + token_exp_secs as i64,
    };
    history.insert(snapshot).await.map_err(UseCaseError::Port)
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
pub struct PublishStatusListWithHistory<R: ?Sized, H: ?Sized> {
    repository: Arc<R>,
    history: Arc<H>,
    token_exp_secs: u64,
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
impl<R: StatusListRepository + ?Sized, H: StatusListHistoryRepository + ?Sized>
    PublishStatusListWithHistory<R, H>
{
    pub fn new(repository: Arc<R>, history: Arc<H>, token_exp_secs: u64) -> Self {
        Self {
            repository,
            history,
            token_exp_secs,
        }
    }

    pub async fn execute(&self, record: StatusListRecord) -> Result<(), UseCaseError> {
        if self.repository.find(&record.list_id).await?.is_some() {
            return Err(UseCaseError::AlreadyExists);
        }
        self.repository.insert(record.clone()).await?;

        persist_snapshot(self.history.as_ref(), &record, self.token_exp_secs).await?;

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
            updated_at: current_unix_timestamp(),
        };
        self.execute(record).await
    }
}

pub struct StatusListApplicationService<R: ?Sized, C: ?Sized> {
    repository: Arc<R>,
    cache: Arc<C>,
    max_serialized_list_size: usize,
}

impl<R: StatusListRepository + ?Sized, C: StatusListCache + ?Sized>
    StatusListApplicationService<R, C>
{
    pub fn new(repository: Arc<R>, cache: Arc<C>) -> Self {
        Self {
            repository,
            cache,
            max_serialized_list_size: usize::MAX,
        }
    }

    pub fn with_max_serialized_list_size(mut self, max_serialized_list_size: usize) -> Self {
        self.max_serialized_list_size = max_serialized_list_size;
        self
    }
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
pub struct StatusListApplicationServiceWithHistory<R: ?Sized, C: ?Sized, H: ?Sized> {
    repository: Arc<R>,
    cache: Arc<C>,
    history: Option<Arc<H>>,
    token_exp_secs: u64,
    max_serialized_list_size: usize,
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
impl<
    R: StatusListRepository + ?Sized,
    C: StatusListCache + ?Sized,
    H: StatusListHistoryRepository + ?Sized,
> StatusListApplicationServiceWithHistory<R, C, H>
{
    pub fn new(repository: Arc<R>, cache: Arc<C>, history: Arc<H>, token_exp_secs: u64) -> Self {
        Self {
            repository,
            cache,
            history: Some(history),
            token_exp_secs,
            max_serialized_list_size: usize::MAX,
        }
    }

    pub fn without_history(repository: Arc<R>, cache: Arc<C>, token_exp_secs: u64) -> Self {
        Self {
            repository,
            cache,
            history: None,
            token_exp_secs,
            max_serialized_list_size: usize::MAX,
        }
    }

    pub fn with_max_serialized_list_size(mut self, max_serialized_list_size: usize) -> Self {
        self.max_serialized_list_size = max_serialized_list_size;
        self
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
        self.update_statuses_with_max_serialized_list_size(
            issuer,
            list_id,
            statuses,
            self.max_serialized_list_size,
        )
        .await
    }

    async fn update_statuses_with_max_serialized_list_size(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
        max_serialized_list_size: usize,
    ) -> Result<(), UseCaseError> {
        UpdateStatuses::new(self.repository.clone(), self.cache.clone())
            .with_max_serialized_list_size(max_serialized_list_size)
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

    #[cfg(any(
        feature = "server",
        feature = "postgres",
        feature = "sqlite",
        feature = "mysql"
    ))]
    async fn get_historical_status_list(
        &self,
        _list_id: &str,
        _time: i64,
    ) -> Result<StatusListSnapshot, UseCaseError> {
        Err(UseCaseError::NotFound)
    }

    #[cfg(any(
        feature = "server",
        feature = "postgres",
        feature = "sqlite",
        feature = "mysql"
    ))]
    async fn cleanup_history(&self, _cutoff: i64) -> Result<u64, UseCaseError> {
        Ok(0)
    }
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
#[async_trait]
impl<
    R: StatusListRepository + ?Sized,
    C: StatusListCache + ?Sized,
    H: StatusListHistoryRepository + ?Sized,
> StatusListService for StatusListApplicationServiceWithHistory<R, C, H>
{
    async fn publish_status_list(
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
            updated_at: current_unix_timestamp(),
        };
        if self.repository.find(&record.list_id).await?.is_some() {
            return Err(UseCaseError::AlreadyExists);
        }
        self.repository.insert(record.clone()).await?;
        if let Some(history) = &self.history {
            persist_snapshot(history.as_ref(), &record, self.token_exp_secs).await?;
        }
        Ok(())
    }

    async fn update_statuses(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
    ) -> Result<(), UseCaseError> {
        self.update_statuses_with_max_serialized_list_size(
            issuer,
            list_id,
            statuses,
            self.max_serialized_list_size,
        )
        .await
    }

    async fn update_statuses_with_max_serialized_list_size(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
        max_serialized_list_size: usize,
    ) -> Result<(), UseCaseError> {
        let updater = match &self.history {
            Some(history) => UpdateStatusesWithHistory::new(
                self.repository.clone(),
                self.cache.clone(),
                history.clone(),
            ),
            None => UpdateStatusesWithHistory::without_history(
                self.repository.clone(),
                self.cache.clone(),
            ),
        };
        updater
            .with_max_serialized_list_size(max_serialized_list_size)
            .execute(issuer, list_id, statuses, self.token_exp_secs)
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

    async fn get_historical_status_list(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<StatusListSnapshot, UseCaseError> {
        self.history
            .as_ref()
            .ok_or(UseCaseError::NotFound)?
            .find_valid_at(list_id, time)
            .await
            .map_err(UseCaseError::Port)?
            .ok_or(UseCaseError::NotFound)
    }

    async fn cleanup_history(&self, cutoff: i64) -> Result<u64, UseCaseError> {
        let Some(history) = &self.history else {
            return Ok(0);
        };
        history
            .delete_older_than(cutoff)
            .await
            .map_err(UseCaseError::Port)
    }
}

pub struct UpdateStatuses<R: ?Sized, C: ?Sized> {
    repository: Arc<R>,
    cache: Arc<C>,
    max_serialized_list_size: usize,
}

impl<R: StatusListRepository + ?Sized, C: StatusListCache + ?Sized> UpdateStatuses<R, C> {
    pub fn new(repository: Arc<R>, cache: Arc<C>) -> Self {
        Self {
            repository,
            cache,
            max_serialized_list_size: usize::MAX,
        }
    }

    pub fn with_max_serialized_list_size(mut self, max_serialized_list_size: usize) -> Self {
        self.max_serialized_list_size = max_serialized_list_size;
        self
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
        if existing.status_list.lst.len() > self.max_serialized_list_size {
            return Err(UseCaseError::StatusListTooLarge);
        }
        existing.updated_at = current_unix_timestamp();
        if !self.repository.update(existing.clone()).await? {
            return Err(UseCaseError::NotFound);
        }
        self.cache.invalidate(&existing.list_id).await?;
        Ok(())
    }
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
pub struct UpdateStatusesWithHistory<R: ?Sized, C: ?Sized, H: ?Sized> {
    repository: Arc<R>,
    cache: Arc<C>,
    history: Option<Arc<H>>,
    max_serialized_list_size: usize,
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
impl<
    R: StatusListRepository + ?Sized,
    C: StatusListCache + ?Sized,
    H: StatusListHistoryRepository + ?Sized,
> UpdateStatusesWithHistory<R, C, H>
{
    pub fn new(repository: Arc<R>, cache: Arc<C>, history: Arc<H>) -> Self {
        Self {
            repository,
            cache,
            history: Some(history),
            max_serialized_list_size: usize::MAX,
        }
    }

    pub fn without_history(repository: Arc<R>, cache: Arc<C>) -> Self {
        Self {
            repository,
            cache,
            history: None,
            max_serialized_list_size: usize::MAX,
        }
    }

    pub fn with_max_serialized_list_size(mut self, max_serialized_list_size: usize) -> Self {
        self.max_serialized_list_size = max_serialized_list_size;
        self
    }

    pub async fn execute(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
        token_exp_secs: u64,
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
        if existing.status_list.lst.len() > self.max_serialized_list_size {
            return Err(UseCaseError::StatusListTooLarge);
        }
        existing.updated_at = current_unix_timestamp();
        if !self.repository.update(existing.clone()).await? {
            return Err(UseCaseError::NotFound);
        }
        self.cache.invalidate(&existing.list_id).await?;

        if let Some(history) = &self.history {
            persist_snapshot(history.as_ref(), &existing, token_exp_secs).await?;
        }

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
