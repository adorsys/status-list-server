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
use crate::domain::StatusListSnapshot;
#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
use crate::ports::StatusListHistoryRepository;
use crate::{
    domain::{Credential, DomainError, Issuer, StatusEntry, StatusList, StatusListRecord},
    ports::{CredentialRepository, PortError, StatusListCache, StatusListRepository},
};

fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Maps a duplicate-key insert conflict to `AlreadyExists` (racing publish →
/// 409, same outcome as the pre-check), leaving `Conflict` for the
/// optimistic-concurrency update race.
fn map_insert_conflict(error: PortError) -> UseCaseError {
    match error {
        PortError::Conflict { .. } => UseCaseError::AlreadyExists,
        other => UseCaseError::Port(other),
    }
}

/// Computes the next `updated_at` for an optimistic-concurrency write.
///
/// `updated_at` is unix seconds, so two writers in the same second read the
/// same `previous` and both see `now == previous`. `.max(previous + 1)` forces
/// the stamp to strictly increase so the loser's `WHERE updated_at = previous`
/// guard misses; dropping the `+ 1` reintroduces the same-second lost update.
pub fn next_updated_at(previous: i64, now: i64) -> i64 {
    now.max(previous + 1)
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
    #[error("the status list was modified concurrently")]
    Conflict,
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
        self.repository
            .insert(credential)
            .await
            .map_err(map_insert_conflict)?;
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
    max_serialized_list_size: usize,
}

impl<R: StatusListRepository + ?Sized> PublishStatusList<R> {
    pub fn new(repository: Arc<R>) -> Self {
        Self {
            repository,
            max_serialized_list_size: usize::MAX,
        }
    }

    pub fn with_max_serialized_list_size(mut self, max_serialized_list_size: usize) -> Self {
        self.max_serialized_list_size = max_serialized_list_size;
        self
    }

    pub async fn execute(&self, record: StatusListRecord) -> Result<(), UseCaseError> {
        if record.status_list.lst.len() > self.max_serialized_list_size {
            return Err(UseCaseError::StatusListTooLarge);
        }
        if self.repository.find(&record.list_id).await?.is_some() {
            return Err(UseCaseError::AlreadyExists);
        }
        self.repository
            .insert(record)
            .await
            .map_err(map_insert_conflict)?;
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
/// Builds the point-in-time snapshot for `record`. `iat` reuses
/// `record.updated_at` rather than re-reading the clock, so the write and its
/// snapshot share one `now` and cannot drift apart (C4).
fn build_snapshot(record: &StatusListRecord, token_exp_secs: u64) -> StatusListSnapshot {
    let iat = record.updated_at;
    StatusListSnapshot {
        snapshot_id: uuid::Uuid::new_v4().to_string(),
        list_id: record.list_id.clone(),
        issuer: record.issuer.clone(),
        status_list: record.status_list.clone(),
        sub: record.sub.clone(),
        iat,
        exp: iat + token_exp_secs as i64,
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
    history
        .insert(build_snapshot(record, token_exp_secs))
        .await
        .map_err(UseCaseError::Port)
}

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
pub struct PublishStatusListWithHistory<R: ?Sized, H: ?Sized> {
    repository: Arc<R>,
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
impl<R: StatusListRepository + ?Sized, H: StatusListHistoryRepository + ?Sized>
    PublishStatusListWithHistory<R, H>
{
    pub fn new(repository: Arc<R>, history: Arc<H>, token_exp_secs: u64) -> Self {
        Self {
            repository,
            history: Some(history),
            token_exp_secs,
            max_serialized_list_size: usize::MAX,
        }
    }

    pub fn without_history(repository: Arc<R>, token_exp_secs: u64) -> Self {
        Self {
            repository,
            history: None,
            token_exp_secs,
            max_serialized_list_size: usize::MAX,
        }
    }

    pub fn with_max_serialized_list_size(mut self, max_serialized_list_size: usize) -> Self {
        self.max_serialized_list_size = max_serialized_list_size;
        self
    }

    pub async fn execute(&self, record: StatusListRecord) -> Result<(), UseCaseError> {
        // Reuse the single publish core (size guard, existence check, guarded
        // insert), then record the snapshot on top.
        PublishStatusList::new(self.repository.clone())
            .with_max_serialized_list_size(self.max_serialized_list_size)
            .execute(record.clone())
            .await?;

        if let Some(history) = &self.history {
            persist_snapshot(history.as_ref(), &record, self.token_exp_secs).await?;
        }

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
        // Delegate to the publish use case so the size limit lives there, not in
        // this facade, and applies to every inbound adapter.
        let publisher = match &self.history {
            Some(history) => PublishStatusListWithHistory::new(
                self.repository.clone(),
                history.clone(),
                self.token_exp_secs,
            ),
            None => PublishStatusListWithHistory::without_history(
                self.repository.clone(),
                self.token_exp_secs,
            ),
        };
        publisher
            .with_max_serialized_list_size(self.max_serialized_list_size)
            .execute_new(list_id, issuer, sub, statuses)
            .await
    }

    async fn update_statuses(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
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
            .with_max_serialized_list_size(self.max_serialized_list_size)
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
            .ok_or(UseCaseError::NotFound)?
            .as_ref()
            .clone();
        if &existing.issuer != issuer {
            return Err(UseCaseError::IssuerMismatch);
        }
        existing.status_list = existing.status_list.update(statuses)?;
        if existing.status_list.lst.len() > self.max_serialized_list_size {
            return Err(UseCaseError::StatusListTooLarge);
        }
        // Optimistic guard: the write below lands only if `updated_at` is still
        // this value, so a racing writer that moved it is rejected.
        let previous_updated_at = existing.updated_at;
        existing.updated_at = next_updated_at(previous_updated_at, current_unix_timestamp());
        if !self
            .repository
            .update(existing.clone(), previous_updated_at)
            .await?
        {
            return Err(UseCaseError::Conflict);
        }
        invalidate_after_commit(self.cache.as_ref(), &existing.list_id).await;
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
            .ok_or(UseCaseError::NotFound)?
            .as_ref()
            .clone();
        if &existing.issuer != issuer {
            return Err(UseCaseError::IssuerMismatch);
        }
        existing.status_list = existing.status_list.update(statuses)?;
        if existing.status_list.lst.len() > self.max_serialized_list_size {
            return Err(UseCaseError::StatusListTooLarge);
        }
        // Optimistic guard; see the non-history path.
        let previous_updated_at = existing.updated_at;
        existing.updated_at = next_updated_at(previous_updated_at, current_unix_timestamp());

        // With history, the row update and its snapshot must commit or fail as a
        // unit (`update_with_snapshot` wraps both in one transaction) so a
        // committed row can never lack the snapshot recording it. Without
        // history there is no snapshot, so the plain guarded update suffices.
        let landed = match &self.history {
            Some(_) => {
                let snapshot = build_snapshot(&existing, token_exp_secs);
                self.repository
                    .update_with_snapshot(existing.clone(), previous_updated_at, snapshot)
                    .await?
            }
            None => {
                self.repository
                    .update(existing.clone(), previous_updated_at)
                    .await?
            }
        };
        if !landed {
            return Err(UseCaseError::Conflict);
        }

        invalidate_after_commit(self.cache.as_ref(), &existing.list_id).await;
        Ok(())
    }
}

/// Invalidates the cache after a durable write has committed. Deliberately does
/// not fail the operation: the write is already durable and a stale entry
/// self-heals at the TTL, whereas erroring here would misreport a committed
/// write as 500 and make the client retry into a 409 against the new stamp.
async fn invalidate_after_commit<C: StatusListCache + ?Sized>(cache: &C, list_id: &str) {
    if let Err(_error) = cache.invalidate(list_id).await {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            list_id = %list_id,
            error = ?_error,
            "status list write committed, but cache invalidation failed; \
             reads may be stale until the cache entry expires"
        );
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
            return Ok(record.as_ref().clone());
        }
        let record = self
            .repository
            .find(list_id)
            .await?
            .ok_or(UseCaseError::NotFound)?;
        self.cache.put(record.as_ref().clone()).await?;
        Ok(record.as_ref().clone())
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;
    use crate::{
        adapters::memory::{MemoryStatusListHistory, MemoryStatusLists},
        test_utils::test_status_list_record,
    };
    use std::sync::Arc;

    /// A snapshot's `iat` must mirror the row's `updated_at`, not the wall
    /// clock — that keeps `Last-Modified` and the §8.4 lookup key (`iat`)
    /// consistent and per-list snapshot ordering strict.
    #[tokio::test]
    async fn test_snapshot_iat_mirrors_record_updated_at() {
        let history = Arc::new(MemoryStatusListHistory::default());
        let token_exp_secs = 900u64;
        let publish = PublishStatusListWithHistory::new(
            Arc::new(MemoryStatusLists::default()),
            history.clone(),
            token_exp_secs,
        );

        let mut record = test_status_list_record("issuer", "list-iat");
        // A stamp the clock would never produce right now, in either direction.
        record.updated_at = 4_102_444_800; // 2100-01-01

        publish.execute(record.clone()).await.unwrap();

        let snapshot = history
            .find_valid_at("list-iat", record.updated_at)
            .await
            .unwrap()
            .expect("snapshot was persisted");
        assert_eq!(snapshot.iat, record.updated_at);
        assert_eq!(snapshot.exp, record.updated_at + token_exp_secs as i64);
    }
}
