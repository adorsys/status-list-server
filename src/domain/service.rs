//! Service container holding injected outbound adapter ports and domain business operations.

use std::sync::Arc;

use crate::domain::models::credential::{Credential, CredentialError, Issuer};
use crate::domain::models::status_list::{
    StatusEntry, StatusList, StatusListError, StatusListRecord, StatusListSnapshot,
};
use crate::domain::ports::{
    CertificateProvider, CredentialRepo, StatusListCache, StatusListHistoryRepo, StatusListRepo,
};

/// Container struct for building and exposing external service ports injected into handlers.
#[derive(Clone)]
pub struct Service {
    pub(crate) status_list_repo: Arc<dyn StatusListRepo>,
    pub(crate) credential_repo: Arc<dyn CredentialRepo>,
    pub(crate) status_list_cache: Arc<dyn StatusListCache>,
    pub(crate) history_repo: Option<Arc<dyn StatusListHistoryRepo>>,
    pub(crate) cert_provider: Arc<dyn CertificateProvider>,
}

impl Service {
    pub fn from_arcs(
        status_list_repo: Arc<dyn StatusListRepo>,
        credential_repo: Arc<dyn CredentialRepo>,
        status_list_cache: Arc<dyn StatusListCache>,
        history_repo: Option<Arc<dyn StatusListHistoryRepo>>,
        cert_provider: Arc<dyn CertificateProvider>,
    ) -> Self {
        Self {
            status_list_repo,
            credential_repo,
            status_list_cache,
            history_repo,
            cert_provider,
        }
    }

    pub fn new<S, C, SC, CP>(
        status_list_repo: S,
        credential_repo: C,
        status_list_cache: SC,
        history_repo: Option<Arc<dyn StatusListHistoryRepo>>,
        cert_provider: CP,
    ) -> Self
    where
        S: StatusListRepo,
        C: CredentialRepo,
        SC: StatusListCache,
        CP: CertificateProvider,
    {
        Self {
            status_list_repo: Arc::new(status_list_repo),
            credential_repo: Arc::new(credential_repo),
            status_list_cache: Arc::new(status_list_cache),
            history_repo,
            cert_provider: Arc::new(cert_provider),
        }
    }

    pub fn status_list_repo(&self) -> &dyn StatusListRepo {
        self.status_list_repo.as_ref()
    }

    pub fn credential_repo(&self) -> &dyn CredentialRepo {
        self.credential_repo.as_ref()
    }

    pub fn status_list_cache(&self) -> &dyn StatusListCache {
        self.status_list_cache.as_ref()
    }

    pub fn history_repo(&self) -> Option<&dyn StatusListHistoryRepo> {
        self.history_repo.as_deref()
    }

    pub fn cert_provider(&self) -> &dyn CertificateProvider {
        self.cert_provider.as_ref()
    }

    /// Create and publish a new status list record, enforcing uniqueness and size invariants.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish_status_list(
        &self,
        list_id: String,
        issuer: Issuer,
        sub: String,
        statuses: Vec<StatusEntry>,
        token_exp_secs: u64,
        max_status_index: i32,
        max_statuses_per_request: usize,
        max_serialized_list_size: usize,
    ) -> Result<StatusListRecord, StatusListError> {
        if statuses.len() > max_statuses_per_request {
            return Err(StatusListError::TooManyStatuses {
                count: statuses.len(),
                max: max_statuses_per_request,
            });
        }
        for entry in &statuses {
            if entry.index > max_status_index {
                return Err(StatusListError::IndexTooLarge {
                    index: entry.index,
                    max: max_status_index,
                });
            }
        }

        let record = StatusListRecord {
            list_id,
            issuer,
            status_list: StatusList::create(statuses)?,
            sub,
            updated_at: current_unix_timestamp(),
        };

        if record.status_list.lst.len() > max_serialized_list_size {
            return Err(StatusListError::TooLarge);
        }
        if self.status_list_repo.find(&record.list_id).await?.is_some() {
            return Err(StatusListError::AlreadyExists);
        }

        match &self.history_repo {
            Some(_) => {
                let snapshot = build_snapshot(&record, token_exp_secs);
                self.status_list_repo
                    .insert_with_snapshot(record.clone(), snapshot)
                    .await?;
            }
            None => {
                self.status_list_repo.insert(record.clone()).await?;
            }
        }
        Ok(record)
    }

    /// Mutate statuses in an existing status list record with optimistic concurrency checks and cache invalidation.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_statuses(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
        token_exp_secs: u64,
        max_status_index: i32,
        max_statuses_per_request: usize,
        max_serialized_list_size: usize,
    ) -> Result<StatusListRecord, StatusListError> {
        if statuses.len() > max_statuses_per_request {
            return Err(StatusListError::TooManyStatuses {
                count: statuses.len(),
                max: max_statuses_per_request,
            });
        }
        for entry in &statuses {
            if entry.index > max_status_index {
                return Err(StatusListError::IndexTooLarge {
                    index: entry.index,
                    max: max_status_index,
                });
            }
        }

        let mut existing = self
            .status_list_repo
            .find(list_id)
            .await?
            .ok_or(StatusListError::NotFound)?;

        if &existing.issuer != issuer {
            return Err(StatusListError::IssuerMismatch);
        }

        existing.status_list = existing.status_list.update(statuses)?;
        if existing.status_list.lst.len() > max_serialized_list_size {
            return Err(StatusListError::TooLarge);
        }

        let previous_updated_at = existing.updated_at;
        existing.updated_at = next_updated_at(previous_updated_at, current_unix_timestamp());

        let landed = match &self.history_repo {
            Some(_) => {
                let snapshot = build_snapshot(&existing, token_exp_secs);
                self.status_list_repo
                    .update_with_snapshot(existing.clone(), previous_updated_at, snapshot)
                    .await?
            }
            None => {
                self.status_list_repo
                    .update(existing.clone(), previous_updated_at)
                    .await?
            }
        };

        if !landed {
            return Err(StatusListError::Conflict);
        }

        invalidate_after_commit(self.status_list_cache.as_ref(), &existing.list_id).await;
        Ok(existing)
    }

    /// Retrieve a status list record from cache or fallback to persistent storage.
    pub async fn get_status_list(
        &self,
        list_id: &str,
    ) -> Result<StatusListRecord, StatusListError> {
        match self.status_list_cache.get(list_id).await {
            Ok(Some(record)) => return Ok(record.as_ref().clone()),
            Ok(None) => {}
            Err(e) => tracing::warn!("Cache get failed for list {list_id}: {e}"),
        }
        let record = self
            .status_list_repo
            .find(list_id)
            .await?
            .ok_or(StatusListError::NotFound)?;
        if let Err(e) = self.status_list_cache.put(record.clone()).await {
            tracing::warn!("Cache put failed for list {list_id}: {e}");
        }
        Ok(record)
    }

    /// List all published status list URIs.
    pub async fn list_uris(&self) -> Result<Vec<String>, StatusListError> {
        self.status_list_repo.list_uris().await
    }

    /// Retrieve a historical status list snapshot active at a specific Unix timestamp.
    pub async fn get_historical_snapshot(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<StatusListSnapshot, StatusListError> {
        self.history_repo
            .as_ref()
            .ok_or(StatusListError::NotFound)?
            .find_valid_at(list_id, time)
            .await?
            .ok_or(StatusListError::HistoricalNotFound)
    }

    /// Purge historical snapshots older than `cutoff` timestamp.
    pub async fn cleanup_historical_snapshots(&self, cutoff: i64) -> Result<u64, StatusListError> {
        let Some(history) = &self.history_repo else {
            return Ok(0);
        };
        history.delete_older_than(cutoff).await
    }

    /// Publish new credentials for an issuer after verifying uniqueness invariant.
    pub async fn publish_credential(&self, credential: Credential) -> Result<(), CredentialError> {
        if self
            .credential_repo
            .find(&credential.issuer.0)
            .await?
            .is_some()
        {
            return Err(CredentialError::AlreadyExists);
        }
        self.credential_repo.insert(credential).await
    }

    /// Retrieve credentials by issuer identifier.
    pub async fn find_credential(
        &self,
        issuer: &str,
    ) -> Result<Option<Credential>, CredentialError> {
        self.credential_repo.find(issuer).await
    }
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field(
                "status_list_repo",
                &std::any::type_name::<dyn StatusListRepo>(),
            )
            .field(
                "credential_repo",
                &std::any::type_name::<dyn CredentialRepo>(),
            )
            .field(
                "status_list_cache",
                &std::any::type_name::<dyn StatusListCache>(),
            )
            .field(
                "history_repo",
                &std::any::type_name::<dyn StatusListHistoryRepo>(),
            )
            .field(
                "cert_provider",
                &std::any::type_name::<dyn CertificateProvider>(),
            )
            .finish()
    }
}

pub fn current_unix_timestamp() -> i64 {
    time::UtcDateTime::now().unix_timestamp()
}

pub fn next_updated_at(previous: i64, now: i64) -> i64 {
    now.max(previous + 1)
}

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

async fn invalidate_after_commit(cache: &dyn StatusListCache, list_id: &str) {
    if let Err(error) = cache.invalidate(list_id).await {
        tracing::warn!(
            list_id = %list_id,
            error = ?error,
            "status list write committed, but cache invalidation failed; \
             reads may be stale until the cache entry expires"
        );
    }
}
