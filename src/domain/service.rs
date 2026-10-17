use std::sync::Arc;

use crate::domain::models::credential::{AggregationId, Credential, CredentialError, Issuer};
use crate::domain::models::status_list::{
    Status, StatusEntry, StatusList, StatusListError, StatusListRecord, StatusListSnapshot,
    StatusListUriPage, validate_unique_indices,
};
use crate::domain::ports::{
    AllocateStatusListIndices, CertificateProvider, CreateStatusList, CredentialRepo,
    StatusListCache, StatusListRepo, StatusListSnapshotRepo,
};

#[derive(Debug, Clone)]
pub struct StatusListPolicy {
    pub token_exp_secs: u64,
    pub max_status_index: i32,
    pub max_statuses_per_request: usize,
    pub max_serialized_list_size: usize,
    pub max_lists_per_issuer: u64,
}

#[derive(Debug, Clone)]
pub struct PublishStatusListCommand {
    pub list_id: String,
    pub issuer: Issuer,
    pub sub: String,
    pub statuses: Vec<StatusEntry>,
    pub size: Option<u32>,
    pub default_status: Option<Status>,
}

#[derive(Clone)]
pub struct Service {
    pub(crate) status_list_repo: Arc<dyn StatusListRepo>,
    pub(crate) credential_repo: Arc<dyn CredentialRepo>,
    pub(crate) status_list_cache: Arc<dyn StatusListCache>,
    pub(crate) snapshot_repo: Option<Arc<dyn StatusListSnapshotRepo>>,
    pub(crate) cert_provider: Arc<dyn CertificateProvider>,
}

impl Service {
    pub fn from_arcs(
        status_list_repo: Arc<dyn StatusListRepo>,
        credential_repo: Arc<dyn CredentialRepo>,
        status_list_cache: Arc<dyn StatusListCache>,
        snapshot_repo: Option<Arc<dyn StatusListSnapshotRepo>>,
        cert_provider: Arc<dyn CertificateProvider>,
    ) -> Self {
        Self {
            status_list_repo,
            credential_repo,
            status_list_cache,
            snapshot_repo,
            cert_provider,
        }
    }

    pub fn new<S, C, SC, CP>(
        status_list_repo: S,
        credential_repo: C,
        status_list_cache: SC,
        snapshot_repo: Option<Arc<dyn StatusListSnapshotRepo>>,
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
            snapshot_repo,
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

    pub fn snapshot_repo(&self) -> Option<&dyn StatusListSnapshotRepo> {
        self.snapshot_repo.as_deref()
    }

    pub fn cert_provider(&self) -> &dyn CertificateProvider {
        self.cert_provider.as_ref()
    }

    pub fn snapshots_enabled(&self) -> bool {
        self.snapshot_repo.is_some()
    }

    /// The repo enforces the quota inside the insert; counting here first would race.
    pub async fn publish_status_list(
        &self,
        command: PublishStatusListCommand,
        policy: &StatusListPolicy,
    ) -> Result<StatusListRecord, StatusListError> {
        validate_request_shape(
            &command.statuses,
            policy.max_status_index,
            policy.max_statuses_per_request,
        )?;
        let default_status = command.default_status.unwrap_or(Status::Valid);
        if let Some(size) = command.size {
            StatusList::validate_size_limit(
                &command.statuses,
                size,
                &default_status,
                policy.max_status_index,
            )?;
        }
        let initially_allocated = if command.size.is_some() {
            command
                .statuses
                .iter()
                .map(|entry| entry.index)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        let record = StatusListRecord {
            list_id: command.list_id,
            issuer: command.issuer,
            status_list: StatusList::create_with_options(
                command.statuses,
                command.size,
                default_status,
            )?,
            sub: command.sub,
            updated_at: current_unix_timestamp(),
            version: 1,
        };

        if record.status_list.lst.len() > policy.max_serialized_list_size {
            return Err(StatusListError::TooLarge);
        }

        let initial_snapshot = if self.snapshots_enabled() {
            Some(build_snapshot(&record, policy.token_exp_secs)?)
        } else {
            None
        };

        self.status_list_repo
            .create(CreateStatusList {
                record: record.clone(),
                initial_snapshot,
                initial_allocations: initially_allocated,
                max_lists_per_issuer: policy.max_lists_per_issuer,
            })
            .await?;

        Ok(record)
    }

    /// A request that changes nothing is a no-op: no version bump and no new snapshot.
    pub async fn update_statuses(
        &self,
        issuer: &Issuer,
        list_id: &str,
        statuses: Vec<StatusEntry>,
        policy: &StatusListPolicy,
    ) -> Result<StatusListRecord, StatusListError> {
        validate_request_shape(
            &statuses,
            policy.max_status_index,
            policy.max_statuses_per_request,
        )?;
        validate_unique_indices(&statuses)?;

        let mut existing = self
            .status_list_repo
            .find(list_id)
            .await?
            .ok_or(StatusListError::NotFound)?;

        if &existing.issuer != issuer {
            return Err(StatusListError::IssuerMismatch);
        }

        existing
            .status_list
            .validate_updates_within_size(&statuses)?;
        if existing.status_list.size.is_some() {
            let update_indices = statuses.iter().map(|entry| entry.index).collect::<Vec<_>>();
            if let Some(index) = self
                .status_list_repo
                .first_unallocated_index(list_id, &update_indices)
                .await?
            {
                return Err(StatusListError::IndexNotAllocated { index });
            }
        }

        let current_status_list = existing.status_list.clone();
        existing.status_list = existing.status_list.update(statuses)?;

        if existing.status_list == current_status_list {
            return Ok(existing);
        }

        if existing.status_list.lst.len() > policy.max_serialized_list_size {
            return Err(StatusListError::TooLarge);
        }

        let previous_version = existing.version;
        existing.version = next_version(previous_version);
        // max(), not +1: two writes in one second may share updated_at, and that's fine.
        existing.updated_at = existing.updated_at.max(current_unix_timestamp());

        let landed = if self.snapshots_enabled() {
            let snapshot = build_snapshot(&existing, policy.token_exp_secs)?;
            self.status_list_repo
                .update_with_snapshot(existing.clone(), previous_version, snapshot)
                .await?
        } else {
            self.status_list_repo
                .update(existing.clone(), previous_version)
                .await?
        };

        if !landed {
            return Err(StatusListError::Conflict);
        }

        invalidate_after_commit(self.status_list_cache.as_ref(), &existing).await;
        Ok(existing)
    }

    pub async fn allocate_indices(
        &self,
        issuer: &Issuer,
        list_id: &str,
        count: u32,
        policy: &StatusListPolicy,
    ) -> Result<Vec<i32>, StatusListError> {
        if count == 0 || count as usize > policy.max_statuses_per_request {
            return Err(StatusListError::InvalidAllocationCount {
                count,
                max: policy.max_statuses_per_request,
            });
        }

        self.status_list_repo
            .allocate_indices(AllocateStatusListIndices {
                list_id: list_id.to_string(),
                issuer: issuer.clone(),
                count,
            })
            .await
    }

    pub async fn get_status_list(
        &self,
        list_id: &str,
    ) -> Result<StatusListRecord, StatusListError> {
        match self.status_list_cache.get(list_id).await {
            Ok(Some(record)) => return Ok(record),
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

    pub async fn list_uris(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<StatusListUriPage, StatusListError> {
        self.status_list_repo.list_uris(None, after, limit).await
    }

    /// None when no issuer has this aggregation ID.
    pub async fn list_issuer_uris(
        &self,
        aggregation_id: AggregationId,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Option<StatusListUriPage>, StatusListError> {
        let Some(issuer) = self
            .credential_repo
            .find_issuer_by_aggregation_id(aggregation_id)
            .await
            .map_err(|e| StatusListError::Backend(Box::new(e)))?
        else {
            return Ok(None);
        };
        self.status_list_repo
            .list_uris(Some(&issuer.0), after, limit)
            .await
            .map(Some)
    }

    pub async fn get_snapshot_at(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<StatusListSnapshot, StatusListError> {
        self.snapshot_repo
            .as_ref()
            .ok_or(StatusListError::NotFound)?
            .find_valid_at(list_id, time)
            .await?
            .ok_or(StatusListError::HistoricalNotFound)
    }

    pub async fn cleanup_snapshots(&self, cutoff: i64) -> Result<u64, StatusListError> {
        let Some(snapshot_repo) = &self.snapshot_repo else {
            return Ok(0);
        };
        snapshot_repo.delete_older_than(cutoff).await
    }

    /// No find pre-check: the primary key catches duplicates, and a pre-check would race anyway.
    pub async fn publish_credential(
        &self,
        credential: Credential,
    ) -> Result<AggregationId, CredentialError> {
        let aggregation_id = AggregationId::generate();
        self.credential_repo
            .insert(credential, aggregation_id)
            .await?;
        Ok(aggregation_id)
    }

    pub async fn find_aggregation_id(
        &self,
        issuer: &Issuer,
    ) -> Result<Option<AggregationId>, CredentialError> {
        self.credential_repo.find_aggregation_id(&issuer.0).await
    }

    pub async fn find_credential(
        &self,
        issuer: &str,
    ) -> Result<Option<Credential>, CredentialError> {
        self.credential_repo.find(issuer).await
    }

    pub async fn find_credential_by_kid(
        &self,
        kid: &str,
    ) -> Result<Option<Credential>, CredentialError> {
        self.credential_repo.find_by_kid(kid).await
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
                "snapshot_repo",
                &std::any::type_name::<dyn StatusListSnapshotRepo>(),
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

pub fn next_version(previous: u64) -> u64 {
    previous.saturating_add(1)
}

fn validate_request_shape(
    statuses: &[StatusEntry],
    max_status_index: i32,
    max_statuses_per_request: usize,
) -> Result<(), StatusListError> {
    if statuses.len() > max_statuses_per_request {
        return Err(StatusListError::TooManyStatuses {
            count: statuses.len(),
            max: max_statuses_per_request,
        });
    }
    for entry in statuses {
        if entry.index > max_status_index {
            return Err(StatusListError::IndexTooLarge {
                index: entry.index,
                max: max_status_index,
            });
        }
    }
    Ok(())
}

/// Use this for every exp: a raw `as i64` would turn u64::MAX into -1 and "succeed".
pub(crate) fn token_expiry(iat: i64, token_exp_secs: u64) -> Result<i64, StatusListError> {
    let token_exp =
        i64::try_from(token_exp_secs).map_err(|_| StatusListError::TokenExpiryOverflow {
            iat,
            token_exp_secs,
        })?;
    iat.checked_add(token_exp)
        .ok_or_else(|| StatusListError::TokenExpiryOverflow {
            iat,
            token_exp_secs,
        })
}

fn build_snapshot(
    record: &StatusListRecord,
    token_exp_secs: u64,
) -> Result<StatusListSnapshot, StatusListError> {
    let iat = record.updated_at;
    let exp = token_expiry(iat, token_exp_secs)?;
    Ok(StatusListSnapshot {
        snapshot_id: uuid::Uuid::new_v4().to_string(),
        list_id: record.list_id.clone(),
        issuer: record.issuer.clone(),
        status_list: record.status_list.clone(),
        sub: record.sub.clone(),
        iat,
        exp,
        version: record.version,
    })
}

async fn invalidate_after_commit(cache: &dyn StatusListCache, record: &StatusListRecord) {
    match cache
        .invalidate_after_update(&record.list_id, record.version)
        .await
    {
        Ok(()) => {
            tracing::debug!(list_id = %record.list_id, "invalidated cache entry after commit");
        }
        Err(error) => {
            tracing::warn!(
                list_id = %record.list_id,
                error = ?error,
                "status list write committed, but cache invalidation failed; \
                 reads may be stale until the cache entry expires"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::status_list::StatusList;
    use crate::test_utils::{publish_list, register_issuer, test_app_state};

    fn record_with_updated_at(updated_at: i64) -> StatusListRecord {
        StatusListRecord {
            list_id: "list-1".into(),
            issuer: Issuer("test-issuer".into()),
            sub: "https://example.com/status-list/1".into(),
            status_list: StatusList {
                bits: 1,
                lst: "AAECAw==".into(),
                size: None,
                default_status: None,
            },
            updated_at,
            version: 1,
        }
    }

    #[test]
    fn snapshot_exp_guards_against_iat_plus_exp_overflow() {
        let record = record_with_updated_at(i64::MAX - 5);
        let err = build_snapshot(&record, 10)
            .expect_err("iat near i64::MAX with token_exp_secs=10 must overflow and be rejected");
        assert!(
            matches!(err, StatusListError::TokenExpiryOverflow { iat, token_exp_secs }
                if iat == i64::MAX - 5 && token_exp_secs == 10),
            "expected TokenExpiryOverflow, got {err:?}"
        );

        let ok = build_snapshot(&record_with_updated_at(1_000), 900)
            .expect("non-overflowing iat + token_exp_secs should build a snapshot");
        assert_eq!(ok.exp, 1_900);
    }

    #[test]
    fn snapshot_exp_rejects_u64_max_token_exp_secs_via_try_from() {
        let record = record_with_updated_at(1_000);
        let err = build_snapshot(&record, u64::MAX)
            .expect_err("u64::MAX token_exp_secs must be rejected via i64::try_from");
        assert!(
            matches!(err, StatusListError::TokenExpiryOverflow { iat, token_exp_secs }
                if iat == 1_000 && token_exp_secs == u64::MAX),
            "expected TokenExpiryOverflow, got {err:?}"
        );
    }

    #[tokio::test]
    async fn list_issuer_uris_lists_only_that_issuers_lists() {
        let state = test_app_state(None).await;
        let service = &state.service;
        let one = register_issuer(service, "one").await;
        register_issuer(service, "two").await;
        let a = publish_list(service, "one", "a").await;
        publish_list(service, "two", "b").await;

        let page = service.list_issuer_uris(one, None, 10).await.unwrap();
        assert_eq!(page.unwrap().status_lists, [a]);
        assert_eq!(
            service
                .list_uris(None, 10)
                .await
                .unwrap()
                .status_lists
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn list_issuer_uris_is_none_for_an_unknown_aggregation_id() {
        let state = test_app_state(None).await;
        register_issuer(&state.service, "one").await;
        publish_list(&state.service, "one", "a").await;

        let page = state
            .service
            .list_issuer_uris(AggregationId::generate(), None, 10)
            .await
            .unwrap();
        assert_eq!(page, None);
    }
}
