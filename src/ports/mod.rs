//! Outbound ports. Application services depend on these traits, never on an
//! infrastructure client or framework.
use async_trait::async_trait;
use std::sync::Arc;

#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
use crate::domain::StatusListSnapshot;
use crate::domain::{Credential, StatusListRecord};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortOperation {
    CertificateChain,
    DeleteOldStatusListHistory,
    FindCredential,
    FindStatusList,
    FindStatusListHistory,
    InsertCredential,
    InsertStatusList,
    InsertStatusListHistory,
    ListStatusListUris,
    SigningKey,
    UpdateStatusList,
}

impl std::fmt::Display for PortOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::CertificateChain => "certificate chain",
            Self::DeleteOldStatusListHistory => "delete old status list history",
            Self::FindCredential => "find credential",
            Self::FindStatusList => "find status list",
            Self::FindStatusListHistory => "find valid status list history",
            Self::InsertCredential => "insert credential",
            Self::InsertStatusList => "insert status list",
            Self::InsertStatusListHistory => "insert status list history",
            Self::ListStatusListUris => "list status list URIs",
            Self::SigningKey => "signing key",
            Self::UpdateStatusList => "update status list",
        };
        f.write_str(label)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidDataKind {
    Parse,
    Serialization,
}

#[derive(Debug, thiserror::Error)]
pub enum PortError {
    #[error("storage unavailable during {operation}: {detail}")]
    StorageUnavailable {
        operation: PortOperation,
        detail: String,
    },
    #[error("external service unavailable during {operation}: {detail}")]
    ExternalServiceUnavailable {
        operation: PortOperation,
        detail: String,
    },
    #[error("resource conflict for {resource}: {reason}")]
    Conflict {
        resource: &'static str,
        reason: String,
    },
    #[error("invalid data for {resource} ({kind:?}): {reason}")]
    InvalidData {
        resource: &'static str,
        kind: InvalidDataKind,
        reason: String,
    },
}

#[async_trait]
pub trait StatusListRepository: Send + Sync {
    async fn find(&self, list_id: &str) -> Result<Option<Arc<StatusListRecord>>, PortError>;
    async fn insert(&self, status_list: StatusListRecord) -> Result<(), PortError>;
    /// Persists `status_list` only if the stored row still carries
    /// `expected_updated_at` (optimistic concurrency). Returns `false` on a
    /// guard miss (a racing writer advanced the stamp, or the row is gone).
    /// `status_list.updated_at` must be strictly greater than
    /// `expected_updated_at`; see
    /// [`next_updated_at`](crate::application::next_updated_at) for why.
    async fn update(
        &self,
        status_list: StatusListRecord,
        expected_updated_at: i64,
    ) -> Result<bool, PortError>;
    /// Like [`update`](Self::update), but atomically persists the guarded row
    /// update **and** its history snapshot: both commit or neither does.
    /// Implementations MUST perform both writes in a single backend transaction
    /// (portable across Postgres/MySQL/SQLite) so a failed snapshot insert rolls
    /// the row update back — a guarantee `update` plus a separate insert cannot
    /// give. Same `false`-on-guard-miss and strictly-advancing-stamp contract as
    /// `update`; callers that keep no history use it instead.
    #[cfg(any(
        feature = "server",
        feature = "postgres",
        feature = "sqlite",
        feature = "mysql"
    ))]
    async fn update_with_snapshot(
        &self,
        status_list: StatusListRecord,
        expected_updated_at: i64,
        snapshot: StatusListSnapshot,
    ) -> Result<bool, PortError>;
    async fn list_uris(&self) -> Result<Vec<String>, PortError>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn find(&self, issuer: &str) -> Result<Option<Credential>, PortError>;
    async fn insert(&self, credential: Credential) -> Result<(), PortError>;
}

#[async_trait]
pub trait StatusListCache: Send + Sync {
    async fn get(&self, list_id: &str) -> Result<Option<Arc<StatusListRecord>>, PortError>;
    async fn put(&self, status_list: StatusListRecord) -> Result<(), PortError>;
    async fn invalidate(&self, list_id: &str) -> Result<(), PortError>;
}

/// Repository for historical status list snapshots (draft-21 §8.4).
#[cfg(any(
    feature = "server",
    feature = "postgres",
    feature = "sqlite",
    feature = "mysql"
))]
#[async_trait]
pub trait StatusListHistoryRepository: Send + Sync {
    /// Insert a new historical snapshot.
    async fn insert(&self, record: StatusListSnapshot) -> Result<(), PortError>;
    /// Find the snapshot valid at the given timestamp (iat <= time < exp).
    async fn find_valid_at(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<Option<StatusListSnapshot>, PortError>;
    /// Delete snapshots older than the cutoff (exp < cutoff).
    async fn delete_older_than(&self, cutoff: i64) -> Result<u64, PortError>;
}

/// Certificate material required to issue a token. Concrete ACME/S3/secret
/// implementations stay behind this boundary.
#[async_trait]
pub trait CertificateProvider: Send + Sync {
    async fn certificate_chain(&self) -> Result<Option<Vec<String>>, PortError>;
    async fn signing_key_pem(&self) -> Result<String, PortError>;
}
