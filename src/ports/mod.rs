//! Outbound ports. Application services depend on these traits, never on an
//! infrastructure client or framework.
use async_trait::async_trait;

use crate::domain::{Credential, StatusListRecord};

#[derive(Debug, thiserror::Error)]
pub enum PortError {
    #[error("storage unavailable during {operation}: {detail}")]
    StorageUnavailable {
        operation: &'static str,
        detail: String,
    },
    #[error("external service unavailable during {operation}: {detail}")]
    ExternalServiceUnavailable {
        operation: &'static str,
        detail: String,
    },
    #[error("operation timed out during {operation}: {detail}")]
    Timeout {
        operation: &'static str,
        detail: String,
    },
    #[error("unauthorized outbound operation during {operation}: {detail}")]
    Unauthorized {
        operation: &'static str,
        detail: String,
    },
    #[error("resource conflict for {resource}: {reason}")]
    Conflict {
        resource: &'static str,
        reason: String,
    },
    #[error("invalid data for {resource}: {reason}")]
    InvalidData {
        resource: &'static str,
        reason: String,
    },
}

#[async_trait]
pub trait StatusListRepository: Send + Sync {
    async fn find(&self, list_id: &str) -> Result<Option<StatusListRecord>, PortError>;
    async fn insert(&self, status_list: StatusListRecord) -> Result<(), PortError>;
    async fn update(&self, status_list: StatusListRecord) -> Result<bool, PortError>;
    async fn list_uris(&self) -> Result<Vec<String>, PortError>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn find(&self, issuer: &str) -> Result<Option<Credential>, PortError>;
    async fn insert(&self, credential: Credential) -> Result<(), PortError>;
}

#[async_trait]
pub trait StatusListCache: Send + Sync {
    async fn get(&self, list_id: &str) -> Result<Option<StatusListRecord>, PortError>;
    async fn put(&self, status_list: StatusListRecord) -> Result<(), PortError>;
    async fn invalidate(&self, list_id: &str) -> Result<(), PortError>;
}

/// Repository for historical status list snapshots (draft-21 §8.4).
#[cfg(any(feature = "server", feature = "postgres"))]
#[async_trait]
pub trait StatusListHistoryRepository: Send + Sync {
    /// Insert a new historical snapshot.
    async fn insert(&self, record: crate::models::StatusListHistoryRecord)
    -> Result<(), PortError>;
    /// Find the snapshot valid at the given timestamp (iat <= time < exp).
    async fn find_valid_at(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<Option<crate::models::StatusListHistoryRecord>, PortError>;
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

#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn get(&self, name: &str) -> Result<Option<String>, PortError>;
    async fn put(&self, name: &str, value: &str) -> Result<(), PortError>;
}

#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn present_txt(&self, name: &str, value: &str) -> Result<(), PortError>;
    async fn remove_txt(&self, name: &str, value: &str) -> Result<(), PortError>;
}

pub trait MetricsCollector: Send + Sync {
    fn increment(&self, name: &'static str);
}
