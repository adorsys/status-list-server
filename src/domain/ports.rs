//! Outbound secondary ports defining contracts.

use crate::domain::models::credential::{Credential, CredentialError};
use crate::domain::models::status_list::{StatusListError, StatusListRecord, StatusListSnapshot};
use async_trait::async_trait;
use std::sync::Arc;

/// Interface for managing active status list records.
#[async_trait]
pub trait StatusListRepo: Send + Sync + 'static {
    /// Retrieve a status list record by list identifier.
    async fn find(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError>;

    /// Insert a new status list record into persistent storage.
    async fn insert(&self, status_list: StatusListRecord) -> Result<(), StatusListError>;

    /// Concurrently update an existing status list record matching `expected_updated_at`.
    async fn update(
        &self,
        status_list: StatusListRecord,
        expected_updated_at: i64,
    ) -> Result<bool, StatusListError>;

    /// Concurrently update an existing record and atomically record a historical snapshot.
    async fn update_with_snapshot(
        &self,
        status_list: StatusListRecord,
        expected_updated_at: i64,
        snapshot: StatusListSnapshot,
    ) -> Result<bool, StatusListError>;

    /// Insert a new status list record and atomically record its initial historical snapshot.
    async fn insert_with_snapshot(
        &self,
        status_list: StatusListRecord,
        snapshot: StatusListSnapshot,
    ) -> Result<(), StatusListError>;

    /// Return all published status list URIs for aggregation endpoints.
    async fn list_uris(&self) -> Result<Vec<String>, StatusListError>;
}

/// Interface for issuer public key credentials.
#[async_trait]
pub trait CredentialRepo: Send + Sync + 'static {
    /// Find issuer credential details by issuer identifier.
    async fn find(&self, issuer: &str) -> Result<Option<Credential>, CredentialError>;

    /// Insert new issuer credential details into storage.
    async fn insert(&self, credential: Credential) -> Result<(), CredentialError>;
}

/// In-memory or distributed cache interface for status list records.
#[async_trait]
pub trait StatusListCache: Send + Sync + 'static {
    /// Retrieve a cached status list record by list identifier.
    async fn get(&self, list_id: &str) -> Result<Option<Arc<StatusListRecord>>, StatusListError>;

    /// Store a status list record in the cache.
    async fn put(&self, status_list: StatusListRecord) -> Result<(), StatusListError>;

    /// Invalidate a cached status list entry upon mutation.
    async fn invalidate(&self, list_id: &str) -> Result<(), StatusListError>;
}

/// Persistence interface for historical status list snapshots.
#[async_trait]
pub trait StatusListHistoryRepo: Send + Sync + 'static {
    /// Save a historical status list snapshot.
    async fn insert(&self, record: StatusListSnapshot) -> Result<(), StatusListError>;

    /// Find a historical snapshot active at a specific Unix timestamp.
    async fn find_valid_at(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<Option<StatusListSnapshot>, StatusListError>;

    /// Purge historical snapshots with expiration timestamps older than `cutoff`.
    async fn delete_older_than(&self, cutoff: i64) -> Result<u64, StatusListError>;
}

/// Provider interface for certificate chains and signing keys used for VC/token signatures.
#[async_trait]
pub trait CertificateProvider: Send + Sync + 'static {
    /// Retrieve the current PEM-encoded x509 certificate chain.
    async fn certificate_chain(&self) -> Result<Option<Vec<String>>, StatusListError>;

    /// Retrieve the current PKCS#8 PEM-encoded signing key.
    async fn signing_key_pem(&self) -> Result<String, StatusListError>;
}
