//! Outbound secondary ports defining contracts.

use std::{fmt, sync::Arc};

use crate::domain::models::credential::{Credential, CredentialError};
use crate::domain::models::status_list::{StatusListError, StatusListRecord, StatusListSnapshot};
pub use crate::domain::models::token::{SigningAlgorithm, TokenSignerError};
use async_trait::async_trait;

/// Pluggable cache interface for recently used status-list records.
#[async_trait]
pub trait StatusListCache: Send + Sync + 'static {
    /// Retrieve a cached status-list record by list identifier.
    async fn get(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError>;

    /// Store a status-list record in the cache.
    async fn put(&self, status_list: StatusListRecord) -> Result<(), StatusListError>;

    /// Invalidate a cached status-list entry upon mutation.
    async fn invalidate(&self, list_id: &str) -> Result<(), StatusListError>;

    /// Invalidate a cached entry after a committed update, carrying the committed
    /// monotonic version for distributed caches that need stale-fill fencing.
    async fn invalidate_after_update(
        &self,
        list_id: &str,
        _updated_at: i64,
    ) -> Result<(), StatusListError> {
        self.invalidate(list_id).await
    }
}

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

/// Persistence interface for historical status list snapshots.
#[async_trait]
pub trait StatusListSnapshotRepo: Send + Sync + 'static {
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

/// Certificate chain and signing key captured from one provider snapshot.
#[derive(Clone)]
pub struct SigningMaterial {
    /// Base64 DER-encoded x509 certificate chain parts for JWT `x5c` and CWT
    /// `x5chain`.
    pub certificate_chain: Option<Vec<String>>,
    /// Pre-parsed signer. The material does not retain its PEM/DER encoding
    /// after a provider has validated and constructed it; private key material
    /// remains in the signer for its required signing lifetime.
    pub signing_key: Arc<dyn TokenSigner>,
}

impl SigningMaterial {
    /// Construct material from a validated, pre-parsed signer.
    pub fn new(certificate_chain: Option<Vec<String>>, signing_key: Arc<dyn TokenSigner>) -> Self {
        Self {
            certificate_chain,
            signing_key,
        }
    }
}

impl fmt::Debug for SigningMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningMaterial")
            .field("certificate_chain", &self.certificate_chain)
            .field("signing_algorithm", &self.signing_key.algorithm())
            .field("public_key_len", &self.signing_key.public_key_bytes().len())
            .finish()
    }
}

/// Provider interface for certificate chains and signing keys used for VC/token signatures.
#[async_trait]
pub trait CertificateProvider: Send + Sync + 'static {
    /// Retrieve the current certificate chain and signing key from one
    /// internally consistent snapshot.
    async fn signing_material(&self) -> Result<SigningMaterial, StatusListError>;
}

/// Cryptographic port used by token encoders.
///
/// `sign` receives exactly the bytes defined by the caller's token format and
/// returns the raw signature bytes for the selected algorithm: fixed-width
/// IEEE P1363 for ECDSA, 64-byte Ed25519, and PKCS#1 v1.5 for RS256.
pub trait TokenSigner: Send + Sync {
    /// Return the algorithm associated with this signer.
    fn algorithm(&self) -> SigningAlgorithm;

    /// Sign the supplied token-format signing input.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TokenSignerError>;

    /// Return raw public-key bytes for X.509 certificate validation.
    fn public_key_bytes(&self) -> &[u8];
}
