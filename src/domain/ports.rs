//! Outbound secondary ports defining contracts.

use std::{fmt, sync::Arc};

use crate::domain::models::credential::{Credential, CredentialError, Issuer};
use crate::domain::models::status_list::{
    StatusListError, StatusListRecord, StatusListSnapshot, StatusListUriPage,
};
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
#[derive(Debug, Clone)]
pub struct CreateStatusList {
    pub record: StatusListRecord,
    pub initial_snapshot: Option<StatusListSnapshot>,
    pub initial_allocations: Vec<i32>,
    pub max_lists_per_issuer: u64,
}

#[derive(Debug, Clone)]
pub struct AllocateStatusListIndices {
    pub list_id: String,
    pub issuer: Issuer,
    pub count: u32,
}

#[async_trait]
pub trait StatusListRepo: Send + Sync + 'static {
    /// Retrieve a status list record by list identifier.
    async fn find(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError>;

    /// Create a status list and any initial child records atomically.
    async fn create(&self, command: CreateStatusList) -> Result<(), StatusListError>;

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

    /// Return up to `limit` (non-zero) status list URIs in `list_id` order,
    /// starting strictly after `after`.
    async fn list_uris(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<StatusListUriPage, StatusListError>;

    /// Reserve `count` unused indices for `list_id`, returning the newly
    /// allocated indices in ascending order.
    async fn allocate_indices(
        &self,
        command: AllocateStatusListIndices,
    ) -> Result<Vec<i32>, StatusListError>;

    /// Return the first requested index that has not been allocated, if any.
    async fn first_unallocated_index(
        &self,
        list_id: &str,
        indices: &[i32],
    ) -> Result<Option<i32>, StatusListError>;
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
///
/// The base64 chain (`certificate_chain`) is kept for the JWT `x5c` header, and
/// decoded once at construction into DER bytes (`certificate_der`) for the CWT
/// `x5chain` hot path. Both views are derived from the same source and exposed
/// through accessors, so they can never fall out of sync.
#[derive(Clone)]
pub struct SigningMaterial {
    /// Base64 DER-encoded x509 certificate chain parts for JWT `x5c`.
    certificate_chain: Option<Vec<String>>,
    /// DER-encoded x509 certificate chain, decoded once at construction.
    certificate_der: Option<Arc<[Box<[u8]>]>>,
    /// Pre-parsed signer; retains no PEM/DER encoding.
    pub signing_key: Arc<dyn TokenSigner>,
}

impl SigningMaterial {
    /// Construct material from a validated, pre-parsed signer.
    ///
    /// Rejects an empty chain, an empty entry, or a non-base64 entry so a
    /// malformed chain fails at load/renewal time rather than surfacing later
    /// as a missing or empty CWT `x5chain`. Callers should treat this as a
    /// provisioning error.
    pub fn new(
        certificate_chain: Option<Vec<String>>,
        signing_key: Arc<dyn TokenSigner>,
    ) -> Result<Self, StatusListError> {
        use base64::prelude::{BASE64_STANDARD, Engine as _};

        let certificate_der = match &certificate_chain {
            Some(parts) => {
                if parts.is_empty() {
                    return Err(StatusListError::Backend(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "certificate chain is empty",
                    ))));
                }
                if parts.iter().any(|b64| b64.is_empty()) {
                    return Err(StatusListError::Backend(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "certificate chain contains an empty entry",
                    ))));
                }
                let der: Vec<Box<[u8]>> = parts
                    .iter()
                    .map(|b64| {
                        BASE64_STANDARD
                            .decode(b64)
                            .map(Vec::into_boxed_slice)
                            .map_err(|err| StatusListError::Backend(Box::new(err)))
                    })
                    .collect::<Result<_, _>>()?;
                Some(Arc::from(der))
            }
            None => None,
        };
        Ok(Self {
            certificate_chain,
            certificate_der,
            signing_key,
        })
    }

    /// Base64 DER-encoded x509 certificate chain parts for the JWT `x5c` header.
    pub fn certificate_chain(&self) -> Option<&[String]> {
        self.certificate_chain.as_deref()
    }

    /// DER-encoded x509 certificate chain for the CWT `x5chain` header.
    pub fn certificate_der(&self) -> Option<&[Box<[u8]>]> {
        self.certificate_der.as_deref()
    }
}

impl fmt::Debug for SigningMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningMaterial")
            .field(
                "certificate_chain",
                &self.certificate_chain.as_ref().map(|c| c.len()),
            )
            .field(
                "certificate_der",
                &self.certificate_der.as_ref().map(|d| d.len()),
            )
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
    ///
    /// Returns an [`Arc`] so a per-request clone of the chain is avoided; token
    /// encoders move the cheap `Arc` clone into a blocking task and borrow the
    /// material inside it.
    async fn signing_material(&self) -> Result<Arc<SigningMaterial>, StatusListError>;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::crypto::SigningKey;

    fn signer() -> Arc<dyn TokenSigner> {
        Arc::new(SigningKey::generate(SigningAlgorithm::Es256).unwrap())
    }

    #[test]
    fn new_accepts_none_chain() {
        assert!(SigningMaterial::new(None, signer()).is_ok());
    }

    #[test]
    fn new_rejects_empty_chain() {
        assert!(SigningMaterial::new(Some(vec![]), signer()).is_err());
    }

    #[test]
    fn new_rejects_malformed_base64_chain() {
        assert!(SigningMaterial::new(Some(vec!["not-base64!".into()]), signer()).is_err());
    }

    #[test]
    fn new_rejects_empty_chain_entry() {
        assert!(SigningMaterial::new(Some(vec![String::new()]), signer()).is_err());
    }

    #[test]
    fn accessors_keep_views_in_sync() {
        use base64::prelude::{BASE64_STANDARD, Engine as _};
        let chain = vec![
            BASE64_STANDARD.encode(b"leaf"),
            BASE64_STANDARD.encode(b"root"),
        ];
        let material = SigningMaterial::new(Some(chain.clone()), signer()).expect("material");
        assert_eq!(material.certificate_chain(), Some(chain.as_slice()));
        assert_eq!(material.certificate_der().map(|d| d.len()), Some(2));

        let no_chain = SigningMaterial::new(None, signer()).expect("material");
        assert_eq!(no_chain.certificate_chain(), None);
        assert_eq!(no_chain.certificate_der(), None);
    }

    #[test]
    fn new_accepts_valid_chain() {
        use base64::prelude::{BASE64_STANDARD, Engine as _};
        let chain = vec![BASE64_STANDARD.encode(b"cert-der")];
        assert!(SigningMaterial::new(Some(chain), signer()).is_ok());
    }
}
