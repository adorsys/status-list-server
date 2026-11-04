//! Outbound secondary ports defining contracts.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

use async_trait::async_trait;

use crate::domain::models::credential::{
    AggregationId, Credential, CredentialError, Issuer, KeyResolveError, ResolvedKey,
};
use crate::domain::models::hosted_issuer::{
    HostedIssuer, HostedIssuerError, HostedIssuerFilter, HostedIssuerKey, HostedIssuerKeyEntry,
};

/// Resolve a trusted signing key without exposing the backing trust source to
/// authentication.
///
/// Resolution may consult durable storage (hosted-profile issuers), so it is
/// asynchronous; callers in the auth middleware await it.
#[async_trait]
pub trait IssuerKeyResolver: Send + Sync + fmt::Debug {
    async fn resolve(&self, kid: &str) -> Result<Arc<ResolvedKey>, KeyResolveError>;
}

/// A hosted-profile issuer store behind the dynamic trust source. `issuer_keys`
/// is looked up by its `kid` primary key with no cache: every resolution reads
/// the row, so revocation takes effect on the next request (ADR 0002, no
/// cached authorization outlives a change).
#[async_trait]
pub trait HostedIssuerStore: Send + Sync + 'static {
    /// Return a bounded page ordered by issuer id, strictly after `after`.
    async fn list_issuers_after(
        &self,
        after: Option<&str>,
        limit: usize,
        filters: &HostedIssuerFilter,
        now: time::OffsetDateTime,
    ) -> Result<Vec<HostedIssuer>, HostedIssuerError>;
    /// Return all signing-key metadata for one hosted issuer.
    async fn issuer_keys(&self, issuer_id: &str)
    -> Result<Vec<HostedIssuerKey>, HostedIssuerError>;
    /// Return signing-key metadata for a page of hosted issuers in one read.
    async fn issuer_keys_for(
        &self,
        issuer_ids: &[String],
    ) -> Result<HashMap<String, Vec<HostedIssuerKey>>, HostedIssuerError> {
        let mut result = HashMap::with_capacity(issuer_ids.len());
        for issuer_id in issuer_ids {
            result.insert(issuer_id.clone(), self.issuer_keys(issuer_id).await?);
        }
        Ok(result)
    }
    /// The issuer owning a registered management-token key ID.
    async fn find_key_by_kid(
        &self,
        kid: &str,
    ) -> Result<Option<HostedIssuerKeyEntry>, HostedIssuerError>;

    /// One hosted issuer by its assigned identifier.
    async fn find_issuer(&self, id: &str) -> Result<Option<HostedIssuer>, HostedIssuerError>;

    /// Persist a new hosted issuer together with its immutable aggregation
    /// mapping in one unit; both rows commit or neither does. Returns the
    /// stored issuer: an aggregation ID that collided with one already in use
    /// was regenerated server-side, because identifiers are server-assigned.
    async fn create_issuer(
        &self,
        issuer: HostedIssuer,
        actor: &str,
    ) -> Result<HostedIssuer, HostedIssuerError>;

    /// Register a signing key for an existing hosted issuer.
    async fn add_key(&self, key: HostedIssuerKey, actor: &str) -> Result<(), HostedIssuerError>;

    /// Register a signing key only while the issuer is still at
    /// `expected_version`. The default preserves the store's existing API for
    /// test-only adapters; durable stores override it to make an HTTP
    /// `If-Match` precondition atomic with the insertion.
    async fn add_key_if_version(
        &self,
        key: HostedIssuerKey,
        expected_version: u64,
        actor: &str,
    ) -> Result<(), HostedIssuerError> {
        let _ = expected_version;
        self.add_key(key, actor).await
    }

    /// Every registered hosted key row, for the adapter's quarantine scan and
    /// tests; resolution uses [`find_key_by_kid`](HostedIssuerStore::find_key_by_kid).
    async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError>;

    /// Every hosted issuer, for the per-issuer usage gauges.
    async fn all_issuers(&self) -> Result<Vec<HostedIssuer>, HostedIssuerError>;

    /// The hosted key that already holds the given normalized key material
    /// (RFC 7638 §7 parameters), if any. Returns `None` when the material is
    /// free. The `issuer_id` and `state` of the returned key let callers
    /// distinguish a genuine cross-issuer collision from a `Reserved`
    /// carry-over row of the same principal (adoption).
    async fn find_key_by_material(
        &self,
        material: &str,
    ) -> Result<Option<HostedIssuerKey>, HostedIssuerError>;

    /// Which of the given ids name a hosted issuer, in one batched query.
    /// Used by the startup/reload warning path so it does not run one
    /// `find_issuer` per owner.
    async fn find_issuer_ids(&self, ids: &[String]) -> Result<HashSet<String>, HostedIssuerError>;
}

/// Durable lifecycle changes for hosted issuers. Each method commits the state
/// transition and its audit record in one transaction.
#[async_trait]
pub trait HostedIssuerLifecycleStore: Send + Sync + 'static {
    async fn get_issuer(&self, issuer_id: &str) -> Result<HostedIssuer, HostedIssuerError>;

    async fn set_issuer_state(
        &self,
        issuer_id: &str,
        state: crate::domain::models::hosted_issuer::HostedIssuerState,
        expected_version: u64,
        actor: &str,
    ) -> Result<HostedIssuer, HostedIssuerError>;

    async fn revoke_key(
        &self,
        issuer_id: &str,
        kid: &str,
        expected_version: u64,
        actor: &str,
    ) -> Result<HostedIssuerKey, HostedIssuerError>;
}

/// Public aggregation mappings supplied by the active issuer source.
pub trait IssuerDirectory: Send + Sync + fmt::Debug {
    fn issuer_aggregation_id(&self, issuer: &str) -> Option<AggregationId>;
    fn issuer_by_aggregation_id(&self, aggregation_id: AggregationId) -> Option<String>;
}
use crate::domain::models::status_list::{
    StatusListError, StatusListRecord, StatusListSnapshot, StatusListUriPage,
};
pub use crate::domain::models::token::{SigningAlgorithm, TokenSignerError};

#[async_trait]
pub trait StatusListCache: Send + Sync + 'static {
    async fn get(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError>;

    async fn put(&self, status_list: StatusListRecord) -> Result<(), StatusListError>;

    async fn invalidate(&self, list_id: &str) -> Result<(), StatusListError>;

    /// Carries the version so a shared cache can refuse a stale refill.
    async fn invalidate_after_update(
        &self,
        list_id: &str,
        _version: u64,
    ) -> Result<(), StatusListError> {
        self.invalidate(list_id).await
    }
}

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
    /// Count all lists owned by one issuer, including during quota transitions.
    async fn count_by_issuer(&self, issuer: &str) -> Result<u64, StatusListError>;

    /// Count lists for a page of issuers, allowing SQL adapters to group the counts.
    async fn count_by_issuers(
        &self,
        issuers: &[String],
    ) -> Result<HashMap<String, u64>, StatusListError> {
        let mut counts = HashMap::with_capacity(issuers.len());
        for issuer in issuers {
            counts.insert(issuer.clone(), self.count_by_issuer(issuer).await?);
        }
        Ok(counts)
    }

    /// Retrieve a status list record by list identifier.
    async fn find(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError>;

    /// Atomic: the list and its first snapshot land together or not at all.
    async fn create(&self, command: CreateStatusList) -> Result<(), StatusListError>;

    async fn update(
        &self,
        status_list: StatusListRecord,
        expected_version: u64,
    ) -> Result<bool, StatusListError>;

    /// The update and its snapshot commit together.
    async fn update_with_snapshot(
        &self,
        status_list: StatusListRecord,
        expected_version: u64,
        snapshot: StatusListSnapshot,
    ) -> Result<bool, StatusListError>;

    /// Ordered by list_id; `limit` must be non-zero.
    async fn list_uris(
        &self,
        issuer: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<StatusListUriPage, StatusListError>;

    /// Issuer identifiers that currently own at least one status list.
    async fn issuers_with_status_lists(&self) -> Result<Vec<String>, StatusListError>;

    /// Number of status lists each issuer holds against its list quota.
    /// Issuers without a list are absent.
    async fn list_counts_by_issuer(&self) -> Result<HashMap<String, u64>, StatusListError>;

    /// Returns the new indices in ascending order.
    async fn allocate_indices(
        &self,
        command: AllocateStatusListIndices,
    ) -> Result<Vec<i32>, StatusListError>;

    async fn first_unallocated_index(
        &self,
        list_id: &str,
        indices: &[i32],
    ) -> Result<Option<i32>, StatusListError>;
}

#[async_trait]
pub trait CredentialRepo: Send + Sync + 'static {
    async fn find(&self, issuer: &str) -> Result<Option<Credential>, CredentialError>;

    async fn find_by_kid(&self, kid: &str) -> Result<Option<Credential>, CredentialError>;

    async fn insert(
        &self,
        credential: Credential,
        aggregation_id: AggregationId,
    ) -> Result<AggregationId, CredentialError>;

    async fn find_aggregation_id(
        &self,
        issuer: &str,
    ) -> Result<Option<AggregationId>, CredentialError>;

    /// Read a stored aggregation ID without assigning one to legacy rows.
    /// `Some(None)` represents a credential created before aggregation IDs.
    async fn find_stored_aggregation_id(
        &self,
        issuer: &str,
    ) -> Result<Option<Option<AggregationId>>, CredentialError>;

    /// Set the aggregation ID for a legacy credential only when it is still NULL.
    async fn assign_aggregation_id(
        &self,
        issuer: &str,
        aggregation_id: AggregationId,
    ) -> Result<(), CredentialError>;

    /// The issuer an aggregation ID belongs to.
    async fn find_issuer_by_aggregation_id(
        &self,
        aggregation_id: AggregationId,
    ) -> Result<Option<Issuer>, CredentialError>;

    /// Permanently reserve aggregation identifiers for statically trusted
    /// issuers. Existing mappings are immutable; this operation is idempotent
    /// for the same issuer and identifier and fails on either kind of conflict.
    async fn record_registry_aggregation_ids(
        &self,
        mappings: &[(String, AggregationId)],
    ) -> Result<(), CredentialError>;
}

#[async_trait]
pub trait StatusListSnapshotRepo: Send + Sync + 'static {
    async fn insert(&self, record: StatusListSnapshot) -> Result<(), StatusListError>;

    async fn find_valid_at(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<Option<StatusListSnapshot>, StatusListError>;

    async fn delete_older_than(&self, cutoff: i64) -> Result<u64, StatusListError>;
}

/// Holds the chain twice: base64 for JWT x5c and DER for CWT x5chain, decoded once.
#[derive(Clone)]
pub struct SigningMaterial {
    certificate_chain: Option<Vec<String>>,
    certificate_der: Option<Arc<[Box<[u8]>]>>,
    /// Keeps no PEM or DER copy of the key.
    pub signing_key: Arc<dyn TokenSigner>,
}

impl SigningMaterial {
    /// Rejects a malformed chain here so it fails at load, not as an empty x5chain later.
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

    pub fn certificate_chain(&self) -> Option<&[String]> {
        self.certificate_chain.as_deref()
    }

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

#[async_trait]
pub trait CertificateProvider: Send + Sync + 'static {
    /// Chain and key come from one consistent snapshot; the Arc keeps per-request clones cheap.
    async fn signing_material(&self) -> Result<Arc<SigningMaterial>, StatusListError>;
}

/// Signatures are raw: IEEE P1363 for ECDSA (not DER), 64 bytes for Ed25519, PKCS#1 v1.5 for RS256.
pub trait TokenSigner: Send + Sync {
    fn algorithm(&self) -> SigningAlgorithm;

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TokenSignerError>;

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
