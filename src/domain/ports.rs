use std::{fmt, sync::Arc};

use crate::domain::models::credential::{AggregationId, Credential, CredentialError, Issuer};
use crate::domain::models::status_list::{
    StatusListError, StatusListRecord, StatusListSnapshot, StatusListUriPage,
};
pub use crate::domain::models::token::{SigningAlgorithm, TokenSignerError};
use async_trait::async_trait;

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
    ) -> Result<(), CredentialError>;

    async fn find_aggregation_id(
        &self,
        issuer: &str,
    ) -> Result<Option<AggregationId>, CredentialError>;

    async fn find_issuer_by_aggregation_id(
        &self,
        aggregation_id: AggregationId,
    ) -> Result<Option<Issuer>, CredentialError>;
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
