//! Outbound secondary ports defining contracts.

use std::{fmt, sync::Arc};

use crate::domain::models::credential::{Credential, CredentialError};
use crate::domain::models::status_list::{
    StatusListError, StatusListRecord, StatusListSnapshot, StatusListUriPage,
};
pub use crate::domain::models::token::{SigningAlgorithm, TokenSignerError};
use async_trait::async_trait;

/// Interface for managing active status list records.
#[async_trait]
pub trait StatusListRepo: Send + Sync + 'static {
    /// Retrieve a status list record by list identifier.
    async fn find(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError>;

    /// Insert a new status list record into persistent storage.
    ///
    /// Fails with [`StatusListError::QuotaExceeded`] when the issuer already
    /// holds `max_lists_per_issuer` lists. The check must be atomic with the insert.
    async fn insert(
        &self,
        status_list: StatusListRecord,
        max_lists_per_issuer: u64,
    ) -> Result<(), StatusListError>;

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
    /// Enforces `max_lists_per_issuer` like [`Self::insert`].
    async fn insert_with_snapshot(
        &self,
        status_list: StatusListRecord,
        snapshot: StatusListSnapshot,
        max_lists_per_issuer: u64,
    ) -> Result<(), StatusListError>;

    /// Return up to `limit` (non-zero) status list URIs in `list_id` order,
    /// starting strictly after `after`.
    async fn list_uris(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<StatusListUriPage, StatusListError>;
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
    async fn get(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError>;

    /// Store a status list record in the cache.
    async fn put(&self, status_list: StatusListRecord) -> Result<(), StatusListError>;

    /// Invalidate a cached status list entry upon mutation.
    async fn invalidate(&self, list_id: &str) -> Result<(), StatusListError>;
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
/// The chain is stored in three pre-parsed forms so the token hot path never
/// re-decodes or re-assembles static certificate material on each request:
/// * `certificate_chain` – base64 DER parts used verbatim for the JWT `x5c` header;
/// * `cert_chain_der` – the raw DER bytes backing each base64 part;
/// * `x5chain` – the pre-built CBOR `x5chain` header value (`ByteString` for a
///   single certificate, `Array` of `ByteString`s for a chain) used by CWT signing.
///
/// All three are derived once, at certificate load or renewal time, by the
/// provider before the snapshot is published.
#[derive(Clone)]
pub struct SigningMaterial {
    /// Base64 DER-encoded x509 certificate chain parts for JWT `x5c`.
    pub certificate_chain: Option<Vec<String>>,
    /// Pre-decoded DER bytes for each certificate in [`Self::certificate_chain`].
    /// Shared with the CWT path to avoid per-request `base64::decode`.
    pub cert_chain_der: Option<Vec<Vec<u8>>>,
    /// Pre-built CBOR `x5chain` protected-header value for CWT signing.
    pub x5chain: Option<coset::cbor::Value>,
    /// Pre-parsed signer. The material does not retain its PEM/DER encoding
    /// after a provider has validated and constructed it; private key material
    /// remains in the signer for its required signing lifetime.
    pub signing_key: Arc<dyn TokenSigner>,
}

impl SigningMaterial {
    /// Construct material from a validated, pre-parsed signer.
    ///
    /// `certificate_chain` holds base64 DER parts; the DER bytes and the CBOR
    /// `x5chain` value are derived here so decoding happens exactly once, at
    /// construction (load/renewal), never on the token signing hot path.
    pub fn new(certificate_chain: Option<Vec<String>>, signing_key: Arc<dyn TokenSigner>) -> Self {
        let (cert_chain_der, x5chain) = match &certificate_chain {
            Some(parts) => match decode_cert_chain(parts) {
                Ok((der, x5chain)) => (Some(der), Some(x5chain)),
                Err(_) => (None, None),
            },
            None => (None, None),
        };
        Self {
            certificate_chain,
            cert_chain_der,
            x5chain,
            signing_key,
        }
    }

    /// Consume the material and return the certificate components the CWT and
    /// JWT signers need, transferring ownership without cloning certificate data.
    pub fn into_certificate_components(self) -> CertificateComponents {
        CertificateComponents {
            certificate_chain: self.certificate_chain,
            cert_chain_der: self.cert_chain_der,
            x5chain: self.x5chain,
            signing_key: self.signing_key,
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

/// Owned certificate components handed to the dedicated CWT/JWT signing
/// routines. Moving this struct (rather than borrowing its fields) transfers
/// ownership of the pre-parsed certificate representations into the selected
/// signing function with zero clone allocations.
pub struct CertificateComponents {
    /// Base64 DER parts for the JWT `x5c` header.
    pub certificate_chain: Option<Vec<String>>,
    /// Pre-decoded DER bytes for the CWT path.
    pub cert_chain_der: Option<Vec<Vec<u8>>>,
    /// Pre-built CBOR `x5chain` value for the CWT protected header.
    pub x5chain: Option<coset::cbor::Value>,
    /// The signer that produces token signatures.
    pub signing_key: Arc<dyn TokenSigner>,
}

/// Decode a base64 DER chain into its raw DER bytes and the CBOR `x5chain`
/// protected-header value, following the status-list spec: a single certificate
/// maps to a `ByteString`, multiple certificates to an `Array` of `ByteString`s.
fn decode_cert_chain(
    cert_chain: &[String],
) -> Result<(Vec<Vec<u8>>, coset::cbor::Value), StatusListError> {
    use base64::prelude::{BASE64_STANDARD, Engine as _};

    let certs_der: Vec<Vec<u8>> = cert_chain
        .iter()
        .map(|b64| {
            BASE64_STANDARD
                .decode(b64)
                .map_err(|err| StatusListError::Backend(Box::new(err)))
        })
        .collect::<Result<_, _>>()?;

    let x5chain_value = if certs_der.len() == 1 {
        coset::cbor::Value::Bytes(certs_der[0].clone())
    } else {
        let cert_array: Vec<coset::cbor::Value> = certs_der
            .iter()
            .cloned()
            .map(coset::cbor::Value::Bytes)
            .collect();
        coset::cbor::Value::Array(cert_array)
    };

    Ok((certs_der, x5chain_value))
}

/// Provider interface for certificate chains and signing keys used for VC/token signatures.
#[async_trait]
pub trait CertificateProvider: Send + Sync + 'static {
    /// Retrieve the current certificate chain and signing key from one
    /// internally consistent snapshot.
    async fn signing_material(&self) -> Result<SigningMaterial, StatusListError>;

    /// Retrieve the current certificate components by value.
    ///
    /// Returns the pre-parsed DER bytes and CBOR `x5chain` structures from the
    /// active snapshot so the token hot path can consume them by ownership
    /// without re-decoding base64 or re-assembling CBOR on every request.
    async fn get_active_certificate(&self) -> Result<CertificateComponents, StatusListError> {
        Ok(self.signing_material().await?.into_certificate_components())
    }
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
