//! Credential domain model, error types, and core domain business operations.

use serde::{Deserialize, Serialize};

/// Domain errors encountered during issuer credential management.
///
/// `#[non_exhaustive]` so adding a variant stays patch-level instead of tripping
/// `cargo-semver-checks` (`enum_variant_added`).
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("invalid public JWK: {0}")]
    InvalidPublicJwk(String),
    #[error("credentials already exist for this issuer")]
    AlreadyExists,
    /// The write lost a lock race in storage and was rolled back; the request is
    /// safe to retry verbatim. Mirrors [`StatusListError::Contention`], `code`
    /// included, so the same driver error does not become a 409 on one write
    /// path and a 500 on the other.
    ///
    /// [`StatusListError::Contention`]: crate::domain::models::status_list::StatusListError::Contention
    #[error("the write lost a lock race ({code}) and can be retried unchanged")]
    Contention { code: &'static str },
    #[error("storage error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Unique issuer identifier string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer(pub String);

/// Validated JSON Web Key document bytes representing an issuer's public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicJwk(pub Vec<u8>);

impl PublicJwk {
    /// Create public JWK bytes from UTF-8 JSON.
    ///
    /// Ensures the payload is a valid JSON object without enforcing key types.
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, CredentialError> {
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|err| {
            CredentialError::InvalidPublicJwk(format!("expected UTF-8 JSON: {err}"))
        })?;
        if !value.is_object() {
            return Err(CredentialError::InvalidPublicJwk(
                "expected a JSON object".to_string(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Domain entity representing an issuer's registered public key credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub issuer: Issuer,
    pub public_key: PublicJwk,
}
