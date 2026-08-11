//! Credential domain model, error types, and core domain business operations.

use serde::{Deserialize, Serialize};

/// Longest accepted issuer identifier, in bytes.
///
/// Registration is unauthenticated, and a registered issuer becomes both a
/// stored row and a rate-limit bucket key for the lifetime of that row. Bounding
/// the identifier here — at the only place issuers enter the system — is what
/// keeps both bounded, and means there is one length rule rather than one per
/// consumer.
pub const MAX_ISSUER_LEN: usize = 256;

/// Domain errors encountered during issuer credential management.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("invalid public JWK: {0}")]
    InvalidPublicJwk(String),
    #[error("credentials already exist for this issuer")]
    AlreadyExists,
    #[error(
        "issuer identifier is {0} bytes; the maximum is {max}",
        max = MAX_ISSUER_LEN
    )]
    IssuerTooLong(usize),
    #[error("issuer identifier must not be empty")]
    IssuerEmpty,
    #[error("storage error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Unique issuer identifier string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer(pub String);

impl Issuer {
    /// Creates an issuer identifier, rejecting empty and over-long values.
    ///
    /// Use this on any path where the identifier originates from a client. The
    /// tuple field stays public so that values already read back from storage
    /// do not have to be re-validated.
    pub fn try_new(issuer: impl Into<String>) -> Result<Self, CredentialError> {
        let issuer = issuer.into();
        if issuer.is_empty() {
            return Err(CredentialError::IssuerEmpty);
        }
        if issuer.len() > MAX_ISSUER_LEN {
            return Err(CredentialError::IssuerTooLong(issuer.len()));
        }
        Ok(Self(issuer))
    }
}

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
