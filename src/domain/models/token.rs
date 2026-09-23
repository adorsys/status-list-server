use std::fmt;
use thiserror::Error;

/// Algorithms supported by status-list token signers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningAlgorithm {
    /// ECDSA using P-256 and SHA-256.
    Es256,
    /// ECDSA using P-384 and SHA-384.
    Es384,
    /// EdDSA using Ed25519.
    EdDsa,
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    Rs256,
}

impl SigningAlgorithm {
    /// Return the standard JOSE algorithm name.
    pub const fn jose_name(&self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }

    /// Return the IANA COSE algorithm integer identifier.
    pub const fn cose_id(&self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::Es384 => -35,
            Self::EdDsa => -8,
            Self::Rs256 => -257,
        }
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.jose_name())
    }
}

/// An opaque failure returned by a token-signing implementation.
#[derive(Debug, Error)]
#[error("signing operation failed: {message}")]
pub struct TokenSignerError {
    message: String,
}

impl TokenSignerError {
    /// Create a new `TokenSignerError` from the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
