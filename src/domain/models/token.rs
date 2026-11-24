use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningAlgorithm {
    Es256,
    Es384,
    EdDsa,
    Rs256,
}

impl SigningAlgorithm {
    pub const fn jose_name(&self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }

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

#[derive(Debug, Error)]
#[error("signing operation failed: {message}")]
pub struct TokenSignerError {
    message: String,
}

impl TokenSignerError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
