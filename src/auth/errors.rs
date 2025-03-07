use thiserror::Error;

use crate::database::error::RepositoryError;

#[derive(Error, Debug)]
pub enum AuthErrors {
    #[error("algorithm not known")]
    UnknownAlgorithm,
}

impl From<AuthErrors> for RepositoryError {
    fn from(err: AuthErrors) -> Self {
        Self::Generic(err.to_string())
    }
}
