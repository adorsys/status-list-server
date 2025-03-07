use sqlx::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum RepositoryError {
    #[error("generic: {0}")]
    Generic(String),
}

impl From<Error> for RepositoryError {
    fn from(err: Error) -> Self {
        RepositoryError::Generic(err.to_string())
    }
}
