use axum::Json;
use serde_json::{json, Value};
use sqlx::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("generic: {0}")]
    Generic(String),
    #[error("could not store entity")]
    CouldNotStoreEntity,
    #[error("repository not set")]
    RepositoryNotSet,
    #[error("issuer already exist")]
    DuplicateEntry,
}

impl RepositoryError {
    pub fn json(&self) -> Json<Value> {
        Json(json!({"error": self.to_string()}))
    }
}
impl From<Error> for RepositoryError {
    fn from(err: Error) -> Self {
        RepositoryError::Generic(err.to_string())
    }
}
