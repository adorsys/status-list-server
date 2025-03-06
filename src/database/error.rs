use axum::Json;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum RepositoryError {
    #[error("could not store entity")]
    StoreError,
    #[error("could not fetch entity")]
    FetchError,
    #[error("could not update entity")]
    UpdateError,
    #[error("could not delete entity")]
    DeleteError,
    #[error("Repository not set")]
    RepositoryNotSet,
    #[error("generic: {0}")]
    Generic(String),
}

impl RepositoryError {
    pub fn json(&self) -> Json<Value> {
        Json(json!({"error": self.to_string()}))
    }
}
