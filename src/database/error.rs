use axum::Json;
use serde_json::{json, Value};
use sqlx::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("generic: {0}")]
    Generic(String),
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
