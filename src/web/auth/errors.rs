use axum::{response::IntoResponse, Json};
use hyper::StatusCode;
use jsonwebtoken::errors::Error as JwtError;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Issuer not registered")]
    IssuerNotFound,
    #[error("Internal server error")]
    InternalServer,
    #[error("Missing Authorization header")]
    MissingAuthHeader,
    #[error("{0}")]
    JwtError(#[from] JwtError),
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
}

impl IntoResponse for AuthenticationError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            AuthenticationError::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        };

        let body = json!({
            "error": self.to_string()
        });

        (status, Json(body)).into_response()
    }
}
