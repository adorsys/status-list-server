use axum::{Json, http::StatusCode, response::IntoResponse};
use jsonwebtoken::errors::Error as JwtError;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Issuer not registered")]
    IssuerNotFound,
    #[error("Internal server error")]
    InternalServer,
    #[error("Missing or invalid Authorization header")]
    InvalidAuthorizationHeader,
    #[error("{0}")]
    JwtError(#[from] JwtError),
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
}

impl IntoResponse for AuthenticationError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            AuthenticationError::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        };
        let api_error = json!({
            "error": self.get_error_code(),
            "message": self.get_error_message(),
        });
        (status, Json(api_error)).into_response()
    }
}

impl AuthenticationError {
    fn get_error_code(&self) -> &'static str {
        use AuthenticationError::*;
        match self {
            IssuerNotFound => "ISSUER_NOT_FOUND",
            InternalServer => "INTERNAL_SERVER_ERROR",
            InvalidAuthorizationHeader => "INVALID_AUTH_HEADER",
            JwtError(_) => "JWT_ERROR",
            UnsupportedAlgorithm => "UNSUPPORTED_ALGORITHM",
        }
    }

    fn get_error_message(&self) -> String {
        self.to_string()
    }
}
