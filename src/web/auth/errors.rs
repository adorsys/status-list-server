use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use jsonwebtoken::errors::Error as JwtError;
use serde_json::json;
use std::borrow::Cow;
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

impl AuthenticationError {
    pub fn get_status(&self) -> StatusCode {
        match self {
            AuthenticationError::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    pub fn get_error_code(&self) -> Cow<'static, str> {
        match self {
            AuthenticationError::IssuerNotFound => Cow::Borrowed("issuer_not_found"),
            AuthenticationError::InternalServer => Cow::Borrowed("internal_error"),
            AuthenticationError::InvalidAuthorizationHeader => Cow::Borrowed("invalid_auth_header"),
            AuthenticationError::JwtError(_) => Cow::Borrowed("jwt_error"),
            AuthenticationError::UnsupportedAlgorithm => Cow::Borrowed("unsupported_algorithm"),
        }
    }

    #[allow(dead_code)]
    pub fn get_error_message(&self) -> String {
        self.to_string()
    }
}

impl IntoResponse for AuthenticationError {
    fn into_response(self) -> axum::response::Response {
        let status = self.get_status();
        let body = json!({
            "error": self.get_error_code(),
            "message": self.get_error_message(),
        });
        (status, Json(body)).into_response()
    }
}
