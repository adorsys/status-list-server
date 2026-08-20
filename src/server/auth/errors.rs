use crate::server::error::{ApiError, IntoApiError};
use axum::response::IntoResponse;
use hyper::StatusCode;
use std::borrow::Cow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Internal server error")]
    InternalServer,
    #[error("Missing or invalid Authorization header")]
    InvalidAuthorizationHeader,
    // Signature, claim, and algorithm failures deliberately share a single
    // uniform message and `invalid_token` wire code so a response never
    // discloses which layer failed or any token details.
    #[error("Token is invalid")]
    InvalidSignature,
    #[error("Token is invalid")]
    InvalidClaims,
    #[error("Token is invalid")]
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
            AuthenticationError::InternalServer => Cow::Borrowed("internal_error"),
            AuthenticationError::InvalidAuthorizationHeader => Cow::Borrowed("invalid_auth_header"),
            // Signature, claim, and algorithm (HMAC-key) failures are
            // indistinguishable on the wire: all surface as `invalid_token` so
            // the response is not an oracle for which check failed.
            AuthenticationError::InvalidSignature
            | AuthenticationError::InvalidClaims
            | AuthenticationError::UnsupportedAlgorithm => Cow::Borrowed("invalid_token"),
        }
    }

    pub fn get_error_message(&self) -> String {
        self.to_string()
    }
}

impl IntoApiError for AuthenticationError {
    fn into_api_error(self) -> ApiError {
        ApiError::new(
            self.get_status(),
            self.get_error_code(),
            Some(self.get_error_message()),
        )
    }
}

impl IntoResponse for AuthenticationError {
    fn into_response(self) -> axum::response::Response {
        self.into_api_error().into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn test_authentication_error_into_response() {
        let err = AuthenticationError::InvalidAuthorizationHeader;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_auth_header");
        assert_eq!(
            json["error_description"],
            "Missing or invalid Authorization header"
        );
    }

    #[tokio::test]
    async fn test_claim_errors_are_generic_and_non_disclosing() {
        // Signature, claim, and algorithm (HMAC-key) failures all surface as the
        // generic `invalid_token` code with a uniform message that never echoes
        // underlying claim details or which check failed.
        for err in [
            AuthenticationError::InvalidClaims,
            AuthenticationError::InvalidSignature,
            AuthenticationError::UnsupportedAlgorithm,
        ] {
            let response = err.into_response();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "invalid_token");
            assert_eq!(json["error_description"], "Token is invalid");
        }
    }
}
