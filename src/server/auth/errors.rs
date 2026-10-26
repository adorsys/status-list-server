use crate::server::error::{ApiError, IntoApiError};
use axum::response::IntoResponse;
use hyper::StatusCode;
use std::borrow::Cow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Internal server error")]
    InternalServer,
    #[error("Missing bearer token")]
    MissingToken,
    #[error("Invalid authentication token")]
    InvalidToken,
    #[error("The trust backend is temporarily unavailable")]
    BackendUnavailable,
}

impl AuthenticationError {
    pub fn get_status(&self) -> StatusCode {
        match self {
            AuthenticationError::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
            AuthenticationError::BackendUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    pub fn get_error_code(&self) -> Cow<'static, str> {
        match self {
            AuthenticationError::InternalServer => Cow::Borrowed("internal_error"),
            AuthenticationError::MissingToken => Cow::Borrowed("missing_token"),
            AuthenticationError::InvalidToken => Cow::Borrowed("invalid_token"),
            AuthenticationError::BackendUnavailable => Cow::Borrowed("backend_unavailable"),
        }
    }

    pub fn get_error_message(&self) -> String {
        match self {
            AuthenticationError::InvalidToken => "Invalid authentication token".to_string(),
            _ => self.to_string(),
        }
    }
}

impl IntoApiError for AuthenticationError {
    fn into_api_error(self) -> ApiError {
        let challenge = match &self {
            AuthenticationError::MissingToken => Some("Bearer"),
            AuthenticationError::InvalidToken => Some("Bearer error=\"invalid_token\""),
            AuthenticationError::InternalServer | AuthenticationError::BackendUnavailable => None,
        };
        let error = ApiError::new(
            self.get_status(),
            self.get_error_code(),
            Some(self.get_error_message()),
        );
        let error = match challenge {
            Some(challenge) => error.with_header(
                hyper::header::WWW_AUTHENTICATE,
                hyper::header::HeaderValue::from_static(challenge),
            ),
            None => error,
        };
        // A transient trust-backend fault is retryable: tell clients when to
        // try again rather than letting them rotate a perfectly good key.
        if matches!(self, AuthenticationError::BackendUnavailable) {
            error.retry_after(1)
        } else {
            error
        }
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
        let err = AuthenticationError::MissingToken;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[hyper::header::WWW_AUTHENTICATE],
            "Bearer"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "missing_token");
        assert_eq!(json["error_description"], "Missing bearer token");
    }

    #[tokio::test]
    async fn backend_unavailable_is_a_retryable_503_not_a_401() {
        let err = AuthenticationError::BackendUnavailable;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response
                .headers()
                .get(hyper::header::WWW_AUTHENTICATE)
                .is_none(),
            "a backend fault must not issue a Bearer challenge"
        );
        assert_eq!(
            response.headers()[hyper::header::RETRY_AFTER],
            "1",
            "a transient trust-backend fault must be retryable"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "backend_unavailable");
    }
}
