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
            AuthenticationError::MissingToken => Cow::Borrowed("missing_token"),
            AuthenticationError::InvalidToken => Cow::Borrowed("invalid_token"),
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
            AuthenticationError::InternalServer => None,
        };
        let error = ApiError::new(
            self.get_status(),
            self.get_error_code(),
            Some(self.get_error_message()),
        );
        match challenge {
            Some(challenge) => error.with_header(
                hyper::header::WWW_AUTHENTICATE,
                hyper::header::HeaderValue::from_static(challenge),
            ),
            None => error,
        }
    }
}

/// Response extension marking a request the client failed to authenticate,
/// which the management write gate charges to the client address.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticationRejected;

impl IntoResponse for AuthenticationError {
    fn into_response(self) -> axum::response::Response {
        let rejected = !matches!(self, AuthenticationError::InternalServer);
        let mut response = self.into_api_error().into_response();
        if rejected {
            response.extensions_mut().insert(AuthenticationRejected);
        }
        response
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
}
