use std::borrow::Cow;

use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::adapters::sea_orm::error::RepositoryError;
use crate::web::auth::errors::AuthenticationError;
use crate::web::handlers::issue_credential::CredentialError;
use crate::web::handlers::status_list::error::StatusListError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    #[serde(skip)]
    pub status: StatusCode,
    pub error: Cow<'static, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl ApiError {
    #[must_use]
    pub fn new(
        status: StatusCode,
        error: impl Into<Cow<'static, str>>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            error: error.into(),
            error_description: Some(message.into()),
        }
    }

    pub fn internal(source: impl std::fmt::Display) -> Self {
        tracing::error!(error = %source, "internal server error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: Cow::Borrowed("internal_error"),
            error_description: Some("The server encountered an unexpected error.".into()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body<'a> {
            error: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            error_description: Option<&'a str>,
        }

        tracing::error!(
            status = %self.status,
            error = %self.error,
            error_description = ?self.error_description,
            "API error"
        );

        let body = Body {
            error: self.error.as_ref(),
            error_description: self.error_description.as_deref(),
        };

        (
            self.status,
            [(header::CACHE_CONTROL, "no-store, max-age=0")],
            Json(body),
        )
            .into_response()
    }
}

impl From<CredentialError> for ApiError {
    fn from(err: CredentialError) -> Self {
        match err {
            CredentialError::AuthError(err) => ApiError::from(err),
            CredentialError::AlreadyExists => ApiError::new(
                StatusCode::CONFLICT,
                "credentials_already_exist",
                "Credentials already exist for this issuer",
            ),
            CredentialError::Port => ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "The server encountered an unexpected error.",
            ),
        }
    }
}

impl From<RepositoryError> for ApiError {
    fn from(err: RepositoryError) -> Self {
        tracing::error!(error = %err, "repository error");
        let (status, error_code, description) = match &err {
            RepositoryError::DuplicateEntry => (
                StatusCode::CONFLICT,
                Cow::Borrowed("duplicate_entry"),
                "A duplicate entry was detected.",
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Cow::Borrowed("internal_error"),
                "An internal error occurred.",
            ),
        };
        Self {
            status,
            error: error_code,
            error_description: Some(description.to_string()),
        }
    }
}

impl From<AuthenticationError> for ApiError {
    fn from(err: AuthenticationError) -> Self {
        Self {
            status: err.get_status(),
            error: err.get_error_code(),
            error_description: Some(err.get_error_message()),
        }
    }
}

impl From<StatusListError> for ApiError {
    fn from(err: StatusListError) -> Self {
        Self {
            status: err.get_status(),
            error: err.get_error_code(),
            error_description: Some(err.get_error_message()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn test_api_error_new_with_all_fields() {
        let error = ApiError::new(
            StatusCode::NOT_FOUND,
            "status_list_not_found",
            "Status list not found",
        );
        assert_eq!(error.status, StatusCode::NOT_FOUND);
        assert_eq!(error.error, "status_list_not_found");
        assert_eq!(
            error.error_description,
            Some("Status list not found".into())
        );
    }

    #[test]
    fn test_api_error_internal_logs_and_returns_500() {
        let error = ApiError::internal("something went wrong");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.error, "internal_error");
        assert!(error.error_description.is_some());
    }

    #[test]
    fn test_api_error_status_code_not_in_json_body() {
        let error = ApiError::new(StatusCode::NOT_FOUND, "test_error", "test message");
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { to_bytes(response.into_body(), usize::MAX).await.unwrap() });
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "test_error");
        assert!(json.get("status").is_none());
    }

    #[test]
    fn test_repository_error_does_not_leak_db_details() {
        let db_error_message = "DbErr: error connecting: server error? details: host=secret-db password=supersecret user=admin";
        let repo_error = RepositoryError::Generic(db_error_message.to_string());
        let error = ApiError::from(repo_error);
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { to_bytes(response.into_body(), usize::MAX).await.unwrap() });
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        assert_eq!(json["error"], "internal_error");
        assert!(!body_str.contains("secret-db"));
        assert!(!body_str.contains("supersecret"));
        assert!(!body_str.contains("DbErr"));
        assert!(!body_str.contains("host="));
    }
}
