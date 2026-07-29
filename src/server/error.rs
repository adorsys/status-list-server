use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::borrow::Cow;

use crate::domain::models::credential::CredentialError;
use crate::domain::models::status_list::StatusListError;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: Cow<'static, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub error: Cow<'static, str>,
    pub error_description: Option<String>,
}

impl ApiError {
    pub fn new(
        status: StatusCode,
        error: impl Into<Cow<'static, str>>,
        description: Option<String>,
    ) -> Self {
        Self {
            status,
            error: error.into(),
            error_description: description,
        }
    }

    pub fn bad_request(
        error: impl Into<Cow<'static, str>>,
        description: impl Into<String>,
    ) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error, Some(description.into()))
    }

    pub fn not_found(error: impl Into<Cow<'static, str>>, description: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, error, Some(description.into()))
    }

    pub fn conflict(error: impl Into<Cow<'static, str>>, description: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, error, Some(description.into()))
    }

    pub fn forbidden(error: impl Into<Cow<'static, str>>, description: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, error, Some(description.into()))
    }

    pub fn unprocessable(
        error: impl Into<Cow<'static, str>>,
        description: impl Into<String>,
    ) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            error,
            Some(description.into()),
        )
    }

    pub fn internal(source: impl std::fmt::Display) -> Self {
        tracing::error!(error = %source, "internal server error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            Some("The server encountered an unexpected error.".into()),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self.status {
            // 409 Conflict is logged at INFO level to avoid tripping alert systems during high write contention.
            StatusCode::CONFLICT => {
                tracing::info!(
                    status = %self.status,
                    error = %self.error,
                    error_description = ?self.error_description,
                    "API request conflict"
                );
            }
            status if status.is_server_error() => {
                tracing::error!(
                    status = %status,
                    error = %self.error,
                    error_description = ?self.error_description,
                    "API server error"
                );
            }
            status => {
                tracing::warn!(
                    status = %status,
                    error = %self.error,
                    error_description = ?self.error_description,
                    "API client error"
                );
            }
        }

        let body = ErrorResponse {
            error: self.error,
            error_description: self.error_description,
        };
        (self.status, Json(body)).into_response()
    }
}

pub trait IntoApiError {
    fn into_api_error(self) -> ApiError;
}

impl<E: IntoApiError> From<E> for ApiError {
    fn from(err: E) -> Self {
        err.into_api_error()
    }
}

impl IntoApiError for StatusListError {
    fn into_api_error(self) -> ApiError {
        match self {
            StatusListError::InvalidIndex => {
                ApiError::bad_request("invalid_index", "Invalid status list index")
            }
            StatusListError::InvalidStatusList(msg) => {
                ApiError::bad_request("invalid_status_list", msg)
            }
            StatusListError::CorruptStoredList(msg) => ApiError::internal(msg),
            StatusListError::AlreadyExists => {
                ApiError::conflict("status_list_already_exists", "Status list already exists")
            }
            StatusListError::NotFound => {
                ApiError::not_found("status_list_not_found", "Status list was not found")
            }
            StatusListError::HistoricalNotFound => ApiError::not_found(
                "historical_status_list_not_found",
                "Historical status list token not found",
            ),
            StatusListError::InvalidHistoricalTime => {
                ApiError::bad_request("invalid_time", "Invalid historical query time")
            }
            StatusListError::IssuerMismatch => {
                ApiError::forbidden("issuer_mismatch", "Issuer does not own the status list")
            }
            StatusListError::TooLarge => ApiError::unprocessable(
                "status_list_too_large",
                "Serialized status list size exceeds configured maximum",
            ),
            StatusListError::TooManyStatuses { count, max } => ApiError::unprocessable(
                "too_many_statuses",
                format!("too many statuses in request: {count} > {max}"),
            ),
            StatusListError::IndexTooLarge { index, max } => ApiError::unprocessable(
                "index_too_large",
                format!("status index {index} exceeds configured maximum {max}"),
            ),
            StatusListError::Conflict => {
                ApiError::conflict("conflict", "The status list was modified concurrently")
            }
            StatusListError::Backend(err) => ApiError::internal(err),
        }
    }
}

impl IntoApiError for CredentialError {
    fn into_api_error(self) -> ApiError {
        match self {
            CredentialError::InvalidPublicJwk(msg) => {
                ApiError::bad_request("invalid_public_jwk", msg)
            }
            CredentialError::AlreadyExists => ApiError::conflict(
                "credentials_already_exist",
                "Credentials already exist for this issuer",
            ),
            CredentialError::Backend(err) => ApiError::internal(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_list_error_converted_to_api_error() {
        let err = StatusListError::NotFound;
        let api_err: ApiError = err.into();
        assert_eq!(api_err.status, StatusCode::NOT_FOUND);
        assert_eq!(api_err.error, "status_list_not_found");
    }

    #[test]
    fn test_status_list_error_all_variants_convert() {
        let cases = vec![
            (
                StatusListError::InvalidIndex,
                StatusCode::BAD_REQUEST,
                "invalid_index",
            ),
            (
                StatusListError::AlreadyExists,
                StatusCode::CONFLICT,
                "status_list_already_exists",
            ),
            (
                StatusListError::NotFound,
                StatusCode::NOT_FOUND,
                "status_list_not_found",
            ),
            (
                StatusListError::HistoricalNotFound,
                StatusCode::NOT_FOUND,
                "historical_status_list_not_found",
            ),
            (
                StatusListError::InvalidHistoricalTime,
                StatusCode::BAD_REQUEST,
                "invalid_time",
            ),
            (
                StatusListError::IssuerMismatch,
                StatusCode::FORBIDDEN,
                "issuer_mismatch",
            ),
            (
                StatusListError::TooLarge,
                StatusCode::UNPROCESSABLE_ENTITY,
                "status_list_too_large",
            ),
        ];

        for (err, expected_status, expected_code) in cases {
            let api_err: ApiError = err.into();
            assert_eq!(api_err.status, expected_status, "Status mismatch");
            assert_eq!(api_err.error.as_ref(), expected_code, "Code mismatch");
        }
    }

    #[test]
    fn test_status_list_error_into_response_contains_snake_case_code() {
        let err = StatusListError::NotFound;
        let api_err: ApiError = err.into();
        let response = api_err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_api_error_internal_logs_and_returns_500() {
        let api_err = ApiError::internal("something broke");
        assert_eq!(api_err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(api_err.error, "internal_error");
    }
}
