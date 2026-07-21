use std::borrow::Cow;

use axum::http::StatusCode;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StatusListError {
    #[error("Invalid list ID string: {0}")]
    InvalidListId(String),
    #[error("Invalid accept header")]
    InvalidAcceptHeader,
    #[error("Internal server error")]
    InternalServerError,
    #[error("invalid index, status not found")]
    InvalidIndex,
    #[error("error: {0}")]
    Generic(String),
    #[error("failed to update status")]
    UpdateFailed,
    #[error("the status list was modified concurrently; re-read the current state and retry")]
    UpdateConflict,
    #[error("Malformed body: {0}")]
    MalformedBody(String),
    #[error("Status list not found")]
    StatusListNotFound,
    #[error("No status list token is available for the requested time")]
    HistoricalStatusListNotFound,
    #[error("Invalid historical time: must be positive and not in the future")]
    InvalidHistoricalTime,
    #[error("Unsupported bits value")]
    UnsupportedBits,
    #[error("Could not decode lst")]
    DecodeError,
    #[error("Decompression error: {0}")]
    DecompressionError(String),
    #[error("Compression error: {0}")]
    CompressionError(String),
    #[error("Status list already exists")]
    StatusListAlreadyExists,
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Token already exists")]
    TokenAlreadyExists,
    #[error("Issuer mismatch")]
    IssuerMismatch,
    #[error("The service is currently unavailable. Please try again later")]
    ServiceUnavailable,
    #[error("Too many statuses in request: {count} > {max}")]
    TooManyStatuses { count: usize, max: usize },
    #[error("Status index {0} exceeds the configured maximum")]
    IndexTooLarge(i32),
    #[error("Serialized status list size exceeds the configured maximum")]
    StatusTooLarge,
}

impl StatusListError {
    pub(crate) fn get_status(&self) -> StatusCode {
        use StatusListError::*;
        match self {
            InvalidListId(_) => StatusCode::BAD_REQUEST,
            InvalidAcceptHeader => StatusCode::NOT_ACCEPTABLE,
            InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            InvalidIndex => StatusCode::BAD_REQUEST,
            Generic(_) => StatusCode::BAD_REQUEST,
            UpdateFailed => StatusCode::INTERNAL_SERVER_ERROR,
            UpdateConflict => StatusCode::CONFLICT,
            MalformedBody(_) => StatusCode::BAD_REQUEST,
            StatusListNotFound => StatusCode::NOT_FOUND,
            HistoricalStatusListNotFound => StatusCode::NOT_FOUND,
            InvalidHistoricalTime => StatusCode::BAD_REQUEST,
            UnsupportedBits => StatusCode::BAD_REQUEST,
            DecodeError => StatusCode::BAD_REQUEST,
            DecompressionError(_) => StatusCode::BAD_REQUEST,
            CompressionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            StatusListAlreadyExists => StatusCode::CONFLICT,
            Forbidden(_) => StatusCode::FORBIDDEN,
            TokenAlreadyExists => StatusCode::CONFLICT,
            IssuerMismatch => StatusCode::FORBIDDEN,
            ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            TooManyStatuses { .. } => StatusCode::BAD_REQUEST,
            IndexTooLarge(_) => StatusCode::BAD_REQUEST,
            StatusTooLarge => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    pub(crate) fn get_error_code(&self) -> Cow<'static, str> {
        use StatusListError::*;
        match self {
            InvalidListId(_) => Cow::Borrowed("invalid_list_id"),
            InvalidAcceptHeader => Cow::Borrowed("invalid_accept_header"),
            InternalServerError => Cow::Borrowed("internal_error"),
            InvalidIndex => Cow::Borrowed("invalid_index"),
            Generic(_) => Cow::Borrowed("invalid_input"),
            UpdateFailed => Cow::Borrowed("update_failed"),
            UpdateConflict => Cow::Borrowed("update_conflict"),
            MalformedBody(_) => Cow::Borrowed("malformed_body"),
            StatusListNotFound => Cow::Borrowed("status_list_not_found"),
            HistoricalStatusListNotFound => Cow::Borrowed("historical_status_list_not_found"),
            InvalidHistoricalTime => Cow::Borrowed("invalid_historical_time"),
            UnsupportedBits => Cow::Borrowed("unsupported_bits"),
            DecodeError => Cow::Borrowed("decode_error"),
            DecompressionError(_) => Cow::Borrowed("decompression_error"),
            CompressionError(_) => Cow::Borrowed("compression_error"),
            StatusListAlreadyExists => Cow::Borrowed("status_list_already_exists"),
            Forbidden(_) => Cow::Borrowed("forbidden"),
            TokenAlreadyExists => Cow::Borrowed("token_already_exists"),
            IssuerMismatch => Cow::Borrowed("issuer_mismatch"),
            ServiceUnavailable => Cow::Borrowed("service_unavailable"),
            TooManyStatuses { .. } => Cow::Borrowed("too_many_statuses"),
            IndexTooLarge(_) => Cow::Borrowed("index_too_large"),
            StatusTooLarge => Cow::Borrowed("status_too_large"),
        }
    }

    pub(crate) fn get_error_message(&self) -> String {
        self.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::errors::ApiError;
    use axum::{body::to_bytes, response::IntoResponse};
    #[test]
    fn test_status_list_error_converted_to_api_error() {
        let err = StatusListError::StatusListNotFound;
        let api_err: ApiError = err.into();
        assert_eq!(api_err.status, StatusCode::NOT_FOUND);
        assert_eq!(api_err.error, "status_list_not_found");
    }

    #[test]
    fn test_status_list_error_all_variants_convert() {
        let cases = vec![
            (
                StatusListError::InvalidListId("id".into()),
                StatusCode::BAD_REQUEST,
                "invalid_list_id",
            ),
            (
                StatusListError::InvalidAcceptHeader,
                StatusCode::NOT_ACCEPTABLE,
                "invalid_accept_header",
            ),
            (
                StatusListError::InternalServerError,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            (
                StatusListError::StatusListNotFound,
                StatusCode::NOT_FOUND,
                "status_list_not_found",
            ),
            (
                StatusListError::StatusListAlreadyExists,
                StatusCode::CONFLICT,
                "status_list_already_exists",
            ),
            (
                StatusListError::Forbidden("msg".into()),
                StatusCode::FORBIDDEN,
                "forbidden",
            ),
            (
                StatusListError::ServiceUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            ),
        ];

        for (err, expected_status, expected_code) in cases {
            let api_err: ApiError = err.into();
            assert_eq!(api_err.status, expected_status, "Status mismatch");
            assert_eq!(api_err.error.as_ref(), expected_code, "Code mismatch");
        }

        let api_err: ApiError = StatusListError::HistoricalStatusListNotFound.into();
        assert_eq!(api_err.status, StatusCode::NOT_FOUND);
        assert_eq!(api_err.error.as_ref(), "historical_status_list_not_found");

        let api_err: ApiError = StatusListError::InvalidHistoricalTime.into();
        assert_eq!(api_err.status, StatusCode::BAD_REQUEST);
        assert_eq!(api_err.error.as_ref(), "invalid_historical_time");
    }

    #[test]
    fn test_status_list_error_into_response_contains_snake_case_code() {
        let err = StatusListError::StatusListNotFound;
        let api_err: ApiError = err.into();
        let response = api_err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { to_bytes(response.into_body(), usize::MAX).await.unwrap() });
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "status_list_not_found");
        assert!(json.get("error_description").is_some());
    }
}
