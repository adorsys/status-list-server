use axum::{
    Json,
    http::{HeaderValue, StatusCode},
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

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub error: Cow<'static, str>,
    pub error_description: Option<String>,
    /// Allowed on any status (RFC 9110 §10.2.3), not just 503 and 429.
    pub retry_after_secs: Option<u64>,
    /// For headers like Vary that must ride along on errors such as 406.
    pub extra_headers: Vec<(axum::http::HeaderName, HeaderValue)>,
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
            retry_after_secs: None,
            extra_headers: Vec::new(),
        }
    }

    pub(crate) fn with_header(mut self, name: axum::http::HeaderName, value: HeaderValue) -> Self {
        self.extra_headers.push((name, value));
        self
    }

    fn retry_after(mut self, secs: u64) -> Self {
        self.retry_after_secs = Some(secs);
        self
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

    /// 409, not 503: matches the version-conflict response and keeps contention out of the SLO.
    /// Unlike update_conflict, the client can retry this unchanged.
    pub fn write_contention() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "write_contention",
            Some(
                "The write lost a lock race in storage and was rolled back. \
                 Nothing was modified; retry the same request."
                    .into(),
            ),
        )
        // A floor; clients add jitter so collided writers don't retry in lockstep.
        .retry_after(1)
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
            // Info, so write contention doesn't trip alerts.
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

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store, max-age=0"),
        );
        if let Some(secs) = self.retry_after_secs {
            // Can't fail for our values, but not worth a panic.
            if let Ok(value) = axum::http::HeaderValue::try_from(secs.to_string()) {
                headers.insert(axum::http::header::RETRY_AFTER, value);
            }
        }
        for (name, value) in self.extra_headers {
            debug_assert!(
                name != axum::http::header::CACHE_CONTROL
                    && name != axum::http::header::RETRY_AFTER,
                "with_header must not overwrite the managed Cache-Control/Retry-After headers"
            );
            headers.insert(name, value);
        }

        let body = ErrorResponse {
            error: self.error,
            error_description: self.error_description,
        };
        (self.status, headers, Json(body)).into_response()
    }
}

/// Resolved per call: a meter cached before setup_metrics would stay a no-op forever.
fn record_write_contention(resource: &'static str, code: &'static str) {
    use opentelemetry::KeyValue;

    opentelemetry::global::meter("status-list-server")
        .u64_counter("db_write_contention")
        .with_description(
            "Writes rolled back by a storage-level lock race (deadlock or lock-wait timeout).",
        )
        .with_unit("{write}")
        .build()
        .add(
            1,
            &[
                KeyValue::new("resource", resource),
                KeyValue::new("code", code),
            ],
        );
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
            StatusListError::InvalidStatusList(msg) => ApiError::bad_request("invalid_input", msg),
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
                ApiError::bad_request("invalid_historical_time", "Invalid historical query time")
            }
            StatusListError::IssuerMismatch => {
                ApiError::forbidden("issuer_mismatch", "Issuer does not own the status list")
            }
            StatusListError::TooLarge => ApiError::unprocessable(
                "status_too_large",
                "Serialized status list size exceeds configured maximum",
            ),
            StatusListError::TooManyStatuses { count, max } => ApiError::bad_request(
                "too_many_statuses",
                format!("too many statuses in request: {count} > {max}"),
            ),
            StatusListError::IndexTooLarge { index, max } => ApiError::bad_request(
                "index_too_large",
                format!("status index {index} exceeds configured maximum {max}"),
            ),
            StatusListError::DuplicateIndex { index } => ApiError::bad_request(
                "duplicate_index",
                format!("duplicate status index {index} in statuses array"),
            ),
            StatusListError::IndexOutOfRange { index, size } => ApiError::bad_request(
                "index_out_of_range",
                format!("status index {index} is outside the fixed status list size {size}"),
            ),
            StatusListError::InvalidSize { size, max } => ApiError::bad_request(
                "invalid_size",
                format!("status list size {size} is invalid; expected 1..={max}"),
            ),
            StatusListError::InvalidAllocationCount { count, max } => ApiError::bad_request(
                "invalid_count",
                format!("allocation count {count} is invalid; expected 1..={max}"),
            ),
            StatusListError::IndexNotAllocated { index } => ApiError::conflict(
                "index_not_allocated",
                format!("status index {index} has not been allocated"),
            ),
            StatusListError::ListNotFixedSize => ApiError::conflict(
                "list_not_fixed_size",
                "status list must be fixed-size to allocate indices",
            ),
            StatusListError::AllocationExhausted => ApiError::conflict(
                "allocation_exhausted",
                "status list does not have enough unallocated indices",
            ),
            // Not 429 (waiting won't free a slot) and not 403 (reserved for ownership).
            StatusListError::QuotaExceeded { count, max } => ApiError::bad_request(
                "list_quota_exceeded",
                format!("issuer already has {count} status lists; the configured maximum is {max}"),
            ),
            StatusListError::Conflict => ApiError::conflict(
                "update_conflict",
                "The status list was modified concurrently",
            ),
            StatusListError::Contention { code } => {
                record_write_contention("status_list", code);
                ApiError::write_contention()
            }
            StatusListError::Unavailable => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                Some("the service is currently unavailable. Please try again later".into()),
            ),
            StatusListError::Backend(err) => ApiError::internal(err),
            StatusListError::TokenExpiryOverflow { .. } => ApiError::internal(
                "token exp overflowed the configured token lifetime; check APP_STATUS_LIST__TOKEN_EXP_SECS",
            ),
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
                "Credentials already exist for this issuer or key ID",
            ),
            CredentialError::Contention { code } => {
                record_write_contention("credential", code);
                ApiError::write_contention()
            }
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
                StatusListError::InvalidStatusList("test".into()),
                StatusCode::BAD_REQUEST,
                "invalid_input",
            ),
            (
                StatusListError::CorruptStoredList("test".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
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
                "invalid_historical_time",
            ),
            (
                StatusListError::IssuerMismatch,
                StatusCode::FORBIDDEN,
                "issuer_mismatch",
            ),
            (
                StatusListError::TooLarge,
                StatusCode::UNPROCESSABLE_ENTITY,
                "status_too_large",
            ),
            (
                StatusListError::TooManyStatuses { count: 2, max: 1 },
                StatusCode::BAD_REQUEST,
                "too_many_statuses",
            ),
            (
                StatusListError::IndexTooLarge { index: 2, max: 1 },
                StatusCode::BAD_REQUEST,
                "index_too_large",
            ),
            (
                StatusListError::DuplicateIndex { index: 3 },
                StatusCode::BAD_REQUEST,
                "duplicate_index",
            ),
            (
                StatusListError::IndexOutOfRange { index: 3, size: 3 },
                StatusCode::BAD_REQUEST,
                "index_out_of_range",
            ),
            (
                StatusListError::AllocationExhausted,
                StatusCode::CONFLICT,
                "allocation_exhausted",
            ),
            (
                StatusListError::QuotaExceeded { count: 2, max: 2 },
                StatusCode::BAD_REQUEST,
                "list_quota_exceeded",
            ),
            (
                StatusListError::Conflict,
                StatusCode::CONFLICT,
                "update_conflict",
            ),
            (
                StatusListError::Contention { code: "40001" },
                StatusCode::CONFLICT,
                "write_contention",
            ),
            (
                StatusListError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            ),
            (
                StatusListError::Backend(Box::new(std::io::Error::other("test"))),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            (
                StatusListError::TokenExpiryOverflow {
                    iat: 1_000,
                    token_exp_secs: 900,
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ];

        for (err, expected_status, expected_code) in cases {
            let api_err: ApiError = err.into();
            assert_eq!(api_err.status, expected_status, "Status mismatch");
            assert_eq!(api_err.error.as_ref(), expected_code, "Code mismatch");
        }
    }

    #[test]
    fn test_credential_error_all_variants_convert() {
        let cases = vec![
            (
                CredentialError::InvalidPublicJwk("test".into()),
                StatusCode::BAD_REQUEST,
                "invalid_public_jwk",
            ),
            (
                CredentialError::AlreadyExists,
                StatusCode::CONFLICT,
                "credentials_already_exist",
            ),
            (
                CredentialError::Contention { code: "1213" },
                StatusCode::CONFLICT,
                "write_contention",
            ),
            (
                CredentialError::Backend(Box::new(std::io::Error::other("test"))),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ];

        for (err, expected_status, expected_code) in cases {
            let api_err: ApiError = err.into();
            assert_eq!(api_err.status, expected_status, "Status mismatch");
            assert_eq!(api_err.error.as_ref(), expected_code, "Code mismatch");
        }
    }

    #[tokio::test]
    async fn test_status_list_error_into_response_contains_snake_case_code() {
        let err = StatusListError::NotFound;
        let api_err: ApiError = err.into();
        let response = api_err.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let cache_control = response
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .expect("Cache-Control header should be present");
        assert_eq!(cache_control, "no-store, max-age=0");

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(
            body_str.contains("\"error\":\"status_list_not_found\""),
            "Response body should contain error code"
        );
        assert!(
            body_str.contains("\"error_description\""),
            "Response body should contain error_description field"
        );
        assert!(
            body_str.contains("Status list was not found"),
            "Response body should contain error description text"
        );
    }

    #[test]
    fn test_api_error_internal_logs_and_returns_500() {
        let api_err = ApiError::internal("something broke");
        assert_eq!(api_err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(api_err.error, "internal_error");
    }

    #[tokio::test]
    async fn test_contention_response_never_logs_at_error() {
        use std::sync::{Arc, Mutex};
        use tracing::subscriber;
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Default)]
        struct Levels(Arc<Mutex<Vec<tracing::Level>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Levels {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.0.lock().unwrap().push(*event.metadata().level());
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let layer = Levels(seen.clone());
        let dispatch = tracing_subscriber::registry().with(layer);

        subscriber::with_default(dispatch, || {
            let _ = ApiError::from(StatusListError::Contention { code: "1213" }).into_response();
            let _ = ApiError::from(CredentialError::Contention { code: "40P01" }).into_response();
        });

        let levels = seen.lock().unwrap();
        assert!(!levels.is_empty(), "expected the conflict to be logged");
        assert!(
            !levels.contains(&tracing::Level::ERROR),
            "contention must not log at ERROR; got {levels:?}"
        );
    }

    #[tokio::test]
    async fn test_write_contention_response_carries_retry_after() {
        let api_err: ApiError = StatusListError::Contention { code: "40001" }.into();
        let response = api_err.into_response();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .expect("write_contention must advertise Retry-After"),
            "1"
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .expect("Cache-Control must survive the Retry-After addition"),
            "no-store, max-age=0"
        );
    }

    #[tokio::test]
    async fn test_other_errors_do_not_carry_retry_after() {
        for err in [
            StatusListError::AlreadyExists,
            StatusListError::Conflict,
            StatusListError::NotFound,
            StatusListError::Unavailable,
            StatusListError::QuotaExceeded { count: 1, max: 1 },
        ] {
            let api_err: ApiError = err.into();
            let error_code = api_err.error.clone();
            let response = api_err.into_response();
            assert!(
                response
                    .headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .is_none(),
                "{error_code} must not advertise Retry-After"
            );
        }
    }

    #[tokio::test]
    async fn test_extra_headers_are_emitted() {
        let err = ApiError::new(
            StatusCode::NOT_ACCEPTABLE,
            "invalid_accept_header",
            Some("No acceptable media type.".into()),
        )
        .with_header(
            axum::http::header::VARY,
            HeaderValue::from_static("Accept, Accept-Encoding"),
        );
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            response.headers().get(axum::http::header::VARY).unwrap(),
            "Accept, Accept-Encoding"
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "no-store, max-age=0"
        );
    }

    #[tokio::test]
    async fn test_the_two_conflicts_are_distinguishable_in_the_body() {
        async fn error_code_of(err: StatusListError) -> String {
            let response = ApiError::from(err).into_response();
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"]
                .as_str()
                .unwrap()
                .to_string()
        }

        assert_eq!(
            error_code_of(StatusListError::Conflict).await,
            "update_conflict"
        );
        assert_eq!(
            error_code_of(StatusListError::Contention { code: "1205" }).await,
            "write_contention"
        );
    }
}

#[cfg(test)]
mod additional_tests {
    use super::*;

    #[tokio::test]
    async fn test_error_response_sets_no_store() {
        let api_err = ApiError::not_found("test_error", "test description");
        let response = api_err.into_response();

        let cache_control = response
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .expect("Cache-Control header must be present on error responses");
        assert_eq!(
            cache_control, "no-store, max-age=0",
            "Error responses must include Cache-Control: no-store to prevent caching of errors"
        );
    }
}
