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
    /// RFC 9110 §10.2.3 permits `Retry-After` on any response, not just
    /// 503/429. It is the only machine-readable part of the retry instruction.
    pub retry_after_secs: Option<u64>,
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
        }
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

    /// 409 for a storage-level lock race: the write was rolled back, nothing
    /// landed, and the same request can be retried unchanged.
    ///
    /// Not `update_conflict`, which promises the opposite — that a racing
    /// writer's value won and the client must re-read first.
    ///
    /// Not 503 either, though 503 is the better protocol fit and is the class
    /// generic retry middleware actually replays (409 is treated as terminal by
    /// most SDKs and meshes). 409 is chosen because it matches what the
    /// optimistic guard already returns on the same endpoint and keeps
    /// single-row contention out of the availability SLO. `Retry-After` below
    /// offsets the cost. If clients need to recover without bespoke handling,
    /// revisit: 503 + `Retry-After` already exists in `openapi.yaml`.
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
        // A floor, not a schedule; clients are told to add jitter, since a fixed
        // hint would resynchronise the writers that just collided.
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

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store, max-age=0"),
        );
        if let Some(secs) = self.retry_after_secs {
            // Infallible for the values this module chooses, but not worth a
            // panic on a request that is otherwise handled correctly.
            if let Ok(value) = axum::http::HeaderValue::try_from(secs.to_string()) {
                headers.insert(axum::http::header::RETRY_AFTER, value);
            }
        }

        let body = ErrorResponse {
            error: self.error,
            error_description: self.error_description,
        };
        (self.status, headers, Json(body)).into_response()
    }
}

/// `code` separates waiters that gave up (`1205`/`40001` — lock-wait budget,
/// transaction scope) from cycles the server broke (`1213`/`40P01` — lock
/// ordering); the remediations differ. Both attributes are closed compile-time
/// sets, so there is no cardinality risk.
///
/// The meter is resolved per increment rather than cached: a handle taken before
/// `setup_metrics` installs the global provider would bind a no-op permanently.
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

        // Verify status code
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Verify Cache-Control header is present
        let cache_control = response
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .expect("Cache-Control header should be present");
        assert_eq!(cache_control, "no-store, max-age=0");

        // Verify JSON body contains both error and error_description
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

    /// `Retry-After` is the only machine-actionable part of the retry
    /// instruction; without it the contract is advisory-only.
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

    /// Advertising `Retry-After` on a permanent failure would tell a client to
    /// replay a write that can never succeed.
    #[tokio::test]
    async fn test_other_errors_do_not_carry_retry_after() {
        for err in [
            StatusListError::AlreadyExists,
            StatusListError::Conflict,
            StatusListError::NotFound,
            StatusListError::Unavailable,
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

    /// The two 409s carry opposite instructions, so the field clients branch on
    /// must actually differ.
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
