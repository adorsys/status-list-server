use axum::response::IntoResponse;
use status_list_server::web::auth::errors::AuthenticationError;
use status_list_server::web::errors::ApiError;
use status_list_server::web::handlers::status_list::error::StatusListError;

#[test]
fn test_api_error_new_generates_trace_id() {
    let error = ApiError::new("TEST_ERROR", "Test message");
    assert!(!error.trace_id.is_empty());
    assert_eq!(error.error, "TEST_ERROR");
    assert_eq!(error.message, "Test message");
    assert!(error.details.is_none());
}

#[test]
fn test_api_error_with_details() {
    let details = serde_json::json!({"field": "value"});
    let error = ApiError::new("TEST_ERROR", "Test message").with_details(details.clone());
    assert_eq!(error.details, Some(details));
}

#[test]
fn test_api_error_status_mapping() {
    let cases = vec![
        ("STATUS_LIST_NOT_FOUND", axum::http::StatusCode::NOT_FOUND),
        ("INVALID_LIST_ID", axum::http::StatusCode::BAD_REQUEST),
        ("DUPLICATE_ENTRY", axum::http::StatusCode::CONFLICT),
        ("FORBIDDEN", axum::http::StatusCode::FORBIDDEN),
        (
            "INTERNAL_SERVER_ERROR",
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        ),
        ("INVALID_AUTH_HEADER", axum::http::StatusCode::UNAUTHORIZED),
        (
            "SERVICE_UNAVAILABLE",
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        ),
    ];

    for (code, expected_status) in cases {
        let error = ApiError::new(code, "test");
        assert_eq!(
            error.determine_status_code(),
            expected_status,
            "Error code {} should map to {:?}",
            code,
            expected_status
        );
    }
}

#[test]
fn test_status_list_error_into_response_returns_structured_json() {
    let error = StatusListError::StatusListNotFound;
    let response = error.into_response();
    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[test]
fn test_status_list_error_all_variants_are_convertible() {
    let errors = vec![
        StatusListError::InvalidListId("id".into()),
        StatusListError::InvalidAcceptHeader,
        StatusListError::InternalServerError,
        StatusListError::InvalidIndex,
        StatusListError::Generic("msg".into()),
        StatusListError::UpdateFailed,
        StatusListError::MalformedBody("msg".into()),
        StatusListError::StatusListNotFound,
        StatusListError::UnsupportedBits,
        StatusListError::DecodeError,
        StatusListError::DecompressionError("msg".into()),
        StatusListError::CompressionError("msg".into()),
        StatusListError::StatusListAlreadyExists,
        StatusListError::Forbidden("msg".into()),
        StatusListError::TokenAlreadyExists,
        StatusListError::IssuerMismatch,
        StatusListError::ServiceUnavailable,
    ];

    for error in errors {
        let response = error.into_response();
        assert!(
            response.status().is_server_error() || response.status().is_client_error(),
            "Error response should have 4xx or 5xx status, got {:?}",
            response.status()
        );
    }
}

#[test]
fn test_status_list_error_status_codes() {
    let status_codes = vec![
        (
            StatusListError::InvalidListId("id".into()),
            axum::http::StatusCode::BAD_REQUEST,
        ),
        (
            StatusListError::InvalidAcceptHeader,
            axum::http::StatusCode::NOT_ACCEPTABLE,
        ),
        (
            StatusListError::StatusListNotFound,
            axum::http::StatusCode::NOT_FOUND,
        ),
        (
            StatusListError::StatusListAlreadyExists,
            axum::http::StatusCode::CONFLICT,
        ),
        (
            StatusListError::ServiceUnavailable,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            StatusListError::Forbidden("msg".into()),
            axum::http::StatusCode::FORBIDDEN,
        ),
    ];

    for (error, expected_status) in status_codes {
        let response = error.into_response();
        assert_eq!(response.status(), expected_status);
    }
}

#[test]
fn test_authentication_error_into_response() {
    let error = AuthenticationError::InvalidAuthorizationHeader;
    let response = error.into_response();
    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[test]
fn test_api_error_unknown_code_defaults_to_500() {
    let error = ApiError::new("UNKNOWN_CODE_XYZ", "test");
    assert_eq!(
        error.determine_status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
}
