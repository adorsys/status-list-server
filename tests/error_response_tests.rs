use std::borrow::Cow;

use axum::{body::to_bytes, http::StatusCode, response::IntoResponse};
use status_list_server::web::auth::errors::AuthenticationError;
use status_list_server::web::errors::ApiError;
use status_list_server::web::handlers::status_list::error::StatusListError;

#[test]
fn test_api_error_new_with_all_fields() {
    let error = ApiError::new(
        StatusCode::NOT_FOUND,
        "status_list_not_found",
        "Status list not found",
    );
    assert_eq!(error.status, StatusCode::NOT_FOUND);
    assert_eq!(error.error, Cow::Borrowed("status_list_not_found"));
    assert_eq!(
        error.error_description,
        Some("Status list not found".into())
    );
}

#[test]
fn test_api_error_internal_logs_and_returns_500() {
    let error = ApiError::internal("something went wrong");
    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.error, Cow::Borrowed("internal_error"));
    assert!(error.error_description.is_some());
}

#[test]
fn test_status_list_error_converted_to_api_error() {
    let err = StatusListError::StatusListNotFound;
    let api_err: ApiError = err.into();
    assert_eq!(api_err.status, StatusCode::NOT_FOUND);
    assert_eq!(api_err.error, Cow::Borrowed("status_list_not_found"));
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

#[tokio::test]
async fn test_authentication_error_into_response() {
    let err = AuthenticationError::InvalidAuthorizationHeader;
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_auth_header");
    assert!(json.get("message").is_some());
}

#[test]
fn test_api_error_status_code_not_in_json_body() {
    let error = ApiError::new(StatusCode::NOT_FOUND, "test_error", "test message");
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
