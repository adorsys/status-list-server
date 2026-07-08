use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
    pub trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl ApiError {
    #[must_use]
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
            trace_id: Uuid::new_v4().to_string(),
            details: None,
        }
    }

    #[must_use]
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn determine_status_code(&self) -> StatusCode {
        match self.error.as_str() {
            "INVALID_LIST_ID" => StatusCode::BAD_REQUEST,
            "INVALID_ACCEPT_HEADER" => StatusCode::NOT_ACCEPTABLE,
            "INTERNAL_SERVER_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            "INVALID_INDEX" => StatusCode::BAD_REQUEST,
            "INVALID_INPUT" => StatusCode::BAD_REQUEST,
            "UPDATE_FAILED" => StatusCode::INTERNAL_SERVER_ERROR,
            "MALFORMED_BODY" => StatusCode::BAD_REQUEST,
            "STATUS_LIST_NOT_FOUND" => StatusCode::NOT_FOUND,
            "UNSUPPORTED_BITS" => StatusCode::BAD_REQUEST,
            "DECODE_ERROR" => StatusCode::BAD_REQUEST,
            "DECOMPRESSION_ERROR" => StatusCode::BAD_REQUEST,
            "COMPRESSION_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            "STATUS_LIST_ALREADY_EXISTS" => StatusCode::CONFLICT,
            "FORBIDDEN" => StatusCode::FORBIDDEN,
            "TOKEN_ALREADY_EXISTS" => StatusCode::CONFLICT,
            "ISSUER_MISMATCH" => StatusCode::FORBIDDEN,
            "SERVICE_UNAVAILABLE" => StatusCode::SERVICE_UNAVAILABLE,
            "ISSUER_NOT_FOUND" => StatusCode::UNAUTHORIZED,
            "INVALID_AUTH_HEADER" => StatusCode::UNAUTHORIZED,
            "JWT_ERROR" => StatusCode::UNAUTHORIZED,
            "UNSUPPORTED_ALGORITHM" => StatusCode::UNAUTHORIZED,
            "INSERT_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            "FIND_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            "UPDATE_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            "DELETE_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            "COULD_NOT_STORE_ENTITY" => StatusCode::INTERNAL_SERVER_ERROR,
            "REPOSITORY_NOT_SET" => StatusCode::INTERNAL_SERVER_ERROR,
            "DUPLICATE_ENTRY" => StatusCode::CONFLICT,
            "REPO_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            "AUTH_ERROR" => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = self.determine_status_code();
        tracing::error!(
            trace_id = %self.trace_id,
            error = %self.error,
            message = %self.message,
            "API error"
        );
        (status, Json(self)).into_response()
    }
}
