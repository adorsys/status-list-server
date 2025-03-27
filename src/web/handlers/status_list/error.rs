use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StatusListError {
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
    #[error("Malformed body: {0}")]
    MalformedBody(String),
    #[error("Status list not found")]
    StatusListNotFound,
    #[error("Unsupported bits value")]
    UnsupportedBits,
    #[error("Could not decode lst")]
    DecodeError,
    #[error("Decompression error: {0}")]
    DecompressionError(String),
    #[error("Compression error: {0}")]
    CompressionError(String),
}

impl IntoResponse for StatusListError {
    fn into_response(self) -> axum::response::Response {
        use StatusListError::*;
        let status_code = match self {
            InvalidAcceptHeader => StatusCode::BAD_REQUEST,
            InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            InvalidIndex => StatusCode::BAD_REQUEST,
            Generic(_) => StatusCode::BAD_REQUEST,
            UpdateFailed => StatusCode::INTERNAL_SERVER_ERROR,
            MalformedBody(_) => StatusCode::BAD_REQUEST,
            StatusListNotFound => StatusCode::NOT_FOUND,
            UnsupportedBits => StatusCode::BAD_REQUEST,
            DecodeError => StatusCode::BAD_REQUEST,
            DecompressionError(_) => StatusCode::BAD_REQUEST,
            CompressionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status_code, self.to_string()).into_response()
    }
}
