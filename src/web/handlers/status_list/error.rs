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
            MalformedBody(_) => StatusCode::BAD_REQUEST,
            StatusListNotFound => StatusCode::NOT_FOUND,
            UnsupportedBits => StatusCode::BAD_REQUEST,
            DecodeError => StatusCode::BAD_REQUEST,
            DecompressionError(_) => StatusCode::BAD_REQUEST,
            CompressionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            StatusListAlreadyExists => StatusCode::CONFLICT,
            Forbidden(_) => StatusCode::FORBIDDEN,
            TokenAlreadyExists => StatusCode::CONFLICT,
            IssuerMismatch => StatusCode::FORBIDDEN,
            ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
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
            MalformedBody(_) => Cow::Borrowed("malformed_body"),
            StatusListNotFound => Cow::Borrowed("status_list_not_found"),
            UnsupportedBits => Cow::Borrowed("unsupported_bits"),
            DecodeError => Cow::Borrowed("decode_error"),
            DecompressionError(_) => Cow::Borrowed("decompression_error"),
            CompressionError(_) => Cow::Borrowed("compression_error"),
            StatusListAlreadyExists => Cow::Borrowed("status_list_already_exists"),
            Forbidden(_) => Cow::Borrowed("forbidden"),
            TokenAlreadyExists => Cow::Borrowed("token_already_exists"),
            IssuerMismatch => Cow::Borrowed("issuer_mismatch"),
            ServiceUnavailable => Cow::Borrowed("service_unavailable"),
        }
    }

    pub(crate) fn get_error_message(&self) -> String {
        self.to_string()
    }
}
