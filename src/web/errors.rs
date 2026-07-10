use std::borrow::Cow;

use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

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

        (self.status, Json(body)).into_response()
    }
}

impl ApiError {
    pub fn internal(source: impl std::fmt::Display) -> Self {
        tracing::error!(error = %source, "internal server error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: Cow::Borrowed("internal_error"),
            error_description: Some("The server encountered an unexpected error.".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
    fn get_status(&self) -> StatusCode {
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

    fn get_error_code(&self) -> Cow<'static, str> {
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

impl From<StatusListError> for ApiError {
    fn from(err: StatusListError) -> Self {
        Self {
            status: err.get_status(),
            error: err.get_error_code(),
            error_description: Some(err.get_error_message()),
        }
    }
}

impl From<crate::web::auth::errors::AuthenticationError> for ApiError {
    fn from(err: crate::web::auth::errors::AuthenticationError) -> Self {
        Self {
            status: err.get_status(),
            error: err.get_error_code(),
            error_description: Some(err.get_error_message()),
        }
    }
}

pub struct ApiJson<T>(pub T);

impl<S, T> axum::extract::FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(inner) =
            Json::<T>::from_request(req, state)
                .await
                .map_err(|_: JsonRejection| {
                    ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "request body is missing or malformed JSON",
                    )
                })?;
        Ok(Self(inner))
    }
}
