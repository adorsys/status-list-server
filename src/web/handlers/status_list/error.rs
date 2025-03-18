use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;

#[derive(Debug, Error)]
pub(super) enum StatusListError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("JWT encoding error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid accept header")]
    InvalidAcceptHeader,
    #[error("Status list not found")]
    NotFound,
}

impl IntoResponse for StatusListError {
    fn into_response(self) -> axum::response::Response {
        use StatusListError::*;
        let status_code = match self {
            Database(_) | StatusListError::Jwt(_) => StatusCode::INTERNAL_SERVER_ERROR,
            InvalidAcceptHeader => StatusCode::BAD_REQUEST,
            NotFound => StatusCode::NOT_FOUND,
        };

        (status_code, self.to_string()).into_response()
    }
}
