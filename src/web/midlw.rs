use axum::{body::Body, middleware::Next};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;

use axum::response::IntoResponse;
use hyper::{header, Request, StatusCode};

use crate::{
    auth::{authentication::verify_token, errors::AuthenticationError},
    utils::state::AppState,
};

pub async fn auth(
    appstate: Arc<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                AuthenticationError::MissingAuthHeader.to_string(),
            )
        })?;

    // Verify the token
    match verify_token(&appstate, token).await {
        Ok(_) => {}
        Err(err) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                err.to_string(),
            ));
        }
    }

    let (parts, body) = request.into_parts();
    let collected = BodyExt::collect(body).await.map_err(|err| {
        tracing::error!("Failed to read request body: {err:?}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read request body".to_string(),
        )
    })?;

    let bytes = collected.to_bytes();
    let json_body: Value = serde_json::from_slice(&bytes).map_err(|err| {
        tracing::error!("Failed to parse JSON body: {err:?}");
        (
            StatusCode::BAD_REQUEST,
            "Failed to parse JSON body".to_string(),
        )
    })?;

    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(json_body);

    Ok(next.run(request).await)
}
