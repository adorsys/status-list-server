use axum::{
    body::Body,
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;

use hyper::{header, Request};

use crate::{
    auth::{authentication::verify_token, errors::AuthenticationError},
    utils::state::AppState,
};

/// Represents an authenticated issuer in the system.
/// This struct is used to store and pass the authenticated issuer's ID through the request pipeline.
#[derive(Clone)]
pub struct AuthenticatedIssuer(pub String);

/// Implementation of FromRequestParts for AuthenticatedIssuer.
/// This allows Axum to automatically extract and validate the authenticated issuer from incoming requests.
impl<S> FromRequestParts<S> for AuthenticatedIssuer
where
    S: Send + Sync + 'static,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    /// Extracts and validates the authenticated issuer from the request.
    /// This function:
    /// 1. Gets the Authorization header
    /// 2. Extracts the Bearer token
    /// 3. Verifies the token
    /// 4. Extracts the issuer ID from the token
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Get the Authorization header and validate its presence
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "Missing Authorization header").into_response()
            })?;

        // Extract the token from the Bearer scheme
        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid Authorization header format",
            )
                .into_response()
        })?;

        // Verify the token and extract the issuer
        match verify_token(&app_state, token).await {
            Ok(true) => {
                // Extract the issuer from the token header
                let header = jsonwebtoken::decode_header(token).map_err(|_| {
                    (StatusCode::UNAUTHORIZED, "Invalid token format").into_response()
                })?;

                let issuer = header.kid.ok_or_else(|| {
                    (
                        StatusCode::UNAUTHORIZED,
                        "Missing issuer identifier in token",
                    )
                        .into_response()
                })?;

                // Store the authenticated issuer in the request extensions
                parts.extensions.insert(AuthenticatedIssuer(issuer.clone()));
                Ok(AuthenticatedIssuer(issuer))
            }
            Ok(false) => Err((StatusCode::UNAUTHORIZED, "Invalid token").into_response()),
            Err(AuthenticationError::IssuerNotFound) => {
                Err((StatusCode::UNAUTHORIZED, "Issuer not found").into_response())
            }
            Err(_) => {
                Err((StatusCode::INTERNAL_SERVER_ERROR, "Authentication error").into_response())
            }
        }
    }
}

/// Middleware function for authentication.
/// This function:
/// 1. Extracts the token from the Authorization header
/// 2. Verifies the token
/// 3. Processes the request body
/// 4. Continues the request pipeline if authentication is successful
pub async fn auth(
    appstate: Arc<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Extract and validate the Bearer token
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
        Ok(true) => {}
        Ok(false) | Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                AuthenticationError::VerificationFailed.to_string(),
            ));
        }
    }

    // Process the request body
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

    // Reconstruct the request with the processed body
    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(json_body);

    // Continue the request pipeline
    Ok(next.run(request).await)
}
