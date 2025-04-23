use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    auth::{authentication::verify_token, errors::AuthenticationError},
    utils::state::AppState,
};

pub struct AuthenticatedIssuer(pub String);

impl<S> FromRequestParts<S> for AuthenticatedIssuer
where
    S: Send + Sync + 'static,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Get the Authorization header
        let auth_header = parts
            .headers
            .get("Authorization")
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

        // Verify the token
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
