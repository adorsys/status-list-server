//! Authentication middleware validating bearer JWTs against registered issuer credentials.

pub mod errors;

use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use errors::AuthenticationError;
use hyper::header;
use jsonwebtoken::{DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::server::AppState;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    exp: usize,
}

/// Authentication middleware acting as a safeguard for unauthorized issuers
pub async fn auth(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, AuthenticationError> {
    use jsonwebtoken::dangerous::insecure_decode;

    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or(AuthenticationError::InvalidAuthorizationHeader)?;

    let alg = jsonwebtoken::decode_header(token)?.alg;
    let issuer = insecure_decode::<Claims>(token)?.claims.iss;

    use crate::domain::models::credential::Credential;
    let credential = Credential::find(state.service.credential_repo(), &issuer)
        .await
        .map_err(|e| {
            tracing::error!("Failed to find credential for {issuer}: {e:?}");
            AuthenticationError::InternalServer
        })?
        .ok_or(AuthenticationError::IssuerNotFound)?;

    let public_key = serde_json::from_slice(credential.public_key.as_bytes())
        .map_err(|_| AuthenticationError::InternalServer)?;
    let decoding_key = DecodingKey::from_jwk(&public_key)?;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[&credential.issuer.0]);

    let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)?;

    request.extensions_mut().insert(token_data.claims.iss);
    Ok(next.run(request).await)
}
