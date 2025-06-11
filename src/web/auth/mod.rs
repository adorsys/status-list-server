pub mod errors;

use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use errors::AuthenticationError;
use hyper::header;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::utils::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    exp: usize,
    iat: usize,
}

/// Authentication middleware acting as a safeguard for unauthorized issuers
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, AuthenticationError> {
    // Try to extract token from Authorization header
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or_else(|| AuthenticationError::MissingAuthHeader)?;

    // We decode without verification to get the issuer
    let issuer = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(&[]),
        &Validation::default(),
    )?
    .claims
    .iss;

    // Check if issuer is in database and get its credentials
    let credential = &state
        .credential_repository
        .find_one_by(issuer.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to find credential for {issuer}: {e:?}");
            AuthenticationError::InternalServer
        })?
        .ok_or(AuthenticationError::IssuerNotFound)?;

    // Get the decoding key
    let decoding_key = match credential.alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => DecodingKey::from_rsa_pem(credential.public_key.as_bytes()),
        Algorithm::ES256 | Algorithm::ES384 => {
            DecodingKey::from_ec_pem(credential.public_key.as_bytes())
        }
        Algorithm::EdDSA => DecodingKey::from_ed_pem(credential.public_key.as_bytes()),
        _ => return Err(AuthenticationError::UnsupportedAlgorithm),
    }?;

    let mut validation = Validation::new(credential.alg);
    validation.set_issuer(&[&credential.issuer]);

    // Verify the token to ensure that the issuer is the same as the one in the database
    let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)?;

    // Insert issuer into request extensions
    request.extensions_mut().insert(token_data.claims.iss);
    Ok(next.run(request).await)
}
