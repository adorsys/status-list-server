use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::{database::error::RepositoryError, model::Credentials, utils::state::AppState};

use super::errors::AuthenticationError;

pub async fn publish_credentials(
    credentials: Credentials,
    state: AppState,
) -> Result<(), RepositoryError> {
    let store = &state.credential_repository;

    // Check for existing issuer
    if store
        .find_one_by(credentials.issuer.clone())
        .await?
        .is_some()
    {
        return Err(RepositoryError::DuplicateEntry);
    }

    let credential = Credentials::new(credentials.issuer, credentials.public_key, credentials.alg);
    store.insert_one(credential).await?;
    Ok(())
}

pub async fn verify_token(state: &AppState, token: &str) -> Result<bool, AuthenticationError> {
    let store = &state.credential_repository;

    let header = decode_header(token).map_err(AuthenticationError::JwtError)?;

    let kid = header.kid.ok_or(AuthenticationError::MissingKid)?;

    let credential = store
        .find_one_by(kid.clone())
        .await
        .map_err(|err| {
            tracing::error!("Failed to find credential for kid {kid}: {err:?}");
            AuthenticationError::DatabaseError(err.to_string())
        })?
        .ok_or(AuthenticationError::IssuerNotFound)?;

    let decoding_key = match credential.alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(DecodingKey::from_secret(credential.public_key.as_bytes()))
        }
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
    }?;

    let mut validation = Validation::new(credential.alg);
    validation.set_issuer(&[credential.issuer]);

    decode::<Value>(token, &decoding_key, &validation)
        .map(|_| true)
        .map_err(AuthenticationError::JwtError)
}
