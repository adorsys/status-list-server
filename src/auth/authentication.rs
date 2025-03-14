use std::str::FromStr;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::{database::error::RepositoryError, model::Credentials, utils::state::AppState};

use super::errors::AuthenticationError;

/// Handle JWT registration
pub async fn publish_credentials(
    credentials: Credentials,
    state: AppState,
) -> Result<(), RepositoryError> {
    // try storing connection with token issuer
    if let Some(store) = state.repository {
        Ok(store.credential_repository.insert_one(credentials).await?)
    } else {
        Err(RepositoryError::RepositoryNotSet)?
    }
}

pub async fn verify_token(state: &AppState, token: &str) -> Result<bool, AuthenticationError> {
    let store = state
        .repository
        .as_ref()
        .ok_or(AuthenticationError::RepositoryNotSet)?;

    let header = decode_header(token).map_err(|_| AuthenticationError::InvalidToken)?;
    let kid = header.kid.ok_or(AuthenticationError::MissingKid)?;

    let credential = store
        .credential_repository
        .find_one_by(kid)
        .await
        .map_err(|e| AuthenticationError::Generic(e.to_string()))?;

    let key_json = serde_json::to_string(&credential.public_key)
        .map_err(|_| AuthenticationError::Generic("Failed to serialize public key".to_string()))?;

    let decoding_key = DecodingKey::from_rsa_pem(key_json.as_bytes())
        .map_err(|_| AuthenticationError::Generic("Invalid public key".to_string()))?;

    let algorithm = Algorithm::from_str(&credential.alg)
        .map_err(|_| AuthenticationError::Generic("Invalid algorithm".to_string()))?;

    let validation = Validation::new(algorithm);

    Ok(decode::<Value>(token, &decoding_key, &validation)
        .map(|_| true)
        .unwrap_or_else(|_| false))
}
