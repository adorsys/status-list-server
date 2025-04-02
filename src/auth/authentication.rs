use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::{database::error::RepositoryError, model::Credentials, utils::state::AppState};

use super::errors::AuthenticationError;

use super::errors::AuthErrors;

pub async fn publish_credentials(
    credentials: Credentials,
    state: AppState,
) -> Result<(), RepositoryError> {
    // Ensure the repository is available
    let store = state.repository.ok_or(RepositoryError::RepositoryNotSet)?;

    // Check if the issuer already exists
    if store
        .credential_repository
        .find_one_by(credentials.issuer.clone())
        .await?
        .is_some()
    {
        return Err(RepositoryError::DuplicateEntry);
    }

    // Validate the algorithm
    let algorithm = credentials.alg;
    match algorithm {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::ES256 => (),
        _ => return Err(RepositoryError::from(AuthErrors::UnknownAlgorithm))?,
    }

    // ensure consistent order in credentials
    let credential = Credentials::new(credentials.issuer, credentials.public_key, credentials.alg);

    // Insert the credentials into the repository
    store.credential_repository.insert_one(credential).await?;

    Ok(())
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
    if let Some(credential) = credential {
        let key_json = serde_json::to_string(&credential.public_key).map_err(|_| {
            AuthenticationError::Generic("Failed to serialize public key".to_string())
        })?;

        let decoding_key = match credential.alg {
            Algorithm::RS256 | Algorithm::RS512 => DecodingKey::from_rsa_pem(key_json.as_bytes())
                .map_err(|_| AuthenticationError::Generic("Invalid RSA public key".to_string())),
            Algorithm::ES256 => DecodingKey::from_ec_pem(key_json.as_bytes())
                .map_err(|_| AuthenticationError::Generic("Invalid EC public key".to_string())),
            Algorithm::HS256 | Algorithm::HS512 => {
                Ok(DecodingKey::from_secret(key_json.as_bytes()))
            }
            _ => Err(AuthenticationError::Generic(
                "Unsupported algorithm".to_string(),
            )),
        }?;

        let algorithm = credential.alg;
        let validation = Validation::new(algorithm);

        match decode::<Value>(token, &decoding_key, &validation) {
            Ok(_) => Ok(true),
            Err(e) => {
                tracing::warn!("Token decoding failed: {}", e);
                Ok(false)
            }
        }
    } else {
        Err(AuthenticationError::IssuerNotFound)
    }
}
