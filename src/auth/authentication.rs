use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::{database::error::RepositoryError, model::Credentials, utils::state::AppState};

use super::errors::{AuthErrors, AuthenticationError};

pub async fn publish_credentials(
    credentials: Credentials,
    state: AppState,
) -> Result<(), RepositoryError> {
    let store = &state.credential_repository;
    if store
        .find_one_by(credentials.issuer.clone())
        .await?
        .is_some()
    {
        return Err(RepositoryError::DuplicateEntry);
    }
    let algorithm = credentials.alg;
    match algorithm {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::ES256 => (),
        _ => return Err(RepositoryError::from(AuthErrors::UnknownAlgorithm))?,
    }
    let credential = Credentials::new(credentials.issuer, credentials.public_key, credentials.alg);
    store.insert_one(credential).await?;
    Ok(())
}

pub async fn verify_token(state: &AppState, token: &str) -> Result<bool, AuthenticationError> {
    let store = &state.credential_repository;
    let header = decode_header(token).map_err(|_| AuthenticationError::InvalidToken)?;
    let kid = header.kid.ok_or(AuthenticationError::MissingKid)?;
    let credential = store
        .find_one_by(kid)
        .await
        .map_err(|e| AuthenticationError::Generic(e.to_string()))?;
    if let Some(credential) = credential {
        let decoding_key = match credential.alg {
            Algorithm::RS256 | Algorithm::RS512 => {
                DecodingKey::from_rsa_pem(credential.public_key.as_bytes())
                    .map_err(|_| AuthenticationError::Generic("Invalid RSA public key".to_string()))
            }
            Algorithm::ES256 => DecodingKey::from_ec_pem(credential.public_key.as_bytes())
                .map_err(|_| AuthenticationError::Generic("Invalid EC public key".to_string())),
            Algorithm::HS256 | Algorithm::HS512 => {
                Ok(DecodingKey::from_secret(credential.public_key.as_bytes()))
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
