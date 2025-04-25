use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use rand::Rng;
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::{database::error::RepositoryError, model::Credentials, utils::state::AppState};

use super::crypto;
use super::errors::{AuthErrors, AuthenticationError};

// Store nonces with their expiration time
type NonceStore = Arc<RwLock<HashMap<String, (String, i64)>>>;

// Create a global nonce store
lazy_static::lazy_static! {
    static ref NONCE_STORE: NonceStore = Arc::new(RwLock::new(HashMap::new()));
}

pub async fn generate_nonce() -> String {
    let nonce: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store the nonce with a 5-minute expiration
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 300;

    NONCE_STORE
        .write()
        .await
        .insert(nonce.clone(), (nonce.clone(), expiration));
    nonce
}

pub async fn verify_signature(public_key: &str, signature: &str) -> bool {
    // The signature should be base64 encoded
    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(signature) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Clean up expired nonces
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    NONCE_STORE.write().await.retain(|_, (_, exp)| *exp > now);

    // Find the nonce that matches this signature
    let nonce_store = NONCE_STORE.read().await;
    for (nonce, _) in nonce_store.values() {
        match crypto::verify_signature(public_key, nonce.as_bytes(), &signature_bytes) {
            Ok(true) => return true,
            _ => continue,
        }
    }

    false
}

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
