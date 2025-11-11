use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use jsonwebtoken::Algorithm;

use crate::{
    database::error::RepositoryError, models::Credentials, utils::state::AppState,
    web::auth::errors::AuthenticationError,
};

#[derive(Debug)]
pub enum CredentialError {
    RepoError(RepositoryError),
    AuthError(AuthenticationError),
}

impl From<RepositoryError> for CredentialError {
    fn from(value: RepositoryError) -> Self {
        CredentialError::RepoError(value)
    }
}

impl From<AuthenticationError> for CredentialError {
    fn from(value: AuthenticationError) -> Self {
        CredentialError::AuthError(value)
    }
}

pub async fn credential_handler(
    State(appstate): State<AppState>,
    Json(credential): Json<Credentials>,
) -> impl IntoResponse {
    match publish_credentials(credential.to_owned(), appstate).await {
        Ok(_) => (StatusCode::ACCEPTED, "Credentials stored successfully").into_response(),
        Err(CredentialError::AuthError(AuthenticationError::JwtError(err))) => {
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
        Err(CredentialError::RepoError(RepositoryError::DuplicateEntry)) => {
            tracing::warn!(
                "Attempted to publish credentials for existing issuer {}",
                credential.issuer,
            );
            (
                StatusCode::CONFLICT,
                "Credentials already exist for this issuer".to_string(),
            )
                .into_response()
        }
        Err(err) => {
            tracing::error!(
                "Failed to store credentials for issuer {}: {err:?}",
                credential.issuer,
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response()
        }
    }
}

pub async fn publish_credentials(
    credentials: Credentials,
    state: AppState,
) -> Result<(), CredentialError> {
    // Validate public key
    validate_pubkey(&credentials.public_key, credentials.alg)?;

    let store = &state.credential_repo;
    // Check for existing issuer
    if store
        .find_one_by(credentials.issuer.clone())
        .await?
        .is_some()
    {
        return Err(CredentialError::RepoError(RepositoryError::DuplicateEntry));
    }

    let credential = Credentials::new(credentials.issuer, credentials.public_key, credentials.alg);
    store.insert_one(credential).await?;
    Ok(())
}

fn validate_pubkey(pubkey: &str, alg: Algorithm) -> Result<(), AuthenticationError> {
    use jsonwebtoken::DecodingKey;

    match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => DecodingKey::from_rsa_pem(pubkey.as_bytes()),
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(pubkey.as_bytes()),
        Algorithm::EdDSA => DecodingKey::from_ed_pem(pubkey.as_bytes()),
        _ => return Err(AuthenticationError::UnsupportedAlgorithm),
    }?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pubkey_success() {
        let publick_key = "-----BEGIN PUBLIC KEY-----\n
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4R/68o1GpW2SvRroSJnCqWzcEX0J
            RnK3fQf9Rl4JqigPTBR5KEyGO1YgaKVucJ5uhX7CSIJSZg9dWN7MKaXVSQ==
            -----END PUBLIC KEY-----\n";
        let alg = Algorithm::ES256;
        assert!(validate_pubkey(publick_key, alg).is_ok());
    }

    #[test]
    fn test_validate_pubkey_invalid_algorithm() {
        let publick_key = "-----BEGIN PUBLIC KEY-----\n
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4R/68o1GpW2SvRroSJnCqWzcEX0J
            RnK3fQf9Rl4JqigPTBR5KEyGO1YgaKVucJ5uhX7CSIJSZg9dWN7MKaXVSQ==
            -----END PUBLIC KEY-----\n";
        let alg = Algorithm::RS256;

        assert!(validate_pubkey(publick_key, alg).is_err());
    }

    #[test]
    fn test_validate_pubkey_invalid_key() {
        let publick_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4R/68o1GpW2SvRroSJnCqWzcEX0J
            RnK3fQf9Rl4JqigPTBR5KEyGO1YgaKVucJ5uhX7CSIJSZg9dWN7MKaXVSQ==";
        let alg = Algorithm::ES256;

        let res = validate_pubkey(publick_key, alg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("InvalidKeyFormat"));
    }
}
