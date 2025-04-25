use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    auth::authentication::{publish_credentials, verify_signature},
    database::error::RepositoryError,
    model::Credentials,
    utils::state::AppState,
};

#[derive(Serialize)]
struct NonceResponse {
    nonce: String,
}

pub async fn generate_nonce() -> impl IntoResponse {
    let nonce: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    Json(NonceResponse { nonce })
}

#[derive(Deserialize)]
pub struct CredentialRequest {
    credentials: Credentials,
    signed_nonce: String,
}

pub async fn credential_handler(
    State(appstate): State<AppState>,
    Json(request): Json<CredentialRequest>,
) -> impl IntoResponse {
    let credential = request.credentials;

    // Verify the signature before storing credentials
    if !verify_signature(&credential.public_key, &request.signed_nonce).await {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid signature. Please provide a valid signature of the nonce using your private key.".to_string(),
        ));
    }

    match publish_credentials(credential, appstate).await {
        Ok(_) => {
            tracing::info!("successfully stored credentials");
            Ok(StatusCode::ACCEPTED)
        }
        Err(err) => {
            tracing::error!("Failed to store credentials: {err:?}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                RepositoryError::CouldNotStoreEntity.to_string(),
            ))
        }
    }
}
