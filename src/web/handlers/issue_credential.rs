use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::{database::error::RepositoryError, models::Credentials, utils::state::AppState};

pub async fn credential_handler(
    State(appstate): State<AppState>,
    Json(credential): Json<Credentials>,
) -> impl IntoResponse {
    match publish_credentials(credential.to_owned(), appstate).await {
        Ok(_) => (StatusCode::ACCEPTED, "Credentials stored successfully").into_response(),
        Err(RepositoryError::DuplicateEntry) => {
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
) -> Result<(), RepositoryError> {
    let store = &state.credential_repo;

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
