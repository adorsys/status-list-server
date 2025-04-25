use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::{
    auth::authentication::publish_credentials, database::error::RepositoryError,
    model::Credentials, utils::state::AppState,
};

pub async fn credential_handler(
    State(appstate): State<AppState>,
    credential: Json<Credentials>,
) -> impl IntoResponse {
    match publish_credentials(credential.0, appstate).await {
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
