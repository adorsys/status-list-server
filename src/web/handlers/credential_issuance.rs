use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::{
    auth::{authentication::publish_credentials, middleware::AuthenticatedIssuer},
    database::error::RepositoryError,
    model::Credentials,
    utils::state::AppState,
};

pub async fn credential_handler(
    State(appstate): State<AppState>,
    AuthenticatedIssuer(issuer): AuthenticatedIssuer,
    credential: Json<Credentials>,
) -> impl IntoResponse {
    // Verify that the issuer in the credential matches the authenticated issuer
    if credential.0.issuer != issuer {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Issuer mismatch: credential issuer does not match authenticated issuer".to_string(),
        ));
    }

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
