use crate::{
    database::{error::RepositoryError, repository::Repository},
    model::Credentials,
    utils::state::AppState,
};

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
