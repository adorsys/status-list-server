use crate::{
    database::{error::RepositoryError, repository::Repository},
    model::Credentials,
    utils::state::AppState,
};

use super::errors::AuthErrors;

/// Handle JWT registration
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
    let algorithm = credentials.alg.clone();
    match algorithm.as_str() {
        "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" => (),
        _ => return Err(RepositoryError::from(AuthErrors::UnknownAlgorithm))?,
    }

    // ensure consistent order in credentials
    let credential = Credentials::new(credentials.issuer, credentials.public_key, credentials.alg);

    // Insert the credentials into the repository
    store.credential_repository.insert_one(credential).await?;

    Ok(())
}
