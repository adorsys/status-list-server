#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("Insert error: {0}")]
    InsertError(String),
    #[error("Find error: {0}")]
    FindError(String),
    #[error("Update error: {0}")]
    UpdateError(String),
    #[error("Delete error: {0}")]
    DeleteError(String),
    #[error("Could not store entity")]
    CouldNotStoreEntity,
    #[error("Repository not set")]
    RepositoryNotSet,
    #[error("Duplicate entry")]
    DuplicateEntry,
    #[error("Generic error: {0}")]
    Generic(String),
}

impl From<sea_orm::DbErr> for RepositoryError {
    fn from(err: sea_orm::DbErr) -> Self {
        RepositoryError::Generic(err.to_string())
    }
}
