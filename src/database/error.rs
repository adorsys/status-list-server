use thiserror::Error;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum RepositoryError {
    #[error("could not store entity")]
    StoreError,
    #[error("could not fetch entity")]
    FetchError,
    #[error("could not update entity")]
    UpdateError,
    #[error("could not delete entity")]
    DeleteError,
}
