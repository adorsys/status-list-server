use thiserror::Error;

#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("could not store entity")]
    StoreError,
}
