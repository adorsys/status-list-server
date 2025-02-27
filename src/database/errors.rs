use thiserror::Error;

#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("could not get connection from pool")]
    PoolError,
    #[error("could not get data")]
    FetchError,
    #[error("could not store data")]
    InsertError,
}