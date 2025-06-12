use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("error: {0}")]
    Generic(String),
    #[error("invalid index")]
    InvalidIndex,
    #[error("Failed to decode lst")]
    DecodeFailed,
}
