use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("error: {0}")]
    Generic(String),
    #[error("invalid index")]
    InvalidIndex,
    #[error("Failed to decode lst")]
    DecodeFailed,
    #[error("status index {0} exceeds the configured maximum")]
    IndexTooLarge(i32),
    #[error("serialized status list size {actual} bytes exceeds maximum {max} bytes")]
    SerializedListTooLarge { actual: usize, max: usize },
}
