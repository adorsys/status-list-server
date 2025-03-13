use thiserror::Error;

#[derive(Error, Debug)]
pub enum StatusError {
    #[error("invalid index, status not found")]
    InvalidIndex,
    #[error("Unknown status")]
    UnknownStatus,
    #[error("error: {0}")]
    Generic(String),
    #[error("failed to update status")]
    UpdateFailed,
    #[error("Request body must contain a valid 'updates' array")]
    MalformedBody,
    #[error("Status list not found")]
    StatusListNotFound
}
