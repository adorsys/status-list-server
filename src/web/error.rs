use core::error;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StatusError {
    #[error("invalid index, status not found")]
    InvalidIndex,
    #[error("Unknown status")]
    UnknownStatus,
    #[error("error: {0}")]
    Generic(String),
}
