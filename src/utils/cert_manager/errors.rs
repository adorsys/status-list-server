use crate::{
    cert_manager::{challenge::ChallengeError, storage::StorageError},
    utils::keygen::Error as KeyOpError,
};
use color_eyre::eyre::Error as EyreError;
use instant_acme::Error as AcmeError;
use serde_json::Error as SerdeError;
use thiserror::Error;
use tokio_cron_scheduler::JobSchedulerError;

/// List of errors that can occur during certificate management
#[derive(Error, Debug)]
pub enum CertError {
    #[error("ACME error: {0}")]
    Acme(#[from] AcmeError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Challenge error: {0}")]
    Challenge(#[from] ChallengeError),

    #[error("Certificate parsing error: {0}")]
    Parsing(String),

    #[error("Cron error: {0}")]
    Cron(#[from] JobSchedulerError),

    #[error("Serialization error: {0}")]
    Serde(#[from] SerdeError),

    #[error("Key operation error: {0}")]
    KeyOp(#[from] KeyOpError),

    #[error("Uncategorized error: {0}")]
    Other(#[source] EyreError),
}
