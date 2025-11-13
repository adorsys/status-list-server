mod dns01;
mod http01;

pub use dns01::{AwsRoute53DnsUpdater, Dns01Handler, PebbleDnsUpdater};
pub use http01::Http01Handler;

use std::{future::Future, pin::Pin};

use color_eyre::eyre::Error as Report;
use instant_acme::AuthorizationHandle;

use crate::cert_manager::storage::StorageError;

use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChallengeError {
    #[error("AWS SDK error: {0}")]
    AwsSdk(#[source] Report),

    #[error("No hosted zone found for domain {0}")]
    ZoneNotFound(String),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Another error occurred: {0}")]
    Other(#[source] Report),
}

/// Abstract interface for handling ACME challenges
#[async_trait::async_trait]
pub trait ChallengeHandler: Send + Sync {
    /// Handle the ACME challenge for the given authorization and order
    ///
    /// Returns a tuple containing the challenge url and a cleanup future
    async fn handle_authorization<'a>(
        &'a self,
        authz: &'a mut AuthorizationHandle<'a>,
    ) -> Result<CleanupFuture, ChallengeError>;
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A future that performs cleanup of resources allocated during ACME challenge validation
pub struct CleanupFuture {
    inner: BoxFuture<'static, Result<(), ChallengeError>>,
}

impl CleanupFuture {
    /// Create a cleanup future with the given future
    pub fn new<F>(fut: F) -> Self
    where
        F: Future<Output = Result<(), ChallengeError>> + Send + 'static,
    {
        Self {
            inner: Box::pin(fut) as BoxFuture<'static, Result<(), ChallengeError>>,
        }
    }

    /// Run the cleanup process
    pub async fn run(self) -> Result<(), ChallengeError> {
        self.inner.await
    }
}
