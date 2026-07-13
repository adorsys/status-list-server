mod pebble;
mod route53;

pub use pebble::PebbleDnsUpdater;
pub use route53::AwsRoute53DnsUpdater;

use std::sync::Arc;

use async_trait::async_trait;
use color_eyre::eyre::eyre;
use instant_acme::{AuthorizationHandle, ChallengeType};

use crate::cert_manager::challenge::{ChallengeError, ChallengeHandler, CleanupFuture};

/// Interface for managing the DNS TXT records used by DNS-01 challenges.
///
/// Implementations must wait internally until the created record is served
/// by the provider's authoritative name servers before returning.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create (or update) the TXT record for the given domain
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError>;
    /// Delete the TXT record for the given domain
    async fn delete_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError>;
}

/// Handler for DNS-01 challenges
pub struct Dns01Handler {
    dns_provider: Arc<dyn DnsProvider>,
}

impl Dns01Handler {
    pub fn new(dns_provider: impl DnsProvider + 'static) -> Self {
        Self {
            dns_provider: Arc::new(dns_provider),
        }
    }
}

#[async_trait]
impl ChallengeHandler for Dns01Handler {
    async fn handle_authorization<'a>(
        &'a self,
        authz: &'a mut AuthorizationHandle<'a>,
    ) -> Result<CleanupFuture, ChallengeError> {
        let mut challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| ChallengeError::Other(eyre!("No DNS-01 challenge found")))?;

        let digest = challenge.key_authorization().dns_value();
        let domain = challenge.identifier().to_string();

        // Create the DNS record
        self.dns_provider
            .create_txt_record(&domain, &digest)
            .await?;

        // Signal the server we are ready to respond to the challenge
        challenge.set_ready().await?;

        let cleanup = {
            let dns_provider = self.dns_provider.clone();
            async move { dns_provider.delete_txt_record(&domain, &digest).await }
        };
        Ok(CleanupFuture::new(cleanup))
    }
}

impl From<instant_acme::Error> for ChallengeError {
    fn from(err: instant_acme::Error) -> Self {
        ChallengeError::Other(err.into())
    }
}
