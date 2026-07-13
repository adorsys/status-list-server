mod pebble;
mod route53;

pub use pebble::PebbleDnsUpdater;
pub use route53::AwsRoute53DnsUpdater;

use std::sync::Arc;

use async_trait::async_trait;
use color_eyre::eyre::eyre;
use instant_acme::{AuthorizationHandle, ChallengeType};

use crate::cert_manager::challenge::{ChallengeError, ChallengeHandler, CleanupFuture};

/// Interface for updating DNS records
#[async_trait]
pub trait DnsUpdater: Send + Sync {
    /// Upsert a DNS record for the given domain
    async fn upsert_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError>;
    /// Remove a DNS record for the given domain
    async fn remove_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError>;
}

/// Handler for DNS-01 challenges
pub struct Dns01Handler {
    dns_updater: Arc<dyn DnsUpdater>,
}

impl Dns01Handler {
    pub fn new(dns_updater: impl DnsUpdater + 'static) -> Self {
        Self {
            dns_updater: Arc::new(dns_updater),
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

        // Upsert the DNS record
        self.dns_updater.upsert_record(&domain, &digest).await?;

        // Signal the server we are ready to respond to the challenge
        challenge.set_ready().await?;

        let cleanup = {
            let dns_updater = self.dns_updater.clone();
            async move { dns_updater.remove_record(&domain, &digest).await }
        };
        Ok(CleanupFuture::new(cleanup))
    }
}

impl From<instant_acme::Error> for ChallengeError {
    fn from(err: instant_acme::Error) -> Self {
        ChallengeError::Other(err.into())
    }
}
