mod acme_dns;
mod azure;
mod cloudflare;
mod gcloud;
mod pebble;
mod route53;
mod token;

pub use acme_dns::AcmeDnsProvider;
pub use azure::{AzureDnsProvider, ServicePrincipal};
pub use cloudflare::CloudflareDnsProvider;
pub use gcloud::GoogleCloudDnsProvider;
pub use pebble::PebbleDnsProvider;
pub use route53::AwsRoute53DnsProvider;

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use color_eyre::eyre::eyre;
use instant_acme::{AuthorizationHandle, ChallengeType};

use crate::cert_manager::challenge::{ChallengeError, ChallengeHandler, CleanupFuture};

/// Timeout applied to every DNS provider HTTP request so a hung API or token
/// endpoint cannot stall certificate renewal indefinitely.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Build the HTTP client shared by the DNS provider implementations
pub(crate) fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .expect("failed to build DNS provider HTTP client")
}

/// Interface for managing the DNS TXT records used by DNS-01 challenges.
///
/// The ACME server queries the zone's authoritative name servers directly and
/// validates only once, so implementations must wait internally until the
/// created record is served, to the degree their provider's API allows
/// confirming it (change-status polling where available, a bounded settle
/// delay otherwise).
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

/// A DNS zone known to a provider
#[derive(Debug, Clone)]
pub(crate) struct ZoneInfo {
    pub(crate) name: String,
    pub(crate) id: String,
}

impl ZoneInfo {
    pub(crate) fn new(name: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            // remove the trailing dot from the zone name if any
            name: name.into().trim_end_matches('.').to_string(),
            id: id.into(),
        }
    }
}

// Find the best matching (longest suffix) zone for the given domain
pub(crate) fn find_best_match<'a>(
    lookup: &str,
    zones: &'a [ZoneInfo],
) -> Option<(&'a str, &'a str)> {
    let mut best_match = None;

    for zone in zones.iter() {
        let zone_name = &zone.name;
        let is_match = if let Some(stripped) = zone_name.strip_prefix("*.") {
            // Try to match wildcard domains
            if lookup.ends_with(stripped) {
                // We ensure there's at least one identifier before the wildcard
                let diff = lookup.len() - stripped.len();
                lookup[..diff].contains('.')
            } else {
                false
            }
        } else if lookup == zone_name {
            true
        } else if lookup.len() > zone_name.len() {
            // Check if lookup ends with .zone_name
            let idx = lookup.len() - zone_name.len() - 1;
            lookup.as_bytes().get(idx) == Some(&b'.') && &lookup[idx + 1..] == zone_name
        } else {
            false
        };

        if is_match {
            let len = zone_name.len();
            match best_match {
                None => best_match = Some((zone.id.as_str(), zone_name, len)),
                Some((_, _, curr_len)) if len > curr_len => {
                    best_match = Some((zone.id.as_str(), zone_name, len));
                }
                _ => {}
            }
        }
    }
    best_match.map(|(zone_id, zone_name, _)| (zone_id, zone_name.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_best_match_exact_and_suffix() {
        let zones = vec![
            ZoneInfo::new("example.com", "Z1"),
            ZoneInfo::new("sub.example.com", "Z2"),
            ZoneInfo::new("test.acme.com", "Z3"),
            ZoneInfo::new("*.test.example.com", "Z4"),
        ];

        let result = find_best_match("sub.example.com", &zones);
        assert_eq!(result, Some(("Z2", "sub.example.com")));

        let result = find_best_match("www.example.com", &zones);
        assert_eq!(result, Some(("Z1", "example.com")));

        let result = find_best_match("acme.com", &zones);
        assert_eq!(result, None);

        let result = find_best_match("wildcard.test.example.com", &zones);
        assert_eq!(result, Some(("Z4", "*.test.example.com")));
    }
}
