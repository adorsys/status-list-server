mod acme_dns;
#[cfg(feature = "azure")]
mod azure;
mod cloudflare;
#[cfg(feature = "gcp")]
mod gcloud;
mod pebble;
#[cfg(feature = "aws")]
mod route53;
#[cfg(feature = "azure")]
mod token;

pub use acme_dns::{AcmeDnsCredentials, AcmeDnsProvider};
#[cfg(feature = "azure")]
pub use azure::AzureDnsProvider;
pub use cloudflare::CloudflareDnsProvider;
#[cfg(feature = "gcp")]
pub use gcloud::GoogleCloudDnsProvider;
pub use pebble::PebbleDnsProvider;
#[cfg(feature = "aws")]
pub use route53::AwsRoute53DnsProvider;

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use color_eyre::eyre::eyre;
use instant_acme::{AuthorizationHandle, ChallengeType};

use crate::cert_manager::challenge::{ChallengeError, ChallengeHandler, CleanupFuture};

/// So a hung provider API can't stall renewal.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .expect("failed to build DNS provider HTTP client")
}

/// create_txt_record must not return until the record is served: the CA checks only once.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError>;
    async fn delete_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError>;
}

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

        self.dns_provider
            .create_txt_record(&domain, &digest)
            .await?;

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

#[derive(Debug, Clone)]
pub(crate) struct ZoneInfo {
    pub(crate) name: String,
    pub(crate) id: String,
}

impl ZoneInfo {
    pub(crate) fn new(name: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            name: name.into().trim_end_matches('.').to_string(),
            id: id.into(),
        }
    }
}

// Longest matching suffix wins.
pub(crate) fn find_best_match<'a>(
    lookup: &str,
    zones: &'a [ZoneInfo],
) -> Option<(&'a str, &'a str)> {
    let mut best_match = None;

    for zone in zones.iter() {
        let zone_name = &zone.name;
        let is_match = if let Some(stripped) = zone_name.strip_prefix("*.") {
            if lookup.ends_with(stripped) {
                // The wildcard must cover at least one label.
                let diff = lookup.len() - stripped.len();
                lookup[..diff].contains('.')
            } else {
                false
            }
        } else if lookup == zone_name {
            true
        } else if lookup.len() > zone_name.len() {
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
