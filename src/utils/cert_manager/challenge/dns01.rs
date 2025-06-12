use std::sync::Arc;

use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_route53::{
    types::{
        Change, ChangeAction, ChangeBatch, HostedZone, ResourceRecord, ResourceRecordSet, RrType,
    },
    Client as Route53Client,
};
use color_eyre::eyre::eyre;
use instant_acme::{Authorization, ChallengeType, Identifier, Order};
use reqwest::Client;
use serde_json::json;
use tokio::sync::RwLock;
use tracing::info;

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
    async fn handle_authorization(
        &self,
        authz: &Authorization,
        order: &mut Order,
    ) -> Result<(String, CleanupFuture), ChallengeError> {
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| ChallengeError::Other(eyre!("No DNS-01 challenge found")))?;

        let digest = order.key_authorization(challenge).dns_value();
        let domain = match &authz.identifier {
            Identifier::Dns(domain) => domain.clone(),
        };
        // Upsert the DNS record
        self.dns_updater.upsert_record(&domain, &digest).await?;

        let cleanup = {
            let dns_updater = self.dns_updater.clone();
            let domain = domain.clone();
            async move { dns_updater.remove_record(&domain, &digest).await }
        };
        let cleanup_fut = CleanupFuture::new(cleanup);

        Ok((challenge.url.clone(), cleanup_fut))
    }
}

/// A DNS updater for AWS Route 53
pub struct AwsRoute53DnsUpdater {
    client: Route53Client,
    zones: Arc<RwLock<Option<Vec<ZoneInfo>>>>,
}

impl AwsRoute53DnsUpdater {
    pub fn new(config: &SdkConfig) -> Self {
        Self {
            client: Route53Client::new(config),
            zones: Arc::new(RwLock::new(None)),
        }
    }

    // Find the hosted zone for the given domain and return its ID
    async fn find_hosted_zone(&self, domain: &str) -> Result<String, ChallengeError> {
        self.try_cache_zones().await?;

        let read_guard = self.zones.read().await;
        let zones = read_guard.as_ref().unwrap();
        // remove the trailing dot from the domain if any
        let domain = domain.trim_end_matches('.');

        if let Some(zone_id) = Self::find_best_match(domain, zones) {
            Ok(zone_id.to_string())
        } else {
            Err(ChallengeError::ZoneNotFound(domain.to_string()))
        }
    }

    // Find the best matching hosted zone for the given domain
    fn find_best_match<'a>(lookup: &str, zones: &'a [ZoneInfo]) -> Option<&'a str> {
        let mut best_match = None;

        for zone in zones.iter() {
            let zone_name = &zone.name;
            let is_match = if let Some(stripped) = zone_name.strip_prefix("*.") {
                // Try to match wilcard domains
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
                lookup.as_bytes().get(idx) == Some(&b'.')
                    && &lookup[idx + 1..] == zone_name.as_str()
            } else {
                false
            };

            if is_match {
                let len = zone_name.len();
                match best_match {
                    None => best_match = Some((zone.id.as_str(), len)),
                    Some((_, curr_len)) if len > curr_len => {
                        best_match = Some((zone.id.as_str(), len));
                    }
                    _ => {}
                }
            }
        }
        best_match.map(|(zone_id, _)| zone_id)
    }

    async fn try_cache_zones(&self) -> Result<(), ChallengeError> {
        // Check if zones are already cached
        let read_guard = self.zones.read().await;
        if read_guard.is_some() {
            return Ok(());
        }
        drop(read_guard);

        let mut all_zones = Vec::new();
        let mut next_marker = None;

        // try to get all hosted zones
        loop {
            let mut req = self.client.list_hosted_zones();
            if let Some(marker) = &next_marker {
                req = req.marker(marker);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| ChallengeError::AwsSdk(e.into()))?;
            let hosted_zones = resp.hosted_zones();
            for zone in hosted_zones {
                all_zones.push(ZoneInfo::new(zone));
            }
            // Check if there are more hosted zones
            if resp.is_truncated() {
                next_marker = resp.next_marker().map(|s| s.to_string());
            } else {
                break;
            }
        }
        *self.zones.write().await = Some(all_zones);
        Ok(())
    }

    async fn change_records(
        &self,
        domain: &str,
        change_action: ChangeAction,
        value: &str,
    ) -> Result<String, ChallengeError> {
        let record_name = format!("_acme-challenge.{}", domain);
        let hosted_zone_id = self.find_hosted_zone(domain).await?;

        // Prepare the TXT record to change
        let change = Change::builder()
            .action(change_action)
            .resource_record_set(
                ResourceRecordSet::builder()
                    .name(&record_name)
                    .r#type(RrType::Txt)
                    .ttl(60)
                    .resource_records(
                        ResourceRecord::builder()
                            .value(format!("\"{}\"", value))
                            .build()
                            .map_err(|e| ChallengeError::AwsSdk(e.into()))?,
                    )
                    .build()
                    .map_err(|e| ChallengeError::AwsSdk(e.into()))?,
            )
            .build()
            .map_err(|e| ChallengeError::AwsSdk(e.into()))?;
        let change_batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|e| ChallengeError::AwsSdk(e.into()))?;

        // Try to change the record in Route53
        self.client
            .change_resource_record_sets()
            .hosted_zone_id(&hosted_zone_id)
            .change_batch(change_batch)
            .send()
            .await
            .map_err(|e| ChallengeError::AwsSdk(e.into()))?;

        Ok(record_name)
    }
}

#[derive(Debug, Clone)]
struct ZoneInfo {
    name: String,
    id: String,
}

impl ZoneInfo {
    fn new(z: &HostedZone) -> Self {
        let trimmed = z.name().trim_end_matches('.').to_string();
        ZoneInfo {
            name: trimmed,
            id: z.id().to_string(),
        }
    }
}

#[async_trait]
impl DnsUpdater for AwsRoute53DnsUpdater {
    async fn upsert_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        // Try to upsert the record in Route53
        let record_name = self
            .change_records(domain, ChangeAction::Upsert, value)
            .await?;

        info!("DNS record {record_name} created for {domain}");
        Ok(())
    }

    async fn remove_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        // Try to delete the record in Route53
        let record_name = self
            .change_records(domain, ChangeAction::Delete, value)
            .await?;

        info!("DNS record {record_name} deleted for {domain}");
        Ok(())
    }
}

// Handler for Pebble DNS (mainly for generating test certificates)
pub struct PebbleDnsUpdater {
    client: Client,
    addr: String,
}

impl PebbleDnsUpdater {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            addr: addr.into(),
        }
    }
}

#[async_trait]
impl DnsUpdater for PebbleDnsUpdater {
    async fn upsert_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{}.", domain);
        let url = format!("{}/set-txt", self.addr);
        let body = json!({"host": record_name, "value": value});

        self.client
            .post(&url)
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| ChallengeError::Other(eyre!("Failed to send request: {e}")))?
            .error_for_status()
            .map_err(|e| ChallengeError::Other(eyre!("Failed to set TXT record: {e}")))?;

        Ok(())
    }

    async fn remove_record(&self, domain: &str, _value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{}.", domain);
        let url = format!("{}/clear-txt", self.addr);
        let body = json!({"host": record_name});

        self.client
            .post(&url)
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| ChallengeError::Other(eyre!("Failed to send request: {e}")))?
            .error_for_status()
            .map_err(|e| ChallengeError::Other(eyre!("Failed to clear TXT record: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_best_match_exact_and_suffix() {
        let zones = vec![
            ZoneInfo {
                name: "example.com".into(),
                id: "Z1".into(),
            },
            ZoneInfo {
                name: "sub.example.com".into(),
                id: "Z2".into(),
            },
            ZoneInfo {
                name: "test.acme.com".into(),
                id: "Z3".into(),
            },
            ZoneInfo {
                name: "*.test.example.com".into(),
                id: "Z4".into(),
            },
        ];

        let id = AwsRoute53DnsUpdater::find_best_match("sub.example.com", &zones);
        assert_eq!(id, Some("Z2"));

        let id = AwsRoute53DnsUpdater::find_best_match("www.example.com", &zones);
        assert_eq!(id, Some("Z1"));

        let id = AwsRoute53DnsUpdater::find_best_match("acme.com", &zones);
        assert_eq!(id, None);

        let id = AwsRoute53DnsUpdater::find_best_match("wildcard.test.example.com", &zones);
        assert_eq!(id, Some("Z4"));
    }
}
