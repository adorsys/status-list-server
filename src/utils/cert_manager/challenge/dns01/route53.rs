use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_route53::{
    Client as Route53Client,
    types::{
        Change, ChangeAction, ChangeBatch, ChangeStatus, HostedZone, ResourceRecord,
        ResourceRecordSet, RrType,
    },
};
use color_eyre::eyre::eyre;
use tokio::sync::RwLock;
use tracing::info;

use super::DnsUpdater;
use crate::cert_manager::challenge::ChallengeError;

/// A DNS updater for AWS Route 53
pub struct AwsRoute53DnsUpdater {
    client: Route53Client,
    zones: Arc<RwLock<Option<Vec<ZoneInfo>>>>,
}

impl AwsRoute53DnsUpdater {
    const TXT_TTL: i64 = 60;
    const PROPAGATION_INITIAL_DELAY: Duration = Duration::from_secs(2);
    const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(60 * 5);

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

        if let Some((zone_id, zone_name)) = Self::find_best_match(domain, zones) {
            info!("Found best matching hosted zone: {zone_name}");
            Ok(zone_id.to_string())
        } else {
            Err(ChallengeError::ZoneNotFound(domain.to_string()))
        }
    }

    // Find the best matching hosted zone for the given domain
    fn find_best_match<'a>(lookup: &str, zones: &'a [ZoneInfo]) -> Option<(&'a str, &'a str)> {
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
        info!("Found hosted zones: {all_zones:?}");
        *self.zones.write().await = Some(all_zones);
        Ok(())
    }

    async fn change_records(
        &self,
        domain: &str,
        change_action: ChangeAction,
        value: &str,
    ) -> Result<(String, String), ChallengeError> {
        let record_name = format!("_acme-challenge.{domain}");
        let hosted_zone_id = self.find_hosted_zone(domain).await?;

        // Prepare the TXT record to change
        let change = Change::builder()
            .action(change_action)
            .resource_record_set(
                ResourceRecordSet::builder()
                    .name(&record_name)
                    .r#type(RrType::Txt)
                    .ttl(Self::TXT_TTL)
                    .resource_records(
                        ResourceRecord::builder()
                            .value(format!("\"{value}\""))
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
        let output = self
            .client
            .change_resource_record_sets()
            .hosted_zone_id(&hosted_zone_id)
            .change_batch(change_batch)
            .send()
            .await
            .map_err(|e| ChallengeError::AwsSdk(e.into()))?;

        let change_id = output.change_info.map(|info| info.id).ok_or_else(|| {
            ChallengeError::Other(eyre!(
                "Missing Change ID from AWS ChangeResourceRecordSets response"
            ))
        })?;

        Ok((record_name, change_id))
    }

    // wait for the change to propagate across all Route53 authoritative name servers
    async fn wait_for_propagation(&self, change_id: &str) -> Result<(), ChallengeError> {
        use tokio::time::{sleep, timeout};

        let initial_delay = Self::PROPAGATION_INITIAL_DELAY;
        let timeout_duration = Self::PROPAGATION_TIMEOUT;

        let mut retries = 0;

        let poll_future = async {
            loop {
                let output = self
                    .client
                    .get_change()
                    .id(change_id)
                    .send()
                    .await
                    .map_err(|e| ChallengeError::AwsSdk(e.into()))?;

                match output.change_info.map(|info| info.status) {
                    Some(ChangeStatus::Insync) => {
                        info!("DNS change {change_id} propagated successfully");
                        return Ok(());
                    }
                    Some(ChangeStatus::Pending) => {
                        info!("DNS change {change_id} still pending. Waiting for propagation...");
                    }
                    status => {
                        return Err(ChallengeError::Other(eyre!(
                            "Unexpected status for change {change_id}: {status:?}",
                        )));
                    }
                }

                // We double the delay after each attempt
                let delay = initial_delay
                    .checked_mul(2u32.pow(retries))
                    .unwrap_or(timeout_duration);
                retries += 1;
                sleep(delay).await;
            }
        };

        match timeout(timeout_duration, poll_future).await {
            Ok(result) => match result {
                Ok(()) => Ok(()),
                Err(e) => Err(e),
            },
            Err(_) => Err(ChallengeError::Other(eyre!(
                "DNS propagation timed out after {}s",
                timeout_duration.as_secs()
            ))),
        }
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
        let (record_name, change_id) = self
            .change_records(domain, ChangeAction::Upsert, value)
            .await?;

        info!("DNS record {record_name} created for {domain}");
        // Wait for the change to propagate before returning
        self.wait_for_propagation(&change_id).await?;
        Ok(())
    }

    async fn remove_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        // Try to delete the record in Route53
        let (record_name, _) = self
            .change_records(domain, ChangeAction::Delete, value)
            .await?;

        info!("DNS record {record_name} deleted for {domain}");
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

        let result = AwsRoute53DnsUpdater::find_best_match("sub.example.com", &zones);
        assert_eq!(result, Some(("Z2", "sub.example.com")));

        let result = AwsRoute53DnsUpdater::find_best_match("www.example.com", &zones);
        assert_eq!(result, Some(("Z1", "example.com")));

        let result = AwsRoute53DnsUpdater::find_best_match("acme.com", &zones);
        assert_eq!(result, None);

        let result = AwsRoute53DnsUpdater::find_best_match("wildcard.test.example.com", &zones);
        assert_eq!(result, Some(("Z4", "*.test.example.com")));
    }
}
