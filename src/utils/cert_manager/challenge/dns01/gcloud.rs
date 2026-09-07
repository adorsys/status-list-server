use std::time::Duration;

use async_trait::async_trait;
use color_eyre::eyre::{Report, eyre};
#[cfg(not(test))]
use google_cloud_auth::credentials::{AccessTokenCredentials, Builder as AdcBuilder};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;
use tracing::info;

use super::{DnsProvider, ZoneInfo, find_best_match, http_client};
use crate::cert_manager::challenge::ChallengeError;

const PROVIDER: &str = "gcloud";
const DEFAULT_API_BASE: &str = "https://dns.googleapis.com/dns/v1";
#[cfg(not(test))]
const OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";

/// A DNS provider for Google Cloud DNS, authenticated with Application Default Credentials.
///
/// Waits for each change to reach the `done` status, which means the record
/// is served by all of the zone's authoritative name servers.
pub struct GoogleCloudDnsProvider {
    client: Client,
    #[cfg(not(test))]
    credentials: AccessTokenCredentials,
    #[cfg(test)]
    test_access_token: Option<SecretString>,
    project_id: String,
    api_base: String,
    zones: RwLock<Option<Vec<ZoneInfo>>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RrSet {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    ttl: u32,
    rrdatas: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RrSetList {
    #[serde(default)]
    rrsets: Vec<RrSet>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedZoneList {
    #[serde(default)]
    managed_zones: Vec<ManagedZone>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedZone {
    name: String,
    dns_name: String,
}

#[derive(Deserialize)]
struct Change {
    id: String,
    status: String,
}

fn dns_err(source: impl Into<Report>) -> ChallengeError {
    ChallengeError::Dns {
        provider: PROVIDER,
        source: source.into(),
    }
}

impl GoogleCloudDnsProvider {
    const TXT_TTL: u32 = 60;
    const CONFLICT_RETRIES: u32 = 3;
    const PROPAGATION_INITIAL_DELAY: Duration = Duration::from_secs(2);
    const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(60 * 5);

    /// Create a provider from Application Default Credentials.
    pub fn new(project_id: impl Into<String>) -> Result<Self, ChallengeError> {
        let project_id = project_id.into();
        if project_id.trim().is_empty() {
            return Err(dns_err(eyre!(
                "Google Cloud DNS requires a non-empty project_id"
            )));
        }
        #[cfg(not(test))]
        let credentials = AdcBuilder::default()
            .with_scopes([OAUTH_SCOPE])
            .build_access_token_credentials()
            .map_err(|e| {
                dns_err(eyre!(
                    "Failed to initialize Google Cloud Application Default Credentials \
                         for DNS provider. Configure GKE Workload Identity or set \
                         GOOGLE_APPLICATION_CREDENTIALS to a valid ADC file. Details: {e}"
                ))
            })?;
        Ok(Self {
            client: http_client(),
            project_id,
            #[cfg(not(test))]
            credentials,
            #[cfg(test)]
            test_access_token: None,
            api_base: DEFAULT_API_BASE.to_string(),
            zones: RwLock::new(None),
        })
    }

    /// Override the API base URL (used in tests)
    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.api_base = api_base.into().trim_end_matches('/').to_string();
        self
    }

    #[cfg(test)]
    fn with_test_access_token(mut self, token: SecretString) -> Self {
        self.test_access_token = Some(token);
        self
    }

    async fn access_token(&self) -> Result<SecretString, ChallengeError> {
        #[cfg(test)]
        {
            if let Some(token) = &self.test_access_token {
                return Ok(token.clone());
            }
            panic!("Google Cloud DNS tests must provide a test access token")
        }
        #[cfg(not(test))]
        {
            self.credentials
                .access_token()
                .await
                .map(|t| t.token.into())
                .map_err(|e| {
                    dns_err(eyre!(
                        "Failed to acquire Google Cloud DNS ambient access token via \
                     Application Default Credentials. Verify GKE Workload Identity, \
                     metadata server access, or GOOGLE_APPLICATION_CREDENTIALS. Details: {e}"
                    ))
                })
        }
    }

    fn project_url(&self) -> String {
        format!("{}/projects/{}", self.api_base, self.project_id)
    }
}

impl GoogleCloudDnsProvider {
    // Find the managed zone for the given domain and return its name
    async fn find_zone(&self, domain: &str) -> Result<String, ChallengeError> {
        self.try_cache_zones().await?;

        let read_guard = self.zones.read().await;
        let zones = read_guard.as_ref().unwrap();
        let domain = domain.trim_end_matches('.');

        if let Some((zone_id, zone_name)) = find_best_match(domain, zones) {
            info!("Found best matching Cloud DNS zone: {zone_name}");
            Ok(zone_id.to_string())
        } else {
            Err(ChallengeError::ZoneNotFound(domain.to_string()))
        }
    }

    async fn try_cache_zones(&self) -> Result<(), ChallengeError> {
        // Check if zones are already cached
        let read_guard = self.zones.read().await;
        if read_guard.is_some() {
            return Ok(());
        }
        drop(read_guard);

        let token = self.access_token().await?;
        let mut all_zones = Vec::new();
        let mut page_token: Option<String> = None;

        // try to get all managed zones
        loop {
            let url = format!("{}/managedZones", self.project_url());
            let mut request = self.client.get(&url).bearer_auth(token.expose_secret());
            if let Some(token) = &page_token {
                request = request.query(&[("pageToken", token)]);
            }
            let response = request.send().await.map_err(dns_err)?;
            let body: ManagedZoneList = Self::parse_response(response).await?;

            for zone in body.managed_zones {
                all_zones.push(ZoneInfo::new(zone.dns_name, zone.name));
            }
            match body.next_page_token {
                Some(token) => page_token = Some(token),
                None => break,
            }
        }
        info!("Found Cloud DNS zones: {all_zones:?}");
        *self.zones.write().await = Some(all_zones);
        Ok(())
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, ChallengeError> {
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(dns_err(eyre!(
                "API request failed (status {status}): {body}"
            )));
        }
        response
            .json()
            .await
            .map_err(|e| dns_err(eyre!("Invalid API response (status {status}): {e}")))
    }

    // Fetch the existing TXT rrset for the record, if any
    async fn get_rrset(
        &self,
        zone: &str,
        record_name: &str,
        token: &SecretString,
    ) -> Result<Option<RrSet>, ChallengeError> {
        let url = format!("{}/managedZones/{zone}/rrsets", self.project_url());
        let response = self
            .client
            .get(&url)
            .query(&[("name", record_name), ("type", "TXT")])
            .bearer_auth(token.expose_secret())
            .send()
            .await
            .map_err(dns_err)?;
        let body: RrSetList = Self::parse_response(response).await?;
        Ok(body.rrsets.into_iter().next())
    }

    // Apply a change replacing the existing rrset (if any) with the new one (if any).
    // Cloud DNS changes replace whole rrsets, so callers pass merged rrdatas.
    // Retries on conflict since another change may have touched the rrset in between.
    async fn change_rrset(
        &self,
        zone: &str,
        record_name: &str,
        merge: impl Fn(Vec<String>) -> Vec<String>,
    ) -> Result<(), ChallengeError> {
        let token = self.access_token().await?;
        let mut attempts = 0;

        loop {
            let existing = self.get_rrset(zone, record_name, &token).await?;
            let old_rrdatas = existing
                .as_ref()
                .map(|r| r.rrdatas.clone())
                .unwrap_or_default();
            let new_rrdatas = merge(old_rrdatas);

            // Nothing to change: the record is already absent or already holds
            // the merged values. Cloud DNS rejects an empty or identity change.
            if existing.as_ref().map(|r| &r.rrdatas) == Some(&new_rrdatas)
                || (existing.is_none() && new_rrdatas.is_empty())
            {
                return Ok(());
            }

            let mut change = json!({});
            if let Some(existing) = &existing {
                change["deletions"] = json!([existing]);
            }
            if !new_rrdatas.is_empty() {
                change["additions"] = json!([RrSet {
                    name: record_name.to_string(),
                    kind: "TXT".to_string(),
                    ttl: Self::TXT_TTL,
                    rrdatas: new_rrdatas,
                }]);
            }

            let url = format!("{}/managedZones/{zone}/changes", self.project_url());
            let response = self
                .client
                .post(&url)
                .bearer_auth(token.expose_secret())
                .json(&change)
                .send()
                .await
                .map_err(dns_err)?;

            if response.status() == StatusCode::CONFLICT && attempts < Self::CONFLICT_RETRIES {
                attempts += 1;
                info!("Cloud DNS change conflict for {record_name}, retrying...");
                continue;
            }

            let change: Change = Self::parse_response(response).await?;
            return self.wait_for_change(zone, &change, &token).await;
        }
    }

    // Wait until the change is served by all authoritative name servers
    async fn wait_for_change(
        &self,
        zone: &str,
        change: &Change,
        token: &SecretString,
    ) -> Result<(), ChallengeError> {
        use tokio::time::{sleep, timeout};

        if change.status == "done" {
            return Ok(());
        }

        let change_id = &change.id;
        let mut retries = 0;

        let poll_future = async {
            loop {
                // We double the delay after each attempt
                let delay = 2u32
                    .checked_pow(retries)
                    .and_then(|factor| Self::PROPAGATION_INITIAL_DELAY.checked_mul(factor))
                    .unwrap_or(Self::PROPAGATION_TIMEOUT);
                retries += 1;
                sleep(delay).await;

                let url = format!(
                    "{}/managedZones/{zone}/changes/{change_id}",
                    self.project_url()
                );
                let response = self
                    .client
                    .get(&url)
                    .bearer_auth(token.expose_secret())
                    .send()
                    .await
                    .map_err(dns_err)?;
                let change: Change = Self::parse_response(response).await?;

                if change.status == "done" {
                    info!("Cloud DNS change {change_id} propagated successfully");
                    return Ok(());
                }
                info!("Cloud DNS change {change_id} still pending. Waiting for propagation...");
            }
        };

        match timeout(Self::PROPAGATION_TIMEOUT, poll_future).await {
            Ok(result) => result,
            Err(_) => Err(dns_err(eyre!(
                "DNS propagation timed out after {}s",
                Self::PROPAGATION_TIMEOUT.as_secs()
            ))),
        }
    }
}

#[async_trait]
impl DnsProvider for GoogleCloudDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{}.", domain.trim_end_matches('.'));
        let zone = self.find_zone(domain).await?;

        let quoted = format!("\"{value}\"");
        self.change_rrset(&zone, &record_name, move |mut rrdatas| {
            if !rrdatas.contains(&quoted) {
                rrdatas.push(quoted.clone());
            }
            rrdatas
        })
        .await?;

        info!("DNS record {record_name} created for {domain}");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{}.", domain.trim_end_matches('.'));
        let zone = self.find_zone(domain).await?;

        let quoted = format!("\"{value}\"");
        self.change_rrset(&zone, &record_name, move |rrdatas| {
            rrdatas.into_iter().filter(|v| *v != quoted).collect()
        })
        .await?;

        info!("DNS record {record_name} deleted for {domain}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{
        body_partial_json, method, path, query_param, query_param_is_missing,
    };
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn provider(server: &MockServer) -> GoogleCloudDnsProvider {
        test_provider(server, "gcp-token")
    }

    fn test_provider(server: &MockServer, token: &str) -> GoogleCloudDnsProvider {
        GoogleCloudDnsProvider {
            client: http_client(),
            test_access_token: None,
            project_id: "test-project".into(),
            api_base: DEFAULT_API_BASE.to_string(),
            zones: RwLock::new(None),
        }
        .with_test_access_token(token.to_string().into())
        .with_api_base(server.uri())
    }

    async fn mount_zone_mock(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/projects/test-project/managedZones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "managedZones": [{"name": "example-zone", "dnsName": "example.com."}],
            })))
            .mount(server)
            .await;
    }

    fn rrsets_response(rrdatas: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "rrsets": [{
                "name": "_acme-challenge.status.example.com.",
                "type": "TXT",
                "ttl": 60,
                "rrdatas": rrdatas,
            }],
        }))
    }

    #[tokio::test]
    async fn creates_record_merging_existing_values() {
        let server = MockServer::start().await;
        mount_zone_mock(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/rrsets",
            ))
            .and(query_param("type", "TXT"))
            .respond_with(rrsets_response(json!(["\"other-value\""])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/changes",
            ))
            .and(body_partial_json(json!({
                "deletions": [{"rrdatas": ["\"other-value\""]}],
                "additions": [{"rrdatas": ["\"other-value\"", "\"digest-value\""]}],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "c1",
                "status": "done",
            })))
            .expect(1)
            .mount(&server)
            .await;

        provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn adc_token_drives_dns_requests() {
        let server = MockServer::start().await;
        mount_zone_mock(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/rrsets",
            ))
            .and(query_param("type", "TXT"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rrsets": []})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/changes",
            ))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer ambient-gcp-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "c1",
                "status": "done",
            })))
            .expect(1)
            .mount(&server)
            .await;

        test_provider(&server, "ambient-gcp-token")
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn retries_on_change_conflict() {
        let server = MockServer::start().await;
        mount_zone_mock(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/rrsets",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rrsets": []})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/changes",
            ))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": {"code": 409, "message": "conflict"},
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/changes",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "c1",
                "status": "done",
            })))
            .expect(1)
            .mount(&server)
            .await;

        provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn waits_until_change_is_done() {
        let server = MockServer::start().await;
        mount_zone_mock(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/rrsets",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rrsets": []})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/changes",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "c1",
                "status": "pending",
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/changes/c1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "c1",
                "status": "done",
            })))
            .expect(1)
            .mount(&server)
            .await;

        provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_is_a_no_op_when_record_absent() {
        let server = MockServer::start().await;
        mount_zone_mock(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/rrsets",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rrsets": []})))
            .mount(&server)
            .await;
        // No POST /changes mock: an empty change request would fail the test

        provider(&server)
            .delete_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_is_a_no_op_when_value_already_present() {
        let server = MockServer::start().await;
        mount_zone_mock(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/rrsets",
            ))
            .respond_with(rrsets_response(json!(["\"digest-value\""])))
            .mount(&server)
            .await;
        // No POST /changes mock: an identity change request would fail the test

        provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn lists_zones_across_pages() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/projects/test-project/managedZones"))
            .and(query_param_is_missing("pageToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "managedZones": [{"name": "other-zone", "dnsName": "other.org."}],
                "nextPageToken": "p2",
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/projects/test-project/managedZones"))
            .and(query_param("pageToken", "p2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "managedZones": [{"name": "example-zone", "dnsName": "example.com."}],
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/rrsets",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rrsets": []})))
            .mount(&server)
            .await;

        // The zone from the second page must be found
        provider(&server)
            .delete_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_removes_only_the_given_value() {
        let server = MockServer::start().await;
        mount_zone_mock(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/rrsets",
            ))
            .respond_with(rrsets_response(json!([
                "\"digest-value\"",
                "\"other-value\""
            ])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/projects/test-project/managedZones/example-zone/changes",
            ))
            .and(body_partial_json(json!({
                "additions": [{"rrdatas": ["\"other-value\""]}],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "c1",
                "status": "done",
            })))
            .expect(1)
            .mount(&server)
            .await;

        provider(&server)
            .delete_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }
}
