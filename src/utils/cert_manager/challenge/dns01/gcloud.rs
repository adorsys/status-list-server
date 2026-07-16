use std::time::Duration;

use async_trait::async_trait;
use color_eyre::eyre::{Report, eyre};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;
use tracing::info;

use super::{DnsProvider, ZoneInfo, find_best_match, http_client, token::TokenCache};
use crate::cert_manager::challenge::ChallengeError;

const PROVIDER: &str = "gcloud";
const DEFAULT_API_BASE: &str = "https://dns.googleapis.com/dns/v1";
const OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";

/// A DNS provider for Google Cloud DNS, authenticated with a service account key.
///
/// Waits for each change to reach the `done` status, which means the record
/// is served by all of the zone's authoritative name servers.
pub struct GoogleCloudDnsProvider {
    client: Client,
    client_email: String,
    token_uri: String,
    project_id: String,
    encoding_key: EncodingKey,
    api_base: String,
    token_cache: TokenCache,
    zones: RwLock<Option<Vec<ZoneInfo>>>,
}

/// Relevant fields of a Google service account key JSON. Only parsed
/// transiently in `new`, so the plaintext private key is not retained;
/// the signing material lives on in the `EncodingKey`.
#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: String,
    project_id: String,
}

#[derive(Serialize)]
struct TokenClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
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
    const TOKEN_LIFETIME: Duration = Duration::from_secs(3600);
    const CONFLICT_RETRIES: u32 = 3;
    const PROPAGATION_INITIAL_DELAY: Duration = Duration::from_secs(2);
    const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(60 * 5);

    /// Create a provider from the service account key JSON
    pub fn new(service_account_key_json: &str) -> Result<Self, ChallengeError> {
        let key: ServiceAccountKey = serde_json::from_str(service_account_key_json)
            .map_err(|e| dns_err(eyre!("Invalid service account key JSON: {e}")))?;
        let encoding_key = EncodingKey::from_rsa_pem(key.private_key.as_bytes())
            .map_err(|e| dns_err(eyre!("Invalid service account private key: {e}")))?;
        Ok(Self {
            client: http_client(),
            client_email: key.client_email,
            token_uri: key.token_uri,
            project_id: key.project_id,
            encoding_key,
            api_base: DEFAULT_API_BASE.to_string(),
            token_cache: TokenCache::new(),
            zones: RwLock::new(None),
        })
    }

    /// Override the API base URL (used in tests)
    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.api_base = api_base.into().trim_end_matches('/').to_string();
        self
    }

    async fn access_token(&self) -> Result<SecretString, ChallengeError> {
        self.token_cache
            .get_or_mint(|| async {
                let iat = time::OffsetDateTime::now_utc().unix_timestamp();
                let claims = TokenClaims {
                    iss: &self.client_email,
                    scope: OAUTH_SCOPE,
                    aud: &self.token_uri,
                    iat,
                    exp: iat + Self::TOKEN_LIFETIME.as_secs() as i64,
                };
                let assertion = jsonwebtoken::encode(
                    &Header::new(Algorithm::RS256),
                    &claims,
                    &self.encoding_key,
                )
                .map_err(|e| dns_err(eyre!("Failed to sign token request: {e}")))?;

                let response = self
                    .client
                    .post(&self.token_uri)
                    .form(&[
                        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                        ("assertion", &assertion),
                    ])
                    .send()
                    .await
                    .map_err(dns_err)?;
                let status = response.status();
                if !status.is_success() {
                    let body = response.text().await.unwrap_or_default();
                    return Err(dns_err(eyre!(
                        "Token exchange failed (status {status}): {body}"
                    )));
                }
                let token: TokenResponse = response
                    .json()
                    .await
                    .map_err(|e| dns_err(eyre!("Invalid token response: {e}")))?;
                Ok((
                    token.access_token.into(),
                    Duration::from_secs(token.expires_in),
                ))
            })
            .await
    }

    fn project_url(&self) -> String {
        format!("{}/projects/{}", self.api_base, self.project_id)
    }

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

    // A throwaway RSA key generated only for these tests; it grants access to
    // nothing and is deliberately named .dummy.pem for secret scanners.
    const TEST_KEY_PEM: &str = include_str!("../../../../../test_data/gcloud_test_key.dummy.pem");

    fn provider(server: &MockServer) -> GoogleCloudDnsProvider {
        let key = json!({
            "client_email": "acme@test-project.iam.gserviceaccount.com",
            "private_key": TEST_KEY_PEM,
            "token_uri": format!("{}/token", server.uri()),
            "project_id": "test-project",
        });
        GoogleCloudDnsProvider::new(&key.to_string())
            .unwrap()
            .with_api_base(server.uri())
    }

    async fn mount_token_mock(server: &MockServer, expected_mints: u64) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "gcp-token",
                "expires_in": 3600,
            })))
            .expect(expected_mints)
            .mount(server)
            .await;
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
        mount_token_mock(&server, 1).await;
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
    async fn retries_on_change_conflict() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;
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
        mount_token_mock(&server, 1).await;
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
        mount_token_mock(&server, 1).await;
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
        mount_token_mock(&server, 1).await;
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
        mount_token_mock(&server, 1).await;
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
        mount_token_mock(&server, 1).await;
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
