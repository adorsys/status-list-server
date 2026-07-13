use std::time::Duration;

use async_trait::async_trait;
use color_eyre::eyre::{Report, eyre};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

use super::{DnsProvider, ZoneInfo, find_best_match, token::TokenCache};
use crate::cert_manager::challenge::ChallengeError;

const PROVIDER: &str = "azure";
const DEFAULT_LOGIN_BASE: &str = "https://login.microsoftonline.com";
const DEFAULT_API_BASE: &str = "https://management.azure.com";
const API_VERSION: &str = "2018-05-01";

/// A DNS provider for Azure DNS, authenticated with a service principal.
///
/// The service principal needs the `DNS Zone Contributor` role on the
/// resource group holding the zones. Azure commits record changes to its
/// authoritative name servers when the API call returns.
pub struct AzureDnsProvider {
    client: Client,
    credentials: ServicePrincipal,
    subscription_id: String,
    resource_group: String,
    login_base: String,
    api_base: String,
    token_cache: TokenCache,
    zones: RwLock<Option<Vec<ZoneInfo>>>,
}

pub struct ServicePrincipal {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: SecretString,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct ZoneList {
    #[serde(default)]
    value: Vec<ZoneEntry>,
    #[serde(rename = "nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct ZoneEntry {
    name: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RecordSet {
    properties: RecordSetProperties,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RecordSetProperties {
    #[serde(rename = "TTL")]
    ttl: u32,
    #[serde(rename = "TXTRecords", default)]
    txt_records: Vec<TxtRecord>,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
struct TxtRecord {
    value: Vec<String>,
}

fn dns_err(source: impl Into<Report>) -> ChallengeError {
    ChallengeError::Dns {
        provider: PROVIDER,
        source: source.into(),
    }
}

impl AzureDnsProvider {
    const TXT_TTL: u32 = 60;

    pub fn new(
        credentials: ServicePrincipal,
        subscription_id: impl Into<String>,
        resource_group: impl Into<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            credentials,
            subscription_id: subscription_id.into(),
            resource_group: resource_group.into(),
            login_base: DEFAULT_LOGIN_BASE.to_string(),
            api_base: DEFAULT_API_BASE.to_string(),
            token_cache: TokenCache::new(),
            zones: RwLock::new(None),
        }
    }

    /// Override the login and API base URLs (used in tests)
    pub fn with_base_urls(
        mut self,
        login_base: impl Into<String>,
        api_base: impl Into<String>,
    ) -> Self {
        self.login_base = login_base.into();
        self.api_base = api_base.into();
        self
    }

    async fn access_token(&self) -> Result<SecretString, ChallengeError> {
        self.token_cache
            .get_or_mint(|| async {
                let url = format!(
                    "{}/{}/oauth2/v2.0/token",
                    self.login_base, self.credentials.tenant_id
                );
                let scope = format!("{}/.default", self.api_base);
                let response = self
                    .client
                    .post(&url)
                    .form(&[
                        ("grant_type", "client_credentials"),
                        ("client_id", &self.credentials.client_id),
                        ("client_secret", self.credentials.client_secret.expose_secret()),
                        ("scope", &scope),
                    ])
                    .send()
                    .await
                    .map_err(dns_err)?;
                let status = response.status();
                if !status.is_success() {
                    let body = response.text().await.unwrap_or_default();
                    return Err(dns_err(eyre!(
                        "Token request failed (status {status}): {body}"
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

    fn zones_url(&self) -> String {
        format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones",
            self.api_base, self.subscription_id, self.resource_group
        )
    }

    fn record_set_url(&self, zone: &str, relative_name: &str) -> String {
        format!(
            "{}/{zone}/TXT/{relative_name}?api-version={API_VERSION}",
            self.zones_url()
        )
    }

    // Find the zone for the given domain and the record name relative to it
    async fn find_zone_and_relative_name(
        &self,
        domain: &str,
        record_name: &str,
    ) -> Result<(String, String), ChallengeError> {
        self.try_cache_zones().await?;

        let read_guard = self.zones.read().await;
        let zones = read_guard.as_ref().unwrap();
        let domain = domain.trim_end_matches('.');

        let Some((_, zone_name)) = find_best_match(domain, zones) else {
            return Err(ChallengeError::ZoneNotFound(domain.to_string()));
        };
        info!("Found best matching Azure DNS zone: {zone_name}");

        let relative_name = record_name
            .strip_suffix(&format!(".{zone_name}"))
            .unwrap_or(record_name)
            .to_string();
        Ok((zone_name.to_string(), relative_name))
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
        let mut next_url = Some(format!("{}?api-version={API_VERSION}", self.zones_url()));

        // try to get all zones
        while let Some(url) = next_url {
            let response = self
                .client
                .get(&url)
                .bearer_auth(token.expose_secret())
                .send()
                .await
                .map_err(dns_err)?;
            let body: ZoneList = Self::parse_response(response).await?;

            for zone in body.value {
                // Azure addresses record sets by zone name
                all_zones.push(ZoneInfo::new(zone.name.clone(), zone.name));
            }
            next_url = body.next_link;
        }
        info!("Found Azure DNS zones: {all_zones:?}");
        *self.zones.write().await = Some(all_zones);
        Ok(())
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, ChallengeError> {
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(dns_err(eyre!("API request failed (status {status}): {body}")));
        }
        response
            .json()
            .await
            .map_err(|e| dns_err(eyre!("Invalid API response (status {status}): {e}")))
    }

    // Fetch the existing TXT record set, if any
    async fn get_record_set(
        &self,
        zone: &str,
        relative_name: &str,
        token: &SecretString,
    ) -> Result<Option<RecordSet>, ChallengeError> {
        let response = self
            .client
            .get(self.record_set_url(zone, relative_name))
            .bearer_auth(token.expose_secret())
            .send()
            .await
            .map_err(dns_err)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(Self::parse_response(response).await?))
    }

    async fn put_record_set(
        &self,
        zone: &str,
        relative_name: &str,
        records: Vec<TxtRecord>,
        token: &SecretString,
    ) -> Result<(), ChallengeError> {
        let record_set = RecordSet {
            properties: RecordSetProperties {
                ttl: Self::TXT_TTL,
                txt_records: records,
            },
        };
        let response = self
            .client
            .put(self.record_set_url(zone, relative_name))
            .bearer_auth(token.expose_secret())
            .json(&record_set)
            .send()
            .await
            .map_err(dns_err)?;
        Self::parse_response::<serde_json::Value>(response).await?;
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for AzureDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{}", domain.trim_end_matches('.'));
        let (zone, relative_name) = self.find_zone_and_relative_name(domain, &record_name).await?;
        let token = self.access_token().await?;

        // Merge with the existing record set since PUT replaces it
        let mut records = self
            .get_record_set(&zone, &relative_name, &token)
            .await?
            .map(|r| r.properties.txt_records)
            .unwrap_or_default();
        let record = TxtRecord {
            value: vec![value.to_string()],
        };
        if !records.contains(&record) {
            records.push(record);
        }
        self.put_record_set(&zone, &relative_name, records, &token)
            .await?;

        info!("DNS record {record_name} created for {domain}");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{}", domain.trim_end_matches('.'));
        let (zone, relative_name) = self.find_zone_and_relative_name(domain, &record_name).await?;
        let token = self.access_token().await?;

        let records: Vec<TxtRecord> = self
            .get_record_set(&zone, &relative_name, &token)
            .await?
            .map(|r| r.properties.txt_records)
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.value != [value.to_string()])
            .collect();

        if records.is_empty() {
            // Delete the whole record set when no values remain
            let response = self
                .client
                .delete(self.record_set_url(&zone, &relative_name))
                .bearer_auth(token.expose_secret())
                .send()
                .await
                .map_err(dns_err)?;
            let status = response.status();
            if !status.is_success() && status != StatusCode::NOT_FOUND {
                let body = response.text().await.unwrap_or_default();
                return Err(dns_err(eyre!(
                    "Failed to delete record set (status {status}): {body}"
                )));
            }
        } else {
            self.put_record_set(&zone, &relative_name, records, &token)
                .await?;
        }

        info!("DNS record {record_name} deleted for {domain}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ZONES_PATH: &str =
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones";

    fn provider(server: &MockServer) -> AzureDnsProvider {
        AzureDnsProvider::new(
            ServicePrincipal {
                tenant_id: "tenant-1".into(),
                client_id: "client-1".into(),
                client_secret: "secret".into(),
            },
            "sub-1",
            "rg-1",
        )
        .with_base_urls(server.uri(), server.uri())
    }

    async fn mount_token_mock(server: &MockServer, expected_mints: u64) {
        Mock::given(method("POST"))
            .and(path("/tenant-1/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "azure-token",
                "expires_in": 3600,
            })))
            .expect(expected_mints)
            .mount(server)
            .await;
    }

    async fn mount_zone_mock(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(ZONES_PATH))
            .and(query_param("api-version", API_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"name": "example.com"}],
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn creates_record_merging_existing_values() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;
        mount_zone_mock(&server).await;
        let record_path = format!("{ZONES_PATH}/example.com/TXT/_acme-challenge.status");
        Mock::given(method("GET"))
            .and(path(&record_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "properties": {"TTL": 60, "TXTRecords": [{"value": ["other-value"]}]},
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(&record_path))
            .and(body_partial_json(json!({
                "properties": {
                    "TXTRecords": [{"value": ["other-value"]}, {"value": ["digest-value"]}],
                },
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;

        provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn creates_record_when_none_exists() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;
        mount_zone_mock(&server).await;
        let record_path = format!("{ZONES_PATH}/example.com/TXT/_acme-challenge.status");
        Mock::given(method("GET"))
            .and(path(&record_path))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {"code": "NotFound"},
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(&record_path))
            .and(body_partial_json(json!({
                "properties": {"TXTRecords": [{"value": ["digest-value"]}]},
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;

        provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_removes_record_set_when_last_value() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;
        mount_zone_mock(&server).await;
        let record_path = format!("{ZONES_PATH}/example.com/TXT/_acme-challenge.status");
        Mock::given(method("GET"))
            .and(path(&record_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "properties": {"TTL": 60, "TXTRecords": [{"value": ["digest-value"]}]},
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(&record_path))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        provider(&server)
            .delete_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn surfaces_api_errors_with_provider_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tenant-1/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": "invalid_client",
            })))
            .mount(&server)
            .await;

        let err = provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap_err();
        match err {
            ChallengeError::Dns { provider, source } => {
                assert_eq!(provider, "azure");
                assert!(source.to_string().contains("invalid_client"));
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }
}
