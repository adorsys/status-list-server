use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
#[cfg(test)]
use azure_core::credentials::{AccessToken, TokenRequestOptions};
use color_eyre::eyre::{Report, eyre};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::info;

use super::{DnsProvider, ZoneInfo, find_best_match, http_client, token::TokenCache};
use crate::cert_manager::challenge::ChallengeError;
use crate::outbound::azure_identity::DefaultAzureCredential;

const PROVIDER: &str = "azure";
const DEFAULT_LOGIN_BASE: &str = "https://login.microsoftonline.com";
const DEFAULT_API_BASE: &str = "https://management.azure.com";
const API_VERSION: &str = "2018-05-01";

/// A DNS provider for Azure DNS, authenticated with a service principal.
///
/// The service principal needs the `DNS Zone Contributor` role on the
/// resource group holding the zones. Azure documents that record changes
/// reach its authoritative name servers typically within 60 seconds and
/// offers no change-status API to poll, so `create_txt_record` waits a
/// fixed settle delay after a successful change.
pub struct AzureDnsProvider {
    client: Client,
    token_source: Box<dyn AzureAccessTokenProvider>,
    subscription_id: String,
    resource_group: String,
    login_base: String,
    api_base: String,
    propagation_delay: Duration,
    zones: RwLock<Option<Vec<ZoneInfo>>>,
}

pub struct ServicePrincipal {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: SecretString,
}

#[async_trait]
trait AzureAccessTokenProvider: Send + Sync {
    async fn access_token(
        &self,
        client: &Client,
        login_base: &str,
        api_base: &str,
    ) -> Result<SecretString, ChallengeError>;
}

impl fmt::Debug for dyn AzureAccessTokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<azure_access_token_provider>")
    }
}

struct ServicePrincipalTokenSource {
    credentials: ServicePrincipal,
    token_cache: TokenCache,
}

struct AmbientTokenSource {
    credential: Arc<dyn TokenCredential>,
    token_cache: TokenCache,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    properties: RecordSetProperties,
}

/// Concurrency guard for record set writes
enum Precondition<'a> {
    /// Apply only if the record set still has this etag
    IfMatch(&'a str),
    /// Apply only if the record set does not exist yet
    IfNoneMatch,
    /// Apply unconditionally (no etag available)
    None,
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
    // Azure's documented propagation window for record changes
    const PROPAGATION_DELAY: Duration = Duration::from_secs(60);
    const CONFLICT_RETRIES: u32 = 3;

    pub fn new(
        credentials: ServicePrincipal,
        subscription_id: impl Into<String>,
        resource_group: impl Into<String>,
    ) -> Self {
        Self {
            client: http_client(),
            token_source: Box::new(ServicePrincipalTokenSource {
                credentials,
                token_cache: TokenCache::new(),
            }),
            subscription_id: subscription_id.into(),
            resource_group: resource_group.into(),
            login_base: DEFAULT_LOGIN_BASE.to_string(),
            api_base: DEFAULT_API_BASE.to_string(),
            propagation_delay: Self::PROPAGATION_DELAY,
            zones: RwLock::new(None),
        }
    }

    /// Create a provider from Azure managed identity / workload identity federation.
    pub fn from_ambient_credentials(
        subscription_id: impl Into<String>,
        resource_group: impl Into<String>,
    ) -> Result<Self, ChallengeError> {
        let credential = DefaultAzureCredential::new().map_err(|e| {
            dns_err(eyre!(
                "Failed to initialize Azure DNS ambient credential chain. \
                 Configure AKS Workload Identity, managed identity, or Azure CLI auth. \
                 Details: {e}"
            ))
        })?;
        Ok(Self::from_token_provider(
            Box::new(AmbientTokenSource {
                credential,
                token_cache: TokenCache::new(),
            }),
            subscription_id,
            resource_group,
        ))
    }

    fn from_token_provider(
        token_source: Box<dyn AzureAccessTokenProvider>,
        subscription_id: impl Into<String>,
        resource_group: impl Into<String>,
    ) -> Self {
        Self {
            client: http_client(),
            token_source,
            subscription_id: subscription_id.into(),
            resource_group: resource_group.into(),
            login_base: DEFAULT_LOGIN_BASE.to_string(),
            api_base: DEFAULT_API_BASE.to_string(),
            propagation_delay: Self::PROPAGATION_DELAY,
            zones: RwLock::new(None),
        }
    }

    /// Override the login and API base URLs (used in tests)
    pub fn with_base_urls(
        mut self,
        login_base: impl Into<String>,
        api_base: impl Into<String>,
    ) -> Self {
        self.login_base = login_base.into().trim_end_matches('/').to_string();
        self.api_base = api_base.into().trim_end_matches('/').to_string();
        self
    }

    /// Override the propagation settle delay (used in tests)
    pub fn with_propagation_delay(mut self, delay: Duration) -> Self {
        self.propagation_delay = delay;
        self
    }

    async fn access_token(&self) -> Result<SecretString, ChallengeError> {
        self.token_source
            .access_token(&self.client, &self.login_base, &self.api_base)
            .await
    }
}

#[async_trait]
impl AzureAccessTokenProvider for ServicePrincipalTokenSource {
    async fn access_token(
        &self,
        client: &Client,
        login_base: &str,
        api_base: &str,
    ) -> Result<SecretString, ChallengeError> {
        self.token_cache
            .get_or_mint(|| async {
                let url = format!(
                    "{}/{}/oauth2/v2.0/token",
                    login_base, self.credentials.tenant_id
                );
                let scope = format!("{}/.default", api_base);
                let response = client
                    .post(&url)
                    .form(&[
                        ("grant_type", "client_credentials"),
                        ("client_id", &self.credentials.client_id),
                        (
                            "client_secret",
                            self.credentials.client_secret.expose_secret(),
                        ),
                        ("scope", &scope),
                    ])
                    .send()
                    .await
                    .map_err(dns_err)?;
                let status = response.status();
                if !status.is_success() {
                    let body = response.text().await.unwrap_or_default();
                    return Err(dns_err(eyre!(
                        "Azure DNS service-principal token request failed \
                         (status {status}): {body}"
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
}

#[async_trait]
impl AzureAccessTokenProvider for AmbientTokenSource {
    async fn access_token(
        &self,
        _client: &Client,
        _login_base: &str,
        api_base: &str,
    ) -> Result<SecretString, ChallengeError> {
        let scope = format!("{}/.default", api_base);
        self.token_cache
            .get_or_mint(|| async {
                let token = self
                    .credential
                    .get_token(&[scope.as_str()], None)
                    .await
                    .map_err(|e| {
                        dns_err(eyre!(
                            "Failed to acquire Azure DNS ambient access token. Verify AKS \
                             Workload Identity, managed identity endpoint, or Azure CLI login. \
                             Details: {e}"
                        ))
                    })?;
                let expires_in = (token.expires_on - OffsetDateTime::now_utc())
                    .try_into()
                    .unwrap_or(Duration::ZERO);
                Ok((token.token.secret().to_string().into(), expires_in))
            })
            .await
    }
}

impl AzureDnsProvider {
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
            return Err(dns_err(eyre!(
                "API request failed (status {status}): {body}"
            )));
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

    // Write the record set under the given precondition.
    // Returns false when the precondition failed (concurrent modification).
    async fn put_record_set(
        &self,
        zone: &str,
        relative_name: &str,
        records: Vec<TxtRecord>,
        precondition: Precondition<'_>,
        token: &SecretString,
    ) -> Result<bool, ChallengeError> {
        let record_set = RecordSet {
            etag: None,
            properties: RecordSetProperties {
                ttl: Self::TXT_TTL,
                txt_records: records,
            },
        };
        let mut request = self
            .client
            .put(self.record_set_url(zone, relative_name))
            .bearer_auth(token.expose_secret())
            .json(&record_set);
        request = match precondition {
            Precondition::IfMatch(etag) => request.header(reqwest::header::IF_MATCH, etag),
            Precondition::IfNoneMatch => request.header(reqwest::header::IF_NONE_MATCH, "*"),
            Precondition::None => request,
        };
        let response = request.send().await.map_err(dns_err)?;
        if response.status() == StatusCode::PRECONDITION_FAILED {
            return Ok(false);
        }
        Self::parse_response::<serde_json::Value>(response).await?;
        Ok(true)
    }

    // Delete the whole record set under the given precondition.
    // Returns false when the precondition failed (concurrent modification).
    async fn delete_record_set(
        &self,
        zone: &str,
        relative_name: &str,
        precondition: Precondition<'_>,
        token: &SecretString,
    ) -> Result<bool, ChallengeError> {
        let mut request = self
            .client
            .delete(self.record_set_url(zone, relative_name))
            .bearer_auth(token.expose_secret());
        if let Precondition::IfMatch(etag) = precondition {
            request = request.header(reqwest::header::IF_MATCH, etag);
        }
        let response = request.send().await.map_err(dns_err)?;
        let status = response.status();
        if status == StatusCode::PRECONDITION_FAILED {
            return Ok(false);
        }
        if !status.is_success() && status != StatusCode::NOT_FOUND {
            let body = response.text().await.unwrap_or_default();
            return Err(dns_err(eyre!(
                "Failed to delete record set (status {status}): {body}"
            )));
        }
        Ok(true)
    }
}

#[async_trait]
impl DnsProvider for AzureDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{}", domain.trim_end_matches('.'));
        let (zone, relative_name) = self
            .find_zone_and_relative_name(domain, &record_name)
            .await?;
        let token = self.access_token().await?;

        let mut attempts = 0;
        loop {
            // Merge with the existing record set since PUT replaces it
            let existing = self.get_record_set(&zone, &relative_name, &token).await?;
            let etag = existing.as_ref().and_then(|r| r.etag.clone());
            let precondition = match (&existing, &etag) {
                (Some(_), Some(etag)) => Precondition::IfMatch(etag),
                (Some(_), None) => Precondition::None,
                (None, _) => Precondition::IfNoneMatch,
            };
            let mut records = existing
                .map(|r| r.properties.txt_records)
                .unwrap_or_default();
            let record = TxtRecord {
                value: vec![value.to_string()],
            };
            if !records.contains(&record) {
                records.push(record);
            }

            if self
                .put_record_set(&zone, &relative_name, records, precondition, &token)
                .await?
            {
                break;
            }
            attempts += 1;
            if attempts > Self::CONFLICT_RETRIES {
                return Err(dns_err(eyre!(
                    "Record set {record_name} kept being modified concurrently"
                )));
            }
            info!("Azure DNS record set conflict for {record_name}, retrying...");
        }

        // No change-status API to poll; wait out the documented propagation window
        tokio::time::sleep(self.propagation_delay).await;

        info!("DNS record {record_name} created for {domain}");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{}", domain.trim_end_matches('.'));
        let (zone, relative_name) = self
            .find_zone_and_relative_name(domain, &record_name)
            .await?;
        let token = self.access_token().await?;

        let mut attempts = 0;
        loop {
            let Some(existing) = self.get_record_set(&zone, &relative_name, &token).await? else {
                // Nothing to delete
                break;
            };
            let etag = existing.etag.clone();
            let precondition = match &etag {
                Some(etag) => Precondition::IfMatch(etag),
                None => Precondition::None,
            };
            let records: Vec<TxtRecord> = existing
                .properties
                .txt_records
                .into_iter()
                .filter(|r| r.value != [value.to_string()])
                .collect();

            let applied = if records.is_empty() {
                // Delete the whole record set when no values remain
                self.delete_record_set(&zone, &relative_name, precondition, &token)
                    .await?
            } else {
                self.put_record_set(&zone, &relative_name, records, precondition, &token)
                    .await?
            };
            if applied {
                break;
            }
            attempts += 1;
            if attempts > Self::CONFLICT_RETRIES {
                return Err(dns_err(eyre!(
                    "Record set {record_name} kept being modified concurrently"
                )));
            }
            info!("Azure DNS record set conflict for {record_name}, retrying...");
        }

        info!("DNS record {record_name} deleted for {domain}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::credentials::Secret as AzureSecret;
    use color_eyre::eyre::eyre;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use time::OffsetDateTime;
    use wiremock::matchers::{body_partial_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ZONES_PATH: &str =
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones";

    struct FakeAzureTokenSource(Result<SecretString, &'static str>);

    #[async_trait]
    impl AzureAccessTokenProvider for FakeAzureTokenSource {
        async fn access_token(
            &self,
            _client: &Client,
            _login_base: &str,
            _api_base: &str,
        ) -> Result<SecretString, ChallengeError> {
            self.0
                .clone()
                .map_err(|msg| dns_err(eyre!("fake ambient token failure: {msg}")))
        }
    }

    #[derive(Debug)]
    struct StaticAzureCredential;

    #[async_trait]
    impl TokenCredential for StaticAzureCredential {
        async fn get_token(
            &self,
            _scopes: &[&str],
            _options: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            Ok(AccessToken::new(
                AzureSecret::new("ambient-azure-token"),
                OffsetDateTime::now_utc() + Duration::from_secs(3600),
            ))
        }
    }

    #[derive(Debug)]
    struct CountingAzureCredential {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl TokenCredential for CountingAzureCredential {
        async fn get_token(
            &self,
            _scopes: &[&str],
            _options: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(AccessToken::new(
                AzureSecret::new("cached-ambient-azure-token"),
                OffsetDateTime::now_utc() + Duration::from_secs(3600),
            ))
        }
    }

    #[derive(Debug)]
    struct FailingAzureCredential;

    #[async_trait]
    impl TokenCredential for FailingAzureCredential {
        async fn get_token(
            &self,
            _scopes: &[&str],
            _options: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            Err(azure_core::Error::with_message(
                azure_core::error::ErrorKind::Credential,
                "identity endpoint unavailable",
            ))
        }
    }

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
        .with_propagation_delay(Duration::ZERO)
    }

    fn ambient_provider(
        server: &MockServer,
        token: Result<SecretString, &'static str>,
    ) -> AzureDnsProvider {
        AzureDnsProvider::from_token_provider(
            Box::new(FakeAzureTokenSource(token)),
            "sub-1",
            "rg-1",
        )
        .with_base_urls(server.uri(), server.uri())
        .with_propagation_delay(Duration::ZERO)
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
    async fn ambient_token_source_drives_dns_requests() {
        let server = MockServer::start().await;
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
            .and(header("authorization", "Bearer ambient-azure-token"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;

        ambient_provider(&server, Ok("ambient-azure-token".into()))
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn azure_token_credential_can_back_ambient_source() {
        let token = AmbientTokenSource {
            credential: Arc::new(StaticAzureCredential),
            token_cache: TokenCache::new(),
        }
        .access_token(&http_client(), DEFAULT_LOGIN_BASE, DEFAULT_API_BASE)
        .await
        .unwrap();

        assert_eq!(token.expose_secret(), "ambient-azure-token");
    }

    #[tokio::test]
    async fn ambient_token_source_caches_acquired_tokens() {
        let credential = Arc::new(CountingAzureCredential {
            calls: AtomicUsize::new(0),
        });
        let token_source = AmbientTokenSource {
            credential: credential.clone(),
            token_cache: TokenCache::new(),
        };

        for _ in 0..3 {
            let token = token_source
                .access_token(&http_client(), DEFAULT_LOGIN_BASE, DEFAULT_API_BASE)
                .await
                .unwrap();
            assert_eq!(token.expose_secret(), "cached-ambient-azure-token");
        }

        assert_eq!(credential.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ambient_token_source_fetch_failure_is_redacted_and_actionable() {
        let err = AmbientTokenSource {
            credential: Arc::new(FailingAzureCredential),
            token_cache: TokenCache::new(),
        }
        .access_token(&http_client(), DEFAULT_LOGIN_BASE, DEFAULT_API_BASE)
        .await
        .unwrap_err();

        match err {
            ChallengeError::Dns { provider, source } => {
                assert_eq!(provider, "azure");
                let msg = source.to_string();
                assert!(msg.contains("Failed to acquire Azure DNS ambient access token"));
                assert!(msg.contains("Workload Identity"));
                assert!(msg.contains("managed identity"));
                assert!(msg.contains("identity endpoint unavailable"));
                assert!(!msg.contains("client_secret"));
                assert!(!msg.contains("password"));
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn ambient_token_failure_is_redacted_and_actionable() {
        let server = MockServer::start().await;
        let err = ambient_provider(&server, Err("identity endpoint unavailable"))
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap_err();
        match err {
            ChallengeError::Dns { provider, source } => {
                assert_eq!(provider, "azure");
                let msg = source.to_string();
                assert!(msg.contains("ambient token failure"));
                assert!(msg.contains("identity endpoint unavailable"));
                assert!(!msg.contains("client_secret"));
                assert!(!msg.contains("password"));
            }
            other => panic!("Unexpected error: {other:?}"),
        }
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
    async fn delete_is_a_no_op_when_record_absent() {
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
        // No PUT/DELETE mocks: any write request would fail the test

        provider(&server)
            .delete_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn retries_on_etag_conflict() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;
        mount_zone_mock(&server).await;
        let record_path = format!("{ZONES_PATH}/example.com/TXT/_acme-challenge.status");
        Mock::given(method("GET"))
            .and(path(&record_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "etag": "e1",
                "properties": {"TTL": 60, "TXTRecords": [{"value": ["other-value"]}]},
            })))
            .expect(2)
            .mount(&server)
            .await;
        // First write loses the etag race, the retry succeeds
        Mock::given(method("PUT"))
            .and(path(&record_path))
            .and(header("if-match", "e1"))
            .respond_with(ResponseTemplate::new(412).set_body_json(json!({
                "error": {"code": "PreconditionFailed"},
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(&record_path))
            .and(header("if-match", "e1"))
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
    async fn lists_zones_across_pages() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;
        Mock::given(method("GET"))
            .and(path(ZONES_PATH))
            .and(query_param("api-version", API_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"name": "other.org"}],
                "nextLink": format!("{}/zones-page-2", server.uri()),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/zones-page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"name": "example.com"}],
            })))
            .expect(1)
            .mount(&server)
            .await;
        let record_path = format!("{ZONES_PATH}/example.com/TXT/_acme-challenge.status");
        Mock::given(method("GET"))
            .and(path(&record_path))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {"code": "NotFound"},
            })))
            .mount(&server)
            .await;

        // The zone from the second page must be found
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
