use std::sync::Arc;

use async_trait::async_trait;
use color_eyre::eyre::{Report, eyre};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;
use tracing::info;

use super::{DnsProvider, ZoneInfo, find_best_match};
use crate::cert_manager::challenge::ChallengeError;

const PROVIDER: &str = "cloudflare";
const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// A DNS provider for Cloudflare, authenticated with an API token.
///
/// The token needs the `Zone.Zone:Read` and `Zone.DNS:Edit` permissions.
/// Record changes are served by Cloudflare's authoritative name servers
/// as soon as the API call returns, so no propagation wait is needed.
pub struct CloudflareDnsProvider {
    client: Client,
    api_token: SecretString,
    api_base: String,
    zones: Arc<RwLock<Option<Vec<ZoneInfo>>>>,
}

/// Response envelope shared by all Cloudflare API endpoints
#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<T>,
    result_info: Option<ResultInfo>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ResultInfo {
    page: u32,
    total_pages: u32,
}

#[derive(Debug, Deserialize)]
struct ZoneEntry {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct RecordEntry {
    id: String,
}

fn dns_err(source: impl Into<Report>) -> ChallengeError {
    ChallengeError::Dns {
        provider: PROVIDER,
        source: source.into(),
    }
}

impl CloudflareDnsProvider {
    const TXT_TTL: u32 = 60;

    pub fn new(api_token: SecretString) -> Self {
        Self {
            client: Client::new(),
            api_token,
            api_base: DEFAULT_API_BASE.to_string(),
            zones: Arc::new(RwLock::new(None)),
        }
    }

    /// Override the API base URL (used in tests)
    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.api_base = api_base.into();
        self
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<ApiResponse<T>, ChallengeError> {
        let response = self
            .client
            .get(url)
            .bearer_auth(self.api_token.expose_secret())
            .send()
            .await
            .map_err(dns_err)?;
        Self::parse_response(response).await
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<ApiResponse<T>, ChallengeError> {
        let status = response.status();
        let body: ApiResponse<T> = response
            .json()
            .await
            .map_err(|e| dns_err(eyre!("Invalid API response (status {status}): {e}")))?;
        if !body.success {
            let errors: Vec<String> = body
                .errors
                .iter()
                .map(|e| format!("{} (code {})", e.message, e.code))
                .collect();
            return Err(dns_err(eyre!(
                "API request failed (status {status}): {}",
                errors.join("; ")
            )));
        }
        Ok(body)
    }

    // Find the zone for the given domain and return its ID
    async fn find_zone(&self, domain: &str) -> Result<String, ChallengeError> {
        self.try_cache_zones().await?;

        let read_guard = self.zones.read().await;
        let zones = read_guard.as_ref().unwrap();
        let domain = domain.trim_end_matches('.');

        if let Some((zone_id, zone_name)) = find_best_match(domain, zones) {
            info!("Found best matching Cloudflare zone: {zone_name}");
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

        let mut all_zones = Vec::new();
        let mut page = 1;

        // try to get all zones
        loop {
            let url = format!("{}/zones?page={page}&per_page=50", self.api_base);
            let body: ApiResponse<Vec<ZoneEntry>> = self.get_json(&url).await?;

            for zone in body.result.unwrap_or_default() {
                all_zones.push(ZoneInfo::new(zone.name, zone.id));
            }

            // Check if there are more pages
            match body.result_info {
                Some(info) if info.page < info.total_pages => page = info.page + 1,
                _ => break,
            }
        }
        info!("Found Cloudflare zones: {all_zones:?}");
        *self.zones.write().await = Some(all_zones);
        Ok(())
    }

    // Find the IDs of TXT records matching the given name and value
    async fn find_txt_records(
        &self,
        zone_id: &str,
        record_name: &str,
        value: &str,
    ) -> Result<Vec<String>, ChallengeError> {
        let url = format!(
            "{}/zones/{zone_id}/dns_records?type=TXT&name={record_name}&content={value}",
            self.api_base
        );
        let body: ApiResponse<Vec<RecordEntry>> = self.get_json(&url).await?;
        Ok(body
            .result
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.id)
            .collect())
    }
}

#[async_trait]
impl DnsProvider for CloudflareDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{domain}");
        let zone_id = self.find_zone(domain).await?;

        let url = format!("{}/zones/{zone_id}/dns_records", self.api_base);
        let response = self
            .client
            .post(&url)
            .bearer_auth(self.api_token.expose_secret())
            .json(&json!({
                "type": "TXT",
                "name": record_name,
                "content": value,
                "ttl": Self::TXT_TTL,
            }))
            .send()
            .await
            .map_err(dns_err)?;
        Self::parse_response::<RecordEntry>(response).await?;

        info!("DNS record {record_name} created for {domain}");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{domain}");
        let zone_id = self.find_zone(domain).await?;

        for record_id in self
            .find_txt_records(&zone_id, &record_name, value)
            .await?
        {
            let url = format!("{}/zones/{zone_id}/dns_records/{record_id}", self.api_base);
            let response = self
                .client
                .delete(&url)
                .bearer_auth(self.api_token.expose_secret())
                .send()
                .await
                .map_err(dns_err)?;
            Self::parse_response::<RecordEntry>(response).await?;
        }

        info!("DNS record {record_name} deleted for {domain}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn provider(server: &MockServer) -> CloudflareDnsProvider {
        CloudflareDnsProvider::new("test-token".into()).with_api_base(server.uri())
    }

    fn zone_list_mock() -> Mock {
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [{"id": "z1", "name": "example.com"}],
                "result_info": {"page": 1, "total_pages": 1},
            })))
    }

    #[tokio::test]
    async fn creates_txt_record_in_best_matching_zone() {
        let server = MockServer::start().await;
        zone_list_mock().expect(1).mount(&server).await;
        Mock::given(method("POST"))
            .and(path("/zones/z1/dns_records"))
            .and(header("authorization", "Bearer test-token"))
            .and(body_partial_json(json!({
                "type": "TXT",
                "name": "_acme-challenge.status.example.com",
                "content": "digest-value",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": {"id": "r1"},
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
    async fn deletes_all_matching_txt_records() {
        let server = MockServer::start().await;
        zone_list_mock().mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .and(query_param("type", "TXT"))
            .and(query_param("name", "_acme-challenge.status.example.com"))
            .and(query_param("content", "digest-value"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [{"id": "r1"}, {"id": "r2"}],
            })))
            .expect(1)
            .mount(&server)
            .await;
        for record_id in ["r1", "r2"] {
            Mock::given(method("DELETE"))
                .and(path(format!("/zones/z1/dns_records/{record_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "success": true,
                    "errors": [],
                    "result": {"id": record_id},
                })))
                .expect(1)
                .mount(&server)
                .await;
        }

        provider(&server)
            .delete_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fails_when_no_zone_matches() {
        let server = MockServer::start().await;
        zone_list_mock().mount(&server).await;

        let err = provider(&server)
            .create_txt_record("status.other.org", "digest-value")
            .await
            .unwrap_err();
        assert!(matches!(err, ChallengeError::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn surfaces_api_errors_with_provider_name() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "success": false,
                "errors": [{"code": 9109, "message": "Invalid access token"}],
                "result": null,
            })))
            .mount(&server)
            .await;

        let err = provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap_err();
        match err {
            ChallengeError::Dns { provider, source } => {
                assert_eq!(provider, "cloudflare");
                assert!(source.to_string().contains("Invalid access token"));
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }
}
