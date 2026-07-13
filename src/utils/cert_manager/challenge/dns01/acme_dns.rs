use async_trait::async_trait;
use color_eyre::eyre::{Report, eyre};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use tracing::info;

use super::DnsProvider;
use crate::cert_manager::challenge::ChallengeError;

const PROVIDER: &str = "acmedns";

/// A DNS provider for a self-hosted ACME-DNS server (https://github.com/joohoi/acme-dns).
///
/// Requires a pre-registered account and a CNAME from `_acme-challenge.<domain>`
/// to the registered ACME-DNS subdomain. ACME-DNS serves updates immediately
/// and keeps the two most recent TXT values, so deletion is a no-op.
pub struct AcmeDnsProvider {
    client: Client,
    server_url: String,
    username: String,
    password: SecretString,
    subdomain: String,
}

fn dns_err(source: impl Into<Report>) -> ChallengeError {
    ChallengeError::Dns {
        provider: PROVIDER,
        source: source.into(),
    }
}

impl AcmeDnsProvider {
    pub fn new(
        server_url: impl Into<String>,
        username: impl Into<String>,
        password: SecretString,
        subdomain: impl Into<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            server_url: server_url.into(),
            username: username.into(),
            password,
            subdomain: subdomain.into(),
        }
    }
}

#[async_trait]
impl DnsProvider for AcmeDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let url = format!("{}/update", self.server_url);
        let body = json!({"subdomain": self.subdomain, "txt": value});

        let response = self
            .client
            .post(&url)
            .header("X-Api-User", &self.username)
            .header("X-Api-Key", self.password.expose_secret())
            .json(&body)
            .send()
            .await
            .map_err(dns_err)?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(dns_err(eyre!(
                "Failed to update TXT record (status {status}): {body}"
            )));
        }

        info!("ACME-DNS TXT record updated for {domain}");
        Ok(())
    }

    async fn delete_txt_record(&self, _domain: &str, _value: &str) -> Result<(), ChallengeError> {
        // ACME-DNS has no delete endpoint; it rotates the two most recent TXT values
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn provider(server: &MockServer) -> AcmeDnsProvider {
        AcmeDnsProvider::new(
            server.uri(),
            "user-uuid",
            "api-key".into(),
            "subdomain-uuid",
        )
    }

    #[tokio::test]
    async fn updates_txt_record_with_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/update"))
            .and(header("x-api-user", "user-uuid"))
            .and(header("x-api-key", "api-key"))
            .and(body_json(json!({
                "subdomain": "subdomain-uuid",
                "txt": "digest-value",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "txt": "digest-value",
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
    async fn surfaces_update_failures_with_provider_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/update"))
            .respond_with(
                ResponseTemplate::new(401).set_body_json(json!({"error": "bad credentials"})),
            )
            .mount(&server)
            .await;

        let err = provider(&server)
            .create_txt_record("status.example.com", "digest-value")
            .await
            .unwrap_err();
        match err {
            ChallengeError::Dns { provider, source } => {
                assert_eq!(provider, "acmedns");
                assert!(source.to_string().contains("bad credentials"));
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_is_a_no_op() {
        let server = MockServer::start().await;
        // No mocks mounted: any request would fail the test

        provider(&server)
            .delete_txt_record("status.example.com", "digest-value")
            .await
            .unwrap();
    }
}
