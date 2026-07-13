use async_trait::async_trait;
use color_eyre::eyre::eyre;
use reqwest::Client;
use serde_json::json;

use super::DnsProvider;
use crate::cert_manager::challenge::ChallengeError;

/// Handler for Pebble DNS (mainly for generating test certificates)
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
impl DnsProvider for PebbleDnsUpdater {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{domain}.");
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

    async fn delete_txt_record(&self, domain: &str, _value: &str) -> Result<(), ChallengeError> {
        let record_name = format!("_acme-challenge.{domain}.");
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
