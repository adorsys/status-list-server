//! Azure Key Vault secret storage adapter implementing [`Storage`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use azure_core::credentials::{Secret as AzureSecret, TokenCredential};
use azure_core::http::{HttpClient, StatusCode};
use azure_identity::ClientSecretCredential;
use azure_security_keyvault_secrets::SecretClient;
use azure_security_keyvault_secrets::models::SetSecretParameters;
use color_eyre::eyre::eyre;
use moka::future::Cache;
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, info, warn};
use url::Url;

use crate::cert_manager::storage::{Storage, StorageError, normalize_key};
use crate::outbound::azure_identity::DefaultAzureCredential;

/// Azure Key Vault secret storage adapter.
///
/// Implements the [`Storage`] trait so it can be used as a secrets backend
/// by the certificate manager.
pub struct AzureKeyVaultClient {
    client: SecretClient,
    cache: Option<Cache<String, String>>,
}

impl AzureKeyVaultClient {
    const CACHE_MAX_CAPACITY: u64 = 100;

    /// Return an [`AzureKeyVaultClientBuilder`] for constructing an adapter
    /// for the given Key Vault URL.
    pub fn builder(vault_url: Url) -> AzureKeyVaultClientBuilder {
        AzureKeyVaultClientBuilder::new(vault_url)
    }

    /// Sanitize key to satisfy Azure Key Vault object naming rules:
    /// 1-127 characters, containing only 0-9, a-z, A-Z, and -.
    pub(crate) fn qualify_key(key: &str) -> String {
        normalize_key(key)
    }
}

/// Builder for constructing an [`AzureKeyVaultClient`] adapter.
#[derive(Clone)]
pub struct AzureKeyVaultClientBuilder {
    vault_url: Url,
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<SecretString>,
    custom_credential: Option<Arc<dyn TokenCredential>>,
    verify_challenge_resource: bool,
    secrets_cache_ttl: Duration,
    http_client: Option<Arc<dyn HttpClient>>,
}

impl std::fmt::Debug for AzureKeyVaultClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureKeyVaultClientBuilder")
            .field("vault_url", &self.vault_url)
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "custom_credential",
                &self
                    .custom_credential
                    .as_ref()
                    .map(|_| "<token_credential>"),
            )
            .field(
                "http_client",
                &self.http_client.as_ref().map(|_| "<http_client>"),
            )
            .field("verify_challenge_resource", &self.verify_challenge_resource)
            .field("secrets_cache_ttl", &self.secrets_cache_ttl)
            .finish()
    }
}

impl AzureKeyVaultClientBuilder {
    /// Create a new [`AzureKeyVaultClientBuilder`] with the vault URL.
    pub fn new(vault_url: Url) -> Self {
        Self {
            vault_url,
            tenant_id: None,
            client_id: None,
            client_secret: None,
            custom_credential: None,
            verify_challenge_resource: true,
            secrets_cache_ttl: Duration::from_secs(300),
            http_client: None,
        }
    }

    /// Set explicit service principal credentials.
    pub fn service_principal(
        mut self,
        tenant_id: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<SecretString>,
    ) -> Self {
        self.tenant_id = tenant_id.map(String::from);
        self.client_id = client_id.map(String::from);
        self.client_secret = client_secret;
        self
    }

    /// Provide a custom [`TokenCredential`].
    pub fn credential(mut self, credential: Arc<dyn TokenCredential>) -> Self {
        self.custom_credential = Some(credential);
        self
    }

    /// Configure whether to verify the challenge resource matches the vault URL.
    pub fn verify_challenge_resource(mut self, verify: bool) -> Self {
        self.verify_challenge_resource = verify;
        self
    }

    /// Set the in-memory cache TTL for secret values.
    ///
    /// Setting `secrets_cache_ttl` to `Duration::ZERO` disables caching completely.
    pub fn secrets_cache_ttl(mut self, secrets_cache_ttl: Duration) -> Self {
        self.secrets_cache_ttl = secrets_cache_ttl;
        self
    }

    /// Provide a custom HTTP client for testing or specific transport configurations.
    ///
    /// This replaces the default HTTP transport used by the Azure SDK client.
    pub fn http_client(mut self, http_client: Arc<dyn HttpClient>) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Build the [`AzureKeyVaultClient`] adapter instance.
    pub fn build(self) -> Result<AzureKeyVaultClient, StorageError> {
        let credential: Arc<dyn TokenCredential> = if let Some(cred) = self.custom_credential {
            cred
        } else if let (Some(tenant_id), Some(client_id), Some(client_secret)) =
            (&self.tenant_id, &self.client_id, &self.client_secret)
        {
            ClientSecretCredential::new(
                tenant_id.as_str(),
                client_id.clone(),
                AzureSecret::new(client_secret.expose_secret().to_string()),
                None,
            )
            .map_err(|e| {
                StorageError::Backend(eyre!("failed to create Azure ClientSecretCredential: {e}"))
            })?
        } else {
            DefaultAzureCredential::new().map_err(|e| {
                StorageError::Backend(eyre!("failed to create DefaultAzureCredential: {e}"))
            })?
        };

        let mut options = azure_security_keyvault_secrets::SecretClientOptions {
            verify_challenge_resource: Some(self.verify_challenge_resource),
            ..Default::default()
        };

        if let Some(http_client) = self.http_client {
            options.client_options.transport = Some(azure_core::http::Transport::new(http_client));
        }

        let client = SecretClient::new(self.vault_url.as_str(), credential, Some(options))
            .map_err(|e| {
                StorageError::Backend(eyre!("failed to create Azure SecretClient: {e}"))
            })?;

        let cache = (!self.secrets_cache_ttl.is_zero()).then(|| {
            Cache::builder()
                .max_capacity(AzureKeyVaultClient::CACHE_MAX_CAPACITY)
                .time_to_live(self.secrets_cache_ttl)
                .build()
        });

        if self.secrets_cache_ttl.is_zero() {
            info!("Azure Key Vault cache disabled (TTL=0)");
        }

        Ok(AzureKeyVaultClient { client, cache })
    }
}

#[async_trait]
impl Storage for AzureKeyVaultClient {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let secret_name = Self::qualify_key(key);
        let parameters = SetSecretParameters {
            value: Some(value.to_string()),
            ..Default::default()
        };

        let set_res = self
            .client
            .set_secret(
                &secret_name,
                parameters.clone().try_into().map_err(|e| {
                    StorageError::Backend(eyre!("failed to serialize Azure secret parameters: {e}"))
                })?,
                None,
            )
            .await;

        match set_res {
            Ok(_) => {}
            Err(err) if err.http_status() == Some(StatusCode::Conflict) => {
                // Secret is in soft-deleted state. Trigger recovery and poll until available.
                info!("Azure secret '{key}' is in soft-deleted state; initiating recovery");
                self.client
                    .recover_deleted_secret(&secret_name, None)
                    .await
                    .map_err(|e| {
                        warn!(
                            "Failed to initiate recovery for soft-deleted Azure secret '{key}': {e}"
                        );
                        StorageError::Backend(eyre!(
                            "failed to initiate recovery of soft-deleted Azure secret '{key}': {e}"
                        ))
                    })?;

                // Recovery in Azure Key Vault is asynchronous; poll with bounded backoff
                let mut recovered = false;
                for attempt in 1..=10 {
                    tokio::time::sleep(Duration::from_millis(attempt * 200)).await;
                    match self
                        .client
                        .set_secret(
                            &secret_name,
                            parameters.clone().try_into().map_err(|e| {
                                StorageError::Backend(eyre!(
                                    "failed to serialize Azure secret parameters: {e}"
                                ))
                            })?,
                            None,
                        )
                        .await
                    {
                        Ok(_) => {
                            recovered = true;
                            break;
                        }
                        Err(retry_err) if retry_err.http_status() == Some(StatusCode::Conflict) => {
                            debug!(
                                "Azure secret '{key}' recovery still pending (attempt {attempt}/10)"
                            );
                        }
                        Err(other_err) => {
                            return Err(StorageError::Backend(eyre!(
                                "failed to set Azure secret '{key}' after recovery: {other_err}"
                            )));
                        }
                    }
                }

                if !recovered {
                    return Err(StorageError::Backend(eyre!(
                        "timeout waiting for Azure secret '{key}' recovery to complete"
                    )));
                }
            }
            Err(e) => {
                return Err(StorageError::Backend(eyre!(
                    "failed to set Azure secret '{key}': {e}"
                )));
            }
        }

        if let Some(cache) = &self.cache {
            cache.insert(key.to_string(), value.to_string()).await;
        }

        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        if let Some(cache) = &self.cache
            && let Some(val) = cache.get(key).await
        {
            return Ok(Some(val));
        }

        let secret_name = Self::qualify_key(key);
        match self.client.get_secret(&secret_name, None).await {
            Ok(resp) => {
                let model = resp.into_model().map_err(|e| {
                    StorageError::Backend(eyre!(
                        "failed to parse Azure secret response model for '{key}': {e}"
                    ))
                })?;

                let value = model.value;

                if let Some(val) = &value
                    && let Some(cache) = &self.cache
                {
                    cache.insert(key.to_string(), val.clone()).await;
                }
                Ok(value)
            }
            Err(err) => {
                if err.http_status() == Some(StatusCode::NotFound) {
                    Ok(None)
                } else {
                    Err(StorageError::Backend(eyre!(
                        "Azure secret load failed for key '{key}': {err}"
                    )))
                }
            }
        }
    }

    async fn update(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.store(key, value).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let secret_name = Self::qualify_key(key);
        match self.client.delete_secret(&secret_name, None).await {
            Ok(_) => {
                if let Some(cache) = &self.cache {
                    cache.invalidate(key).await;
                }
                // Try purging the soft-deleted secret if purge is allowed on the vault
                if let Err(e) = self.client.purge_deleted_secret(&secret_name, None).await {
                    warn!("Azure purge for deleted secret '{key}' skipped/failed: {e}");
                }
                Ok(())
            }
            Err(err) => {
                if err.http_status() == Some(StatusCode::NotFound) {
                    if let Some(cache) = &self.cache {
                        cache.invalidate(key).await;
                    }
                    Ok(())
                } else {
                    Err(StorageError::Backend(eyre!(
                        "Azure secret delete failed for key '{key}': {err}"
                    )))
                }
            }
        }
    }

    async fn reachable(&self) -> Result<(), StorageError> {
        match self
            .client
            .get_secret("health-probe-do-not-create", None)
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => {
                if err.http_status() == Some(StatusCode::NotFound) {
                    Ok(())
                } else {
                    Err(StorageError::Backend(eyre!(
                        "Azure Key Vault readiness check failed: {err}"
                    )))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_builder() {
        let endpoint = Url::parse("https://my-vault.vault.azure.net/").unwrap();
        let builder = AzureKeyVaultClient::builder(endpoint)
            .service_principal(
                Some("tenant-123"),
                Some("client-456"),
                Some(SecretString::from("secret-789")),
            )
            .verify_challenge_resource(false)
            .secrets_cache_ttl(Duration::from_secs(600));

        assert_eq!(
            builder.vault_url.as_str(),
            "https://my-vault.vault.azure.net/"
        );
        assert_eq!(builder.tenant_id.as_deref(), Some("tenant-123"));
        assert_eq!(builder.client_id.as_deref(), Some("client-456"));
        assert!(builder.client_secret.is_some());
        assert!(!builder.verify_challenge_resource);
        assert_eq!(builder.secrets_cache_ttl, Duration::from_secs(600));

        let debug_repr = format!("{builder:?}");
        assert!(debug_repr.contains("<redacted>"));
        assert!(!debug_repr.contains("secret-789"));
    }

    #[test]
    fn test_qualify_key() {
        assert_eq!(
            AzureKeyVaultClient::qualify_key("keys-status.example.com"),
            "keys-status-example-com"
        );
        assert_eq!(
            AzureKeyVaultClient::qualify_key("acme_accounts-example.com"),
            "acme-accounts-example-com"
        );
        assert_eq!(
            AzureKeyVaultClient::qualify_key("certs-status.example.com-cert_data.json"),
            "certs-status-example-com-cert-data-json"
        );
        assert_eq!(
            AzureKeyVaultClient::qualify_key("valid-key-123"),
            "valid-key-123"
        );
    }
}
