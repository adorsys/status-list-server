//! Azure Key Vault secret storage adapter implementing [`Storage`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use azure_core::credentials::{Secret as AzureSecret, TokenCredential};
use azure_core::http::{HttpClient, StatusCode};
use azure_identity::{ClientSecretCredential, DeveloperToolsCredential};
use azure_security_keyvault_secrets::SecretClient;
use azure_security_keyvault_secrets::models::SetSecretParameters;
use color_eyre::eyre::eyre;
use moka::future::Cache;
use secrecy::{ExposeSecret, SecretString};
use tracing::info;
use url::Url;

use crate::cert_manager::storage::{Storage, StorageError};

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
}

/// Builder for constructing an [`AzureKeyVaultClient`] adapter.
#[derive(Clone)]
pub struct AzureKeyVaultClientBuilder {
    vault_url: Url,
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<SecretString>,
    custom_credential: Option<Arc<dyn TokenCredential>>,
    http_client: Option<Arc<dyn HttpClient>>,
    secrets_cache_ttl: Duration,
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
            .field("secrets_cache_ttl", &self.secrets_cache_ttl)
            .finish()
    }
}

impl AzureKeyVaultClientBuilder {
    /// Create a new [`AzureKeyVaultClientBuilder`] with the Vault URL.
    pub fn new(vault_url: Url) -> Self {
        Self {
            vault_url,
            tenant_id: None,
            client_id: None,
            client_secret: None,
            custom_credential: None,
            http_client: None,
            secrets_cache_ttl: Duration::from_secs(300),
        }
    }

    /// Set explicit service principal credentials.
    pub fn service_principal(
        mut self,
        tenant_id: Option<impl Into<String>>,
        client_id: Option<impl Into<String>>,
        client_secret: Option<SecretString>,
    ) -> Self {
        self.tenant_id = tenant_id.map(Into::into);
        self.client_id = client_id.map(Into::into);
        self.client_secret = client_secret;
        self
    }

    /// Set a custom [`TokenCredential`] (e.g. for custom auth).
    pub fn credential(mut self, credential: Arc<dyn TokenCredential>) -> Self {
        self.custom_credential = Some(credential);
        self
    }

    /// Set the in-memory cache TTL for secret values.
    ///
    /// Setting `secrets_cache_ttl` to `Duration::ZERO` disables caching completely.
    pub fn secrets_cache_ttl(mut self, secrets_cache_ttl: Duration) -> Self {
        self.secrets_cache_ttl = secrets_cache_ttl;
        self
    }

    /// Set a custom [`HttpClient`] transport (e.g. for testing over HTTP).
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
            DeveloperToolsCredential::new(None).map_err(|e| {
                StorageError::Backend(eyre!(
                    "failed to create Azure DeveloperToolsCredential: {e}"
                ))
            })?
        };

        let mut options = azure_security_keyvault_secrets::SecretClientOptions {
            verify_challenge_resource: Some(false),
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
        let parameters = SetSecretParameters {
            value: Some(value.to_string()),
            ..Default::default()
        };

        self.client
            .set_secret(
                key,
                parameters.try_into().map_err(|e| {
                    StorageError::Backend(eyre!("failed to serialize Azure secret parameters: {e}"))
                })?,
                None,
            )
            .await
            .map_err(|e| StorageError::Backend(eyre!("failed to set Azure secret '{key}': {e}")))?;

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

        match self.client.get_secret(key, None).await {
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
                        "Azure secret load failed for key '{key}': {err:?}"
                    )))
                }
            }
        }
    }

    async fn update(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.store(key, value).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        match self.client.delete_secret(key, None).await {
            Ok(_) => {
                if let Some(cache) = &self.cache {
                    cache.invalidate(key).await;
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
            .secrets_cache_ttl(Duration::from_secs(600));

        assert_eq!(
            builder.vault_url.as_str(),
            "https://my-vault.vault.azure.net/"
        );
        assert_eq!(builder.tenant_id.as_deref(), Some("tenant-123"));
        assert_eq!(builder.client_id.as_deref(), Some("client-456"));
        assert!(builder.client_secret.is_some());
        assert_eq!(builder.secrets_cache_ttl, Duration::from_secs(600));
    }
}
