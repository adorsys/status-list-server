//! GCP Secret Manager storage adapter implementing [`Storage`].

use std::time::Duration;

use async_trait::async_trait;
use color_eyre::eyre::eyre;
use google_cloud_auth::credentials::service_account;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use google_cloud_secretmanager_v1::model::{
    Replication, Secret, SecretPayload, replication::Automatic, replication::Replication as RepEnum,
};
use moka::future::Cache;
use secrecy::{ExposeSecret, SecretString};
use tracing::info;

use crate::cert_manager::storage::{Storage, StorageError};

/// GCP Secret Manager storage adapter.
///
/// Implements the [`Storage`] trait so it can be used as a secrets backend
/// by the certificate manager.
pub struct GcpSecretManagerClient {
    client: SecretManagerService,
    project_id: String,
    cache: Option<Cache<String, String>>,
}

impl GcpSecretManagerClient {
    const CACHE_MAX_CAPACITY: u64 = 100;

    /// Return a [`GcpSecretManagerClientBuilder`] for constructing an adapter
    /// for the given GCP project ID.
    pub fn builder(project_id: impl Into<String>) -> GcpSecretManagerClientBuilder {
        GcpSecretManagerClientBuilder::new(project_id)
    }

    /// Formats the parent resource name for secret creation (`projects/{project_id}`).
    fn project_parent(&self) -> String {
        format!("projects/{}", self.project_id)
    }

    /// Formats the resource name for a secret (`projects/{project_id}/secrets/{key}`).
    fn secret_name(&self, key: &str) -> String {
        format!("projects/{}/secrets/{}", self.project_id, key)
    }

    /// Formats the resource name for accessing a secret version (`projects/{project_id}/secrets/{key}/versions/{version}`).
    fn secret_version_name(&self, key: &str, version: &str) -> String {
        format!(
            "projects/{}/secrets/{}/versions/{}",
            self.project_id, key, version
        )
    }
}

/// Builder for constructing a [`GcpSecretManagerClient`] adapter.
#[derive(Debug, Clone)]
pub struct GcpSecretManagerClientBuilder {
    project_id: String,
    service_account_key: Option<SecretString>,
    service_account_key_path: Option<String>,
    endpoint: Option<String>,
    secrets_cache_ttl: Duration,
}

impl GcpSecretManagerClientBuilder {
    /// Create a new [`GcpSecretManagerClientBuilder`] with the GCP project ID.
    pub fn new(project_id: impl Into<String>) -> Self {
        Self {
            project_id: project_id.into(),
            service_account_key: None,
            service_account_key_path: None,
            endpoint: None,
            secrets_cache_ttl: Duration::from_secs(300),
        }
    }

    /// Set an inline service account key JSON.
    pub fn service_account_key(mut self, key: Option<SecretString>) -> Self {
        self.service_account_key = key;
        self
    }

    /// Set a path to a service account key JSON file.
    pub fn service_account_key_path(mut self, path: Option<impl Into<String>>) -> Self {
        self.service_account_key_path = path.map(Into::into);
        self
    }

    /// Set a custom endpoint URL (e.g. for emulator testing).
    pub fn endpoint(mut self, endpoint: Option<impl Into<String>>) -> Self {
        self.endpoint = endpoint.map(Into::into);
        self
    }

    /// Set the in-memory cache TTL for secret values.
    ///
    /// Setting `secrets_cache_ttl` to `Duration::ZERO` disables caching completely.
    pub fn secrets_cache_ttl(mut self, secrets_cache_ttl: Duration) -> Self {
        self.secrets_cache_ttl = secrets_cache_ttl;
        self
    }

    /// Build the [`GcpSecretManagerClient`] adapter instance.
    pub async fn build(self) -> Result<GcpSecretManagerClient, StorageError> {
        let mut builder = SecretManagerService::builder();
        if let Some(endpoint) = &self.endpoint {
            builder = builder.with_endpoint(endpoint).with_credentials(
                google_cloud_auth::credentials::anonymous::Builder::new().build(),
            );
        }
        if let Some(key_secret) = &self.service_account_key {
            let key_json: serde_json::Value = serde_json::from_str(key_secret.expose_secret())?;
            let creds = service_account::Builder::new(key_json).build()?;
            builder = builder.with_credentials(creds);
        } else if let Some(key_path) = &self.service_account_key_path {
            let contents = tokio::fs::read_to_string(key_path).await.map_err(|e| {
                StorageError::Backend(eyre!(
                    "failed to read GCP service account key file '{key_path}': {e}"
                ))
            })?;
            let key_json: serde_json::Value = serde_json::from_str(&contents)?;
            let creds = service_account::Builder::new(key_json).build()?;
            builder = builder.with_credentials(creds);
        }

        let client = builder.build().await.map_err(|e| {
            StorageError::Backend(eyre!("failed to create GCP Secret Manager client: {e}"))
        })?;

        let cache = (!self.secrets_cache_ttl.is_zero()).then(|| {
            Cache::builder()
                .max_capacity(GcpSecretManagerClient::CACHE_MAX_CAPACITY)
                .time_to_live(self.secrets_cache_ttl)
                .build()
        });

        if self.secrets_cache_ttl.is_zero() {
            info!("GCP Secret Manager cache disabled (TTL=0)");
        }

        Ok(GcpSecretManagerClient {
            client,
            project_id: self.project_id,
            cache,
        })
    }
}

#[async_trait]
impl Storage for GcpSecretManagerClient {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let secret_name = self.secret_name(key);

        // Check if secret exists
        let resp = self.client.get_secret().set_name(&secret_name).send().await;

        match resp {
            Ok(_) => {}
            Err(e) if e.http_status_code() == Some(404) => {
                // Create secret container with automatic replication
                let secret = Secret::new().set_replication(
                    Replication::new()
                        .set_replication(RepEnum::Automatic(Box::new(Automatic::new()))),
                );

                self.client
                    .create_secret()
                    .set_parent(self.project_parent())
                    .set_secret_id(key)
                    .set_secret(secret)
                    .send()
                    .await?;
            }
            Err(e) => return Err(StorageError::Backend(e.into())),
        };

        // Add secret version with payload
        let payload = SecretPayload::new().set_data(value.as_bytes().to_vec());

        self.client
            .add_secret_version()
            .set_parent(secret_name)
            .set_payload(payload)
            .send()
            .await?;

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

        let version_name = self.secret_version_name(key, "latest");
        match self
            .client
            .access_secret_version()
            .set_name(version_name)
            .send()
            .await
        {
            Ok(resp) => {
                let payload = resp.payload.ok_or_else(|| {
                    StorageError::InvalidData("missing payload in GCP secret response".to_string())
                })?;

                let secret_str = String::from_utf8(payload.data.to_vec())
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;

                if let Some(cache) = &self.cache {
                    cache.insert(key.to_string(), secret_str.clone()).await;
                }
                Ok(Some(secret_str))
            }
            Err(err) => {
                if err.http_status_code() == Some(404) {
                    return Ok(None);
                }
                Err(StorageError::Backend(eyre!(
                    "GCP secret load failed for key '{key}': {err}"
                )))
            }
        }
    }

    async fn update(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let secret_name = self.secret_name(key);

        let payload = SecretPayload::new().set_data(value.as_bytes().to_vec());

        self.client
            .add_secret_version()
            .set_parent(secret_name)
            .set_payload(payload)
            .send()
            .await?;

        if let Some(cache) = &self.cache {
            cache.insert(key.to_string(), value.to_string()).await;
        }

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let secret_name = self.secret_name(key);

        match self
            .client
            .delete_secret()
            .set_name(secret_name)
            .send()
            .await
        {
            Ok(_) => {
                if let Some(cache) = &self.cache {
                    cache.invalidate(key).await;
                }
                Ok(())
            }
            Err(err) if err.http_status_code() == Some(404) => {
                if let Some(cache) = &self.cache {
                    cache.invalidate(key).await;
                }
                Ok(())
            }
            Err(err) => Err(StorageError::Backend(eyre!(
                "GCP secret delete failed for key '{key}': {err}"
            ))),
        }
    }
}

impl From<google_cloud_secretmanager_v1::Error> for StorageError {
    fn from(error: google_cloud_secretmanager_v1::Error) -> Self {
        StorageError::Backend(error.into())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(error: serde_json::Error) -> Self {
        StorageError::Backend(eyre!(
            "failed to parse GCP service account key JSON: {error}"
        ))
    }
}

impl From<google_cloud_auth::build_errors::Error> for StorageError {
    fn from(error: google_cloud_auth::build_errors::Error) -> Self {
        StorageError::Backend(error.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_builder_and_resource_names() {
        let builder = GcpSecretManagerClient::builder("my-gcp-project")
            .secrets_cache_ttl(Duration::from_secs(60))
            .service_account_key(Some(SecretString::from("key")))
            .service_account_key_path(Some("/path/to/key.json"));

        assert_eq!(builder.project_id, "my-gcp-project");
        assert_eq!(builder.secrets_cache_ttl, Duration::from_secs(60));
        assert!(builder.service_account_key.is_some());
        assert_eq!(
            builder.service_account_key_path.as_deref(),
            Some("/path/to/key.json")
        );
    }
}
