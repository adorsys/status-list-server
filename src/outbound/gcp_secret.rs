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

use crate::cert_manager::storage::{Storage, StorageError, normalize_key};

pub struct GcpSecretManagerClient {
    client: SecretManagerService,
    project_id: String,
    cache: Option<Cache<String, String>>,
}

impl std::fmt::Debug for GcpSecretManagerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpSecretManagerClient")
            .field("project_id", &self.project_id)
            .field("cache", &self.cache.is_some())
            .finish()
    }
}

impl GcpSecretManagerClient {
    const CACHE_MAX_CAPACITY: u64 = 100;

    pub fn builder(project_id: impl Into<String>) -> GcpSecretManagerClientBuilder {
        GcpSecretManagerClientBuilder::new(project_id)
    }

    pub(crate) fn qualify_key(key: &str) -> String {
        normalize_key(key)
    }

    fn project_parent(&self) -> String {
        format!("projects/{}", self.project_id)
    }

    fn secret_name(&self, key: &str) -> String {
        format!(
            "projects/{}/secrets/{}",
            self.project_id,
            Self::qualify_key(key)
        )
    }

    fn secret_version_name(&self, key: &str, version: &str) -> String {
        format!(
            "projects/{}/secrets/{}/versions/{}",
            self.project_id,
            Self::qualify_key(key),
            version
        )
    }

    fn is_not_found(err: &google_cloud_secretmanager_v1::Error) -> bool {
        if err.http_status_code() == Some(404) {
            return true;
        }
        if let Some(status) = err.status()
            && (status.code == 5.into() || status.code.name() == "NOT_FOUND")
        {
            return true;
        }
        false
    }

    fn is_already_exists(err: &google_cloud_secretmanager_v1::Error) -> bool {
        if err.http_status_code() == Some(409) {
            return true;
        }
        if let Some(status) = err.status()
            && (status.code == 6.into() || status.code.name() == "ALREADY_EXISTS")
        {
            return true;
        }
        false
    }

    async fn ensure_secret_and_add_version(
        &self,
        key: &str,
        value: &str,
    ) -> Result<(), StorageError> {
        let secret_id = Self::qualify_key(key);
        let secret_name = self.secret_name(key);
        let payload = SecretPayload::new().set_data(value.as_bytes().to_vec());

        match self
            .client
            .add_secret_version()
            .set_parent(&secret_name)
            .set_payload(payload.clone())
            .send()
            .await
        {
            Ok(_) => {
                if let Some(cache) = &self.cache {
                    cache.insert(key.to_string(), value.to_string()).await;
                }
                Ok(())
            }
            Err(e) if Self::is_not_found(&e) => {
                let secret = Secret::new().set_replication(
                    Replication::new()
                        .set_replication(RepEnum::Automatic(Box::new(Automatic::new()))),
                );

                match self
                    .client
                    .create_secret()
                    .set_parent(self.project_parent())
                    .set_secret_id(secret_id)
                    .set_secret(secret)
                    .send()
                    .await
                {
                    Ok(_) => {}
                    // Another replica may have created it first.
                    Err(err) if Self::is_already_exists(&err) => {}
                    Err(err) => return Err(StorageError::Backend(err.into())),
                }

                self.client
                    .add_secret_version()
                    .set_parent(secret_name)
                    .set_payload(payload)
                    .send()
                    .await
                    .map_err(|err| StorageError::Backend(err.into()))?;

                if let Some(cache) = &self.cache {
                    cache.insert(key.to_string(), value.to_string()).await;
                }
                Ok(())
            }
            Err(e) => Err(StorageError::Backend(e.into())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GcpSecretManagerClientBuilder {
    project_id: String,
    service_account_key: Option<SecretString>,
    service_account_key_path: Option<String>,
    endpoint: Option<String>,
    allow_anonymous_credentials: bool,
    secrets_cache_ttl: Duration,
}

impl GcpSecretManagerClientBuilder {
    pub fn new(project_id: impl Into<String>) -> Self {
        Self {
            project_id: project_id.into(),
            service_account_key: None,
            service_account_key_path: None,
            endpoint: None,
            allow_anonymous_credentials: false,
            secrets_cache_ttl: Duration::from_secs(300),
        }
    }

    pub fn service_account_key(mut self, key: Option<SecretString>) -> Self {
        self.service_account_key = key;
        self
    }

    pub fn service_account_key_path(mut self, path: Option<impl Into<String>>) -> Self {
        self.service_account_key_path = path.map(Into::into);
        self
    }

    pub fn endpoint(mut self, endpoint: Option<impl Into<String>>) -> Self {
        self.endpoint = endpoint.map(Into::into);
        self
    }

    pub fn allow_anonymous_credentials(mut self, allow: bool) -> Self {
        self.allow_anonymous_credentials = allow;
        self
    }

    /// `Duration::ZERO` disables caching.
    pub fn secrets_cache_ttl(mut self, secrets_cache_ttl: Duration) -> Self {
        self.secrets_cache_ttl = secrets_cache_ttl;
        self
    }

    pub async fn build(self) -> Result<GcpSecretManagerClient, StorageError> {
        if self.project_id.trim().is_empty() {
            return Err(StorageError::Backend(eyre!(
                "GCP Secret Manager configuration error: project_id must not be empty"
            )));
        }

        let mut builder = SecretManagerService::builder();
        if let Some(endpoint) = &self.endpoint {
            builder = builder.with_endpoint(endpoint);
        }
        if self.allow_anonymous_credentials {
            builder = builder.with_credentials(
                google_cloud_auth::credentials::anonymous::Builder::new().build(),
            );
        } else if let Some(key_secret) = &self.service_account_key {
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
        self.ensure_secret_and_add_version(key, value).await
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
                if Self::is_not_found(&err) {
                    return Ok(None);
                }
                Err(StorageError::Backend(eyre!(
                    "GCP secret load failed for key '{key}': {err}"
                )))
            }
        }
    }

    async fn update(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.ensure_secret_and_add_version(key, value).await
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
            Err(err) if Self::is_not_found(&err) => {
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

    /// Probes a secret name that shouldn't exist, so no real secret is touched.
    async fn reachable(&self) -> Result<(), StorageError> {
        let secret_name = self.secret_name("health-probe-do-not-create");

        match self.client.get_secret().set_name(secret_name).send().await {
            Ok(_) => Ok(()),
            Err(err) if Self::is_not_found(&err) => Ok(()),
            Err(err) => Err(StorageError::Backend(eyre!(
                "GCP Secret Manager readiness check failed: {err}"
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

    #[tokio::test]
    async fn test_builder_rejects_empty_project_id() {
        let err = GcpSecretManagerClient::builder("")
            .build()
            .await
            .unwrap_err();
        match err {
            StorageError::Backend(e) => {
                assert!(e.to_string().contains("project_id must not be empty"));
            }
            other => panic!("expected StorageError::Backend, got {other:?}"),
        }

        let err_ws = GcpSecretManagerClient::builder("   ")
            .build()
            .await
            .unwrap_err();
        match err_ws {
            StorageError::Backend(e) => {
                assert!(e.to_string().contains("project_id must not be empty"));
            }
            other => panic!("expected StorageError::Backend, got {other:?}"),
        }
    }

    #[test]
    fn test_qualify_key() {
        assert_eq!(
            GcpSecretManagerClient::qualify_key("keys-status.example.com"),
            "keys-status-example-com"
        );
        assert_eq!(
            GcpSecretManagerClient::qualify_key("acme_accounts-example.com"),
            "acme-accounts-example-com"
        );
        assert_eq!(
            GcpSecretManagerClient::qualify_key("certs-status.example.com-cert_data.json"),
            "certs-status-example-com-cert-data-json"
        );
        assert_eq!(
            GcpSecretManagerClient::qualify_key("valid_key-123"),
            "valid-key-123"
        );
    }
}
