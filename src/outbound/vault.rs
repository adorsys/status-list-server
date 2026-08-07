//! Vault / OpenBao KV v2 secrets-storage adapter implementing [`Storage`].
//!
//! Both HashiCorp Vault and OpenBao expose the same KV v2 HTTP API, so this
//! single adapter covers both.  Only **token auth** is supported in this
//! initial implementation;

use std::time::Duration;

use async_trait::async_trait;
use color_eyre::eyre::eyre;
use moka::future::Cache;
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::cert_manager::storage::{Storage, StorageError};

/// Vault / OpenBao KV v2 storage adapter.
///
/// Implements the [`Storage`] trait so it can be used as a secrets backend
/// by the certificate manager.
pub struct VaultClient {
    client: Client,
    /// Vault/OpenBao API address (e.g. `http://vault:8200`).
    addr: String,
    /// Authentication token (never logged).
    token: SecretString,
    /// KV v2 engine mount path (default `secret`).
    mount: String,
    /// Prefix prepended to all secret paths.
    path_prefix: String,
    /// Optional Vault Enterprise / OpenBao namespace.
    namespace: Option<String>,
    /// Optional in-process TTL cache.
    cache: Option<Cache<String, String>>,
}

impl VaultClient {
    const CACHE_MAX_CAPACITY: u64 = 10;

    /// Return a [`VaultClientBuilder`] for constructing a [`VaultClient`] adapter
    /// with the given address and token.
    pub fn builder(addr: impl Into<String>, token: SecretString) -> VaultClientBuilder {
        VaultClientBuilder::new(addr, token)
    }

    /// Build the full URL for KV v2 `data` operations.
    fn data_url(&self, key: &str) -> String {
        let path = self.qualify_key(key);
        format!("{}/v1/{}/data/{}", self.addr, self.mount, path)
    }

    /// Build the full URL for KV v2 `metadata` (used by hard-delete).
    fn metadata_url(&self, key: &str) -> String {
        let path = self.qualify_key(key);
        format!("{}/v1/{}/metadata/{}", self.addr, self.mount, path)
    }

    /// Qualify a key by prepending the configured path prefix.
    fn qualify_key(&self, key: &str) -> String {
        if self.path_prefix.is_empty() {
            key.to_string()
        } else if self.path_prefix.ends_with('/') {
            format!("{}{}", self.path_prefix, key)
        } else {
            format!("{}/{}", self.path_prefix, key)
        }
    }

    /// Add common headers (token + optional namespace) to a request builder.
    fn add_auth_headers(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let builder = builder.header("X-Vault-Token", self.token.expose_secret());
        if let Some(ns) = &self.namespace {
            builder.header("X-Vault-Namespace", ns)
        } else {
            builder
        }
    }
}

/// Builder for constructing a [`VaultClient`] adapter.
///
/// # Optional Fields & Default Behavior
/// - `mount`: KV v2 secret engine mount path. **Default**: `"secret"`
/// - `path_prefix`: Prefix prepended to all secret keys. **Default**: `""` (no prefix)
/// - `namespace`: Optional Vault Enterprise / OpenBao namespace header (`X-Vault-Namespace`). **Default**: `None`
/// - `secrets_cache_ttl`: In-memory TTL cache duration for fetched secrets. Setting to `Duration::ZERO` disables caching. **Default**: 5 minutes
/// - `timeout`: HTTP client request timeout. **Default**: 30 seconds
#[derive(Debug, Clone)]
pub struct VaultClientBuilder {
    addr: String,
    token: SecretString,
    mount: String,
    path_prefix: String,
    namespace: Option<String>,
    secrets_cache_ttl: Duration,
    timeout: Duration,
}

impl VaultClientBuilder {
    /// Create a new [`VaultClientBuilder`] with the Vault address and token.
    pub fn new(addr: impl Into<String>, token: SecretString) -> Self {
        Self {
            addr: addr.into(),
            token,
            mount: "secret".to_string(),
            path_prefix: String::new(),
            namespace: None,
            secrets_cache_ttl: Duration::from_secs(300),
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the KV v2 secret engine mount path.
    ///
    /// **Default**: `"secret"`
    pub fn mount(mut self, mount: impl Into<String>) -> Self {
        self.mount = mount.into();
        self
    }

    /// Set a path prefix prepended to all secret keys.
    ///
    /// **Default**: `""` (empty prefix)
    pub fn path_prefix(mut self, path_prefix: impl Into<String>) -> Self {
        self.path_prefix = path_prefix.into();
        self
    }

    /// Set an optional Vault Enterprise or OpenBao namespace header (`X-Vault-Namespace`).
    ///
    /// **Default**: `None`
    pub fn namespace(mut self, namespace: Option<impl Into<String>>) -> Self {
        self.namespace = namespace.map(Into::into);
        self
    }

    /// Set the in-memory cache TTL for secret values.
    ///
    /// Setting `secrets_cache_ttl` to `Duration::ZERO` (or `0` seconds) disables caching completely.
    ///
    /// **Default**: 5 minutes
    pub fn secrets_cache_ttl(mut self, secrets_cache_ttl: Duration) -> Self {
        self.secrets_cache_ttl = secrets_cache_ttl;
        self
    }

    /// Set the HTTP request timeout duration.
    ///
    /// **Default**: 30 seconds
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the [`VaultClient`] adapter instance.
    pub fn build(self) -> Result<VaultClient, StorageError> {
        let client = Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| StorageError::Backend(e.into()))?;

        let cache = (!self.secrets_cache_ttl.is_zero()).then(|| {
            Cache::builder()
                .max_capacity(VaultClient::CACHE_MAX_CAPACITY)
                .time_to_live(self.secrets_cache_ttl)
                .build()
        });

        if self.secrets_cache_ttl.is_zero() {
            info!("Vault secrets cache disabled (TTL=0)");
        }

        Ok(VaultClient {
            client,
            addr: self.addr.trim_end_matches('/').to_string(),
            token: self.token,
            mount: self.mount,
            path_prefix: self.path_prefix,
            namespace: self.namespace,
            cache,
        })
    }
}

/// Top-level response for KV v2 `GET /data/{path}`.
#[derive(Deserialize)]
struct KvReadResponse {
    data: KvDataEnvelope,
}

/// Inner `data` field of a KV v2 payload.
#[derive(Serialize, Deserialize)]
struct KvDataEnvelope {
    data: KvDataPayload,
}

/// The actual key-value pairs stored in Vault.
/// We store a single field named `value`.
#[derive(Serialize, Deserialize)]
struct KvDataPayload {
    value: String,
}

#[async_trait]
impl Storage for VaultClient {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let url = self.data_url(key);
        let body = KvDataEnvelope {
            data: KvDataPayload {
                value: value.to_string(),
            },
        };

        let resp = self
            .add_auth_headers(self.client.post(&url))
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            // Update cache on successful write
            if let Some(cache) = &self.cache {
                cache.insert(key.to_string(), value.to_string()).await;
            }
            Ok(())
        } else {
            Err(StorageError::Backend(eyre!(
                "vault store failed for path '{}': HTTP {status}",
                self.qualify_key(key)
            )))
        }
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        // Check cache first
        if let Some(cache) = &self.cache
            && let Some(value) = cache.get(key).await
        {
            return Ok(Some(value));
        }

        let url = self.data_url(key);
        let resp = self.add_auth_headers(self.client.get(&url)).send().await?;

        let status = resp.status();
        match status {
            StatusCode::OK => {
                let kv: KvReadResponse = resp.json().await?;
                let secret_value = kv.data.data.value;

                // Populate cache
                if let Some(cache) = &self.cache {
                    cache.insert(key.to_string(), secret_value.clone()).await;
                }
                Ok(Some(secret_value))
            }
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::FORBIDDEN => Err(StorageError::Backend(eyre!(
                "vault access denied for path '{}'",
                self.qualify_key(key)
            ))),
            _ => Err(StorageError::Backend(eyre!(
                "vault load failed for path '{}': HTTP {status}",
                self.qualify_key(key)
            ))),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        // Use metadata endpoint for permanent delete of all versions
        let url = self.metadata_url(key);
        let resp = self
            .add_auth_headers(self.client.delete(&url))
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            if let Some(cache) = &self.cache {
                cache.invalidate(key).await;
            }
            Ok(())
        } else {
            Err(StorageError::Backend(eyre!(
                "vault delete failed for path '{}': HTTP {status}",
                self.qualify_key(key)
            )))
        }
    }
}

impl From<reqwest::Error> for StorageError {
    fn from(value: reqwest::Error) -> Self {
        Self::Backend(value.into())
    }
}
