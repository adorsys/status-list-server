//! Vault / OpenBao KV v2 secrets-storage adapter implementing [`Storage`].
//!
//! Both HashiCorp Vault and OpenBao expose the same KV v2 HTTP API, so this
//! single adapter covers both.  Authentication is performed exclusively via
//! the **AppRole** auth method.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use color_eyre::eyre::eyre;
use moka::future::Cache;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::cert_manager::storage::{Storage, StorageError};

/// Vault / OpenBao KV v2 storage adapter.
///
/// Implements the [`Storage`] trait so it can be used as a secrets backend
/// by the certificate manager.  Authentication is performed via **AppRole**.
#[derive(Debug)]
pub struct VaultClient {
    client: Client,
    /// Vault/OpenBao API address (e.g. `http://vault:8200`).
    addr: String,
    /// KV v2 engine mount path (default `secret`).
    mount: String,
    /// Prefix prepended to all secret paths.
    path_prefix: String,
    /// Optional Vault Enterprise / OpenBao namespace.
    namespace: Option<String>,
    /// Optional in-process TTL cache.
    cache: Option<Cache<String, String>>,
    /// AppRole token manager.
    auth: Arc<TokenManager>,
}

impl VaultClient {
    /// Maximum number of distinct secrets kept in the in-process cache.
    /// 100 entries covers multi-domain deployments (20+ domains with cert +
    /// key per domain) with plenty of headroom, while still bounding memory.
    const CACHE_MAX_CAPACITY: u64 = 100;

    /// Return a [`VaultClientBuilder`] for constructing a [`VaultClient`] adapter
    /// with AppRole authentication.
    pub fn builder(
        addr: impl Into<String>,
        role_id: impl Into<String>,
        secret_id: SecretString,
    ) -> VaultClientBuilder {
        VaultClientBuilder::new(addr, role_id, secret_id)
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

    /// Qualify a key by prepending the configured path prefix, then
    /// percent-encode each path segment so that characters such as `?`, `#`,
    /// or spaces cannot corrupt the HTTP request URL.
    fn qualify_key(&self, key: &str) -> String {
        let raw = if self.path_prefix.is_empty() {
            key.to_string()
        } else if self.path_prefix.ends_with('/') {
            format!("{}{}", self.path_prefix, key)
        } else {
            format!("{}/{}", self.path_prefix, key)
        };
        raw.split('/')
            .map(Self::encode_path_segment)
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Percent-encode a single URL path segment (RFC 3986).
    ///
    /// Unreserved characters (`A-Z a-z 0-9 - _ . ~`) and sub-delimiters
    /// allowed in path segments (`! $ & ' ( ) * + , ; = : @`) are left as-is;
    /// everything else (including `?`, `#`, ` `, `%`) is percent-encoded.
    fn encode_path_segment(segment: &str) -> String {
        let mut out = String::with_capacity(segment.len());
        for b in segment.bytes() {
            if b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_'
                        | b'.'
                        | b'~'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b':'
                        | b'@'
                )
            {
                out.push(b as char);
            } else {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
        out
    }

    /// Ensure the AppRole token is valid, then add common headers to a request.
    async fn add_auth_headers(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, StorageError> {
        self.auth
            .ensure_valid(&self.client, &self.addr, self.namespace.as_deref())
            .await?;

        let token = self.auth.current_token().await;
        let builder = builder.header("X-Vault-Token", token.expose_secret());
        if let Some(ns) = &self.namespace {
            Ok(builder.header("X-Vault-Namespace", ns))
        } else {
            Ok(builder)
        }
    }
}

/// Builder for constructing a [`VaultClient`] adapter with AppRole authentication.
///
/// # Optional Fields & Default Behavior
/// - `mount`: KV v2 secret engine mount path. **Default**: `"secret"`
/// - `path_prefix`: Prefix prepended to all secret keys. **Default**: `""` (no prefix)
/// - `namespace`: Optional Vault Enterprise / OpenBao namespace header (`X-Vault-Namespace`). **Default**: `None`
/// - `auth_mount`: AppRole auth engine mount path. **Default**: `"approle"`
/// - `secrets_cache_ttl`: In-memory TTL cache duration for fetched secrets. Setting to `Duration::ZERO` disables caching. **Default**: 5 minutes
/// - `timeout`: HTTP client request timeout. **Default**: 30 seconds
#[derive(Debug, Clone)]
pub struct VaultClientBuilder {
    addr: String,
    role_id: String,
    secret_id: SecretString,
    mount: String,
    auth_mount: String,
    path_prefix: String,
    namespace: Option<String>,
    secrets_cache_ttl: Duration,
    timeout: Duration,
}

impl VaultClientBuilder {
    /// Create a new [`VaultClientBuilder`] with AppRole credentials.
    pub fn new(
        addr: impl Into<String>,
        role_id: impl Into<String>,
        secret_id: SecretString,
    ) -> Self {
        Self {
            addr: addr.into(),
            role_id: role_id.into(),
            secret_id,
            mount: "secret".to_string(),
            auth_mount: "approle".to_string(),
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

    /// Set the AppRole auth engine mount path.
    ///
    /// **Default**: `"approle"`
    pub fn auth_mount(mut self, auth_mount: impl Into<String>) -> Self {
        self.auth_mount = auth_mount.into();
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
    ///
    /// Performs the initial AppRole login during construction.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Backend` if:
    /// - `addr` is empty or not a valid URL.
    /// - `role_id` is empty.
    /// - `secret_id` is empty.
    /// - `mount` is empty.
    /// - The initial AppRole login fails.
    pub async fn build(self) -> Result<VaultClient, StorageError> {
        // Validate address, must be non-empty and parseable as a URL.
        if self.addr.trim().is_empty() {
            return Err(StorageError::Backend(eyre!(
                "Vault configuration error: address must not be empty"
            )));
        }
        Url::parse(&self.addr).map_err(|e| {
            StorageError::Backend(eyre!("Vault configuration error: invalid address: {e}"))
        })?;

        // Validate role_id, must be non-empty.
        if self.role_id.trim().is_empty() {
            return Err(StorageError::Backend(eyre!(
                "Vault configuration error: role_id must not be empty"
            )));
        }

        // Validate secret_id, must be non-empty.
        if self.secret_id.expose_secret().trim().is_empty() {
            return Err(StorageError::Backend(eyre!(
                "Vault configuration error: secret_id must not be empty"
            )));
        }

        // Mount must be non-empty.
        if self.mount.trim().is_empty() {
            return Err(StorageError::Backend(eyre!(
                "Vault configuration error: mount path must not be empty"
            )));
        }

        // Auth mount must be non-empty.
        if self.auth_mount.trim().is_empty() {
            return Err(StorageError::Backend(eyre!(
                "Vault configuration error: auth_mount must not be empty"
            )));
        }

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

        let addr = self.addr.trim_end_matches('/').to_string();

        // Perform initial AppRole login
        let auth = TokenManager::login(
            &client,
            &addr,
            self.role_id,
            self.secret_id,
            self.auth_mount,
            self.namespace.as_deref(),
        )
        .await?;

        Ok(VaultClient {
            client,
            addr,
            mount: self.mount,
            path_prefix: self.path_prefix,
            namespace: self.namespace,
            cache,
            auth: Arc::new(auth),
        })
    }
}

/// Manages the Vault client token obtained via AppRole login.
///
/// Handles:
/// - Initial login via `POST /v1/auth/{mount}/login`
/// - Proactive renewal at 80% of TTL via `POST /v1/auth/token/renew-self`
/// - Full re-authentication when renewal fails or the token exceeds `max_ttl`
#[derive(Debug)]
struct TokenManager {
    /// Current client token, swapped atomically on renewal/re-login.
    token: RwLock<SecretString>,
    /// When the current token was issued.
    issued_at: RwLock<Instant>,
    /// TTL in seconds from the last login or renewal response.
    lease_duration: RwLock<u64>,
    /// Whether the current token is renewable.
    renewable: RwLock<bool>,
    /// AppRole role ID.
    role_id: String,
    /// AppRole secret ID.
    secret_id: SecretString,
    /// Auth engine mount path (default `approle`).
    auth_mount: String,
}

/// Response from `POST /v1/auth/{mount}/login` and `POST /v1/auth/token/renew-self`
#[derive(Deserialize)]
struct LoginOrRenewResponse {
    auth: AuthData,
}

#[derive(Deserialize)]
struct AuthData {
    client_token: String,
    lease_duration: u64,
    renewable: bool,
}

/// Request body for `POST /v1/auth/{mount}/login`.
#[derive(Serialize)]
struct LoginRequest<'a> {
    role_id: String,
    secret_id: &'a str,
}

impl TokenManager {
    /// Percentage of TTL at which we proactively renew/re-login.
    const RENEW_MARGIN_PCT: u64 = 800;

    /// Perform the initial AppRole login and return a ready manager.
    async fn login(
        client: &Client,
        addr: &str,
        role_id: String,
        secret_id: SecretString,
        auth_mount: String,
        namespace: Option<&str>,
    ) -> Result<Self, StorageError> {
        let (token, lease_duration, renewable) =
            Self::perform_login(client, addr, &role_id, &secret_id, &auth_mount, namespace).await?;

        Ok(Self {
            token: RwLock::new(token),
            issued_at: RwLock::new(Instant::now()),
            lease_duration: RwLock::new(lease_duration),
            renewable: RwLock::new(renewable),
            role_id,
            secret_id,
            auth_mount,
        })
    }

    /// Execute the AppRole login HTTP call.
    async fn perform_login(
        client: &Client,
        addr: &str,
        role_id: &str,
        secret_id: &SecretString,
        auth_mount: &str,
        namespace: Option<&str>,
    ) -> Result<(SecretString, u64, bool), StorageError> {
        let url = format!("{addr}/v1/auth/{auth_mount}/login");
        let body = LoginRequest {
            role_id: role_id.to_string(),
            secret_id: secret_id.expose_secret(),
        };

        let mut builder = client.post(&url).json(&body);
        if let Some(ns) = namespace {
            builder = builder.header("X-Vault-Namespace", ns);
        }

        let resp = builder.send().await?;
        let status = resp.status();

        if status.is_success() {
            let login: LoginOrRenewResponse = resp.json().await?;
            info!(
                lease_duration = login.auth.lease_duration,
                renewable = login.auth.renewable,
                "AppRole login successful"
            );
            Ok((
                SecretString::from(login.auth.client_token),
                login.auth.lease_duration,
                login.auth.renewable,
            ))
        } else if status == StatusCode::FORBIDDEN {
            Err(StorageError::Backend(eyre!(
                "vault AppRole login denied (HTTP 403)"
            )))
        } else {
            let body_text = resp.text().await.unwrap_or_default();
            Err(StorageError::Backend(eyre!(
                "vault AppRole login failed: HTTP {status}: {body_text}"
            )))
        }
    }

    /// Ensure the current token is still valid, renewing or re-authenticating
    /// as needed. This is called before every KV request.
    async fn ensure_valid(
        &self,
        client: &Client,
        addr: &str,
        namespace: Option<&str>,
    ) -> Result<(), StorageError> {
        let elapsed = self.issued_at.read().await.elapsed();
        let ttl = *self.lease_duration.read().await;

        // No renewal needed if we're within the safe window (80% of TTL)
        let safe_window = Duration::from_millis(ttl.saturating_mul(Self::RENEW_MARGIN_PCT));
        if ttl == 0 || elapsed < safe_window {
            return Ok(());
        }

        // Try renewal first if the token is renewable
        if *self.renewable.read().await {
            match self.try_renew(client, addr, namespace).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!("Token renewal failed, re-authenticating: {e}");
                }
            }
        }
        // Full re-login
        self.re_login(client, addr, namespace).await
    }

    /// Attempt to renew the current token via `POST /v1/auth/token/renew-self`.
    async fn try_renew(
        &self,
        client: &Client,
        addr: &str,
        namespace: Option<&str>,
    ) -> Result<(), StorageError> {
        let url = format!("{addr}/v1/auth/token/renew-self");
        let token = self.token.read().await.clone();

        let mut builder = client
            .post(&url)
            .header("X-Vault-Token", token.expose_secret());
        if let Some(ns) = namespace {
            builder = builder.header("X-Vault-Namespace", ns);
        }

        let resp = builder.send().await?;
        let status = resp.status();

        if status.is_success() {
            let renew: LoginOrRenewResponse = resp.json().await?;
            info!(
                lease_duration = renew.auth.lease_duration,
                renewable = renew.auth.renewable,
                "Token renewal successful"
            );
            *self.token.write().await = SecretString::from(renew.auth.client_token);
            *self.issued_at.write().await = Instant::now();
            *self.lease_duration.write().await = renew.auth.lease_duration;
            *self.renewable.write().await = renew.auth.renewable;
            Ok(())
        } else {
            Err(StorageError::Backend(eyre!(
                "token renewal failed: HTTP {status}"
            )))
        }
    }

    /// Perform a full re-login via AppRole.
    async fn re_login(
        &self,
        client: &Client,
        addr: &str,
        namespace: Option<&str>,
    ) -> Result<(), StorageError> {
        let (new_token, lease_duration, renewable) = Self::perform_login(
            client,
            addr,
            &self.role_id,
            &self.secret_id,
            &self.auth_mount,
            namespace,
        )
        .await?;

        *self.token.write().await = new_token;
        *self.issued_at.write().await = Instant::now();
        *self.lease_duration.write().await = lease_duration;
        *self.renewable.write().await = renewable;
        Ok(())
    }

    /// Return the current client token.
    async fn current_token(&self) -> SecretString {
        self.token.read().await.clone()
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
            .await?
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
        } else if status == StatusCode::FORBIDDEN {
            Err(StorageError::Backend(eyre!(
                "vault access denied for path '{}'",
                self.qualify_key(key)
            )))
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
        let resp = self
            .add_auth_headers(self.client.get(&url))
            .await?
            .send()
            .await?;

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
            .await?
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            if let Some(cache) = &self.cache {
                cache.invalidate(key).await;
            }
            Ok(())
        } else if status == StatusCode::FORBIDDEN {
            Err(StorageError::Backend(eyre!(
                "vault access denied for path '{}'",
                self.qualify_key(key)
            )))
        } else {
            Err(StorageError::Backend(eyre!(
                "vault delete failed for path '{}': HTTP {status}",
                self.qualify_key(key)
            )))
        }
    }

    /// Verify the Vault/OpenBao endpoint is reachable and the configured mount
    /// is accessible with the provided credentials.
    async fn reachable(&self) -> Result<(), StorageError> {
        let url = format!("{}/v1/{}/config", self.addr, self.mount);
        let resp = self
            .add_auth_headers(self.client.get(&url))
            .await?
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else if status == StatusCode::FORBIDDEN {
            Err(StorageError::Backend(eyre!(
                "vault access denied for mount '{}'",
                self.mount
            )))
        } else {
            Err(StorageError::Backend(eyre!(
                "vault readiness check failed for mount '{}': HTTP {status}",
                self.mount
            )))
        }
    }
}

impl From<reqwest::Error> for StorageError {
    fn from(value: reqwest::Error) -> Self {
        Self::Backend(value.into())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use secrecy::SecretString;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn valid_role_id() -> String {
        "test-role-id".to_string()
    }

    fn valid_secret_id() -> SecretString {
        SecretString::from("test-secret-id")
    }

    fn auth_response(token: &str, lease_duration: u64) -> serde_json::Value {
        json!({
            "auth": {
                "client_token": token,
                "lease_duration": lease_duration,
                "renewable": true,
                "accessor": "test-accessor",
                "policies": ["default"]
            }
        })
    }

    async fn mock_approle_login(server: &MockServer, token: &str, lease_duration: u64) {
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(auth_response(token, lease_duration)),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn build_validates_required_fields() {
        let cases: Vec<(VaultClientBuilder, &str)> = vec![
            (
                VaultClient::builder("", valid_role_id(), valid_secret_id()),
                "address must not be empty",
            ),
            (
                VaultClient::builder("   ", valid_role_id(), valid_secret_id()),
                "address must not be empty",
            ),
            (
                VaultClient::builder("not a url @@", valid_role_id(), valid_secret_id()),
                "invalid address",
            ),
            (
                VaultClient::builder("http://vault:8200", "", valid_secret_id()),
                "role_id must not be empty",
            ),
            (
                VaultClient::builder("http://vault:8200", valid_role_id(), SecretString::from("")),
                "secret_id must not be empty",
            ),
            (
                VaultClient::builder("http://vault:8200", valid_role_id(), valid_secret_id())
                    .mount(""),
                "mount path must not be empty",
            ),
            (
                VaultClient::builder("http://vault:8200", valid_role_id(), valid_secret_id())
                    .auth_mount(""),
                "auth_mount must not be empty",
            ),
        ];

        for (builder, expected_err) in cases {
            let err = builder.build().await.unwrap_err();
            assert!(
                err.to_string().contains(expected_err),
                "expected error containing '{expected_err}', got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn approle_login_and_kv_round_trip() {
        let server = MockServer::start().await;
        mock_approle_login(&server, "s.test-token", 3600).await;

        Mock::given(method("POST"))
            .and(path("/v1/secret/data/my-key"))
            .and(header("X-Vault-Token", "s.test-token"))
            .and(body_json(json!({ "data": { "value": "secret-payload" } })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "data": { "version": 1 } })),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/my-key"))
            .and(header("X-Vault-Token", "s.test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "data": { "value": "secret-payload" } }
            })))
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path("/v1/secret/metadata/my-key"))
            .and(header("X-Vault-Token", "s.test-token"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client = VaultClient::builder(server.uri(), valid_role_id(), valid_secret_id())
            .secrets_cache_ttl(Duration::ZERO)
            .build()
            .await
            .unwrap();

        client.store("my-key", "secret-payload").await.unwrap();
        let loaded = client.load("my-key").await.unwrap();
        assert_eq!(loaded, Some("secret-payload".to_string()));
        client.delete("my-key").await.unwrap();
    }

    #[tokio::test]
    async fn approle_login_failure_modes() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let err = VaultClient::builder(server.uri(), valid_role_id(), valid_secret_id())
            .build()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("AppRole login denied"));
    }

    #[tokio::test]
    async fn approle_login_custom_mount_and_namespace() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/auth/custom-auth/login"))
            .and(header("X-Vault-Namespace", "tenant-corp"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(auth_response("s.ns-token", 3600)),
            )
            .mount(&server)
            .await;

        let client = VaultClient::builder(server.uri(), valid_role_id(), valid_secret_id())
            .auth_mount("custom-auth")
            .namespace(Some("tenant-corp"))
            .build()
            .await
            .expect("should authenticate with custom auth mount and namespace");

        assert_eq!(
            client.auth.current_token().await.expose_secret(),
            "s.ns-token"
        );
    }

    #[tokio::test]
    async fn reachable_endpoint_status_handling() {
        let server = MockServer::start().await;
        mock_approle_login(&server, "s.test-token", 3600).await;

        Mock::given(method("GET"))
            .and(path("/v1/secret/config"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = VaultClient::builder(server.uri(), valid_role_id(), valid_secret_id())
            .build()
            .await
            .unwrap();

        assert!(client.reachable().await.is_ok());
    }

    #[tokio::test]
    async fn reachable_returns_error_on_failure() {
        let server = MockServer::start().await;
        mock_approle_login(&server, "s.test-token", 3600).await;

        Mock::given(method("GET"))
            .and(path("/v1/secret/config"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let client = VaultClient::builder(server.uri(), valid_role_id(), valid_secret_id())
            .build()
            .await
            .unwrap();

        let err = client.reachable().await.unwrap_err();
        assert!(err.to_string().contains("access denied"));
    }

    #[tokio::test]
    async fn token_renewal_and_reauth_flows() {
        let server = MockServer::start().await;

        // Initial login (short 1s TTL)
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(auth_response("s.token-1", 1)))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Token renewal succeeds
        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "s.token-1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(auth_response("s.token-renewed", 1)),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Subsequent renewal fails with 403, triggering re-login
        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "s.token-renewed"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(auth_response("s.token-relogged", 3600)),
            )
            .mount(&server)
            .await;

        // Data mock accepting requests
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "data": { "value": "val" } }
            })))
            .mount(&server)
            .await;

        let client = VaultClient::builder(server.uri(), valid_role_id(), valid_secret_id())
            .secrets_cache_ttl(Duration::ZERO)
            .build()
            .await
            .unwrap();

        // Near expiry -> renewal triggers
        tokio::time::sleep(Duration::from_millis(850)).await;
        client.load("key").await.unwrap();
        assert_eq!(
            client.auth.current_token().await.expose_secret(),
            "s.token-renewed"
        );

        // Renewal failure -> re-login triggers
        tokio::time::sleep(Duration::from_millis(850)).await;
        client.load("key").await.unwrap();
        assert_eq!(
            client.auth.current_token().await.expose_secret(),
            "s.token-relogged"
        );
    }
}
