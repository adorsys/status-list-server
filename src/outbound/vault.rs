//! Vault / OpenBao KV v2 secrets-storage adapter implementing [`Storage`].
//!
//! Both HashiCorp Vault and OpenBao expose the same KV v2 HTTP API, so this
//! single adapter covers both. Authentication is supported via **AppRole**
//! or **Kubernetes** auth methods.

use std::path::PathBuf;
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

use crate::cert_manager::storage::{Storage, StorageError, normalize_key};

/// Vault / OpenBao KV v2 storage adapter.
///
/// Implements the [`Storage`] trait so it can be used as a secrets backend
/// by the certificate manager. Authentication is supported via **AppRole**
/// and **Kubernetes** auth methods.
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
    /// Token manager handling authentication and proactive renewal.
    auth: Arc<TokenManager>,
}

impl VaultClient {
    /// Maximum number of distinct secrets kept in the in-process cache.
    /// 100 entries covers multi-domain deployments (20+ domains with cert +
    /// key per domain) with plenty of headroom, while still bounding memory.
    const CACHE_MAX_CAPACITY: u64 = 100;

    /// Return a [`VaultClientBuilder`] for constructing a [`VaultClient`] adapter
    /// with AppRole authentication.
    pub fn builder_approle(
        addr: impl Into<String>,
        role_id: impl Into<String>,
        secret_id: SecretString,
    ) -> VaultClientBuilder {
        VaultClientBuilder::approle(addr, role_id, secret_id)
    }

    /// Return a [`VaultClientBuilder`] for constructing a [`VaultClient`] adapter
    /// with Kubernetes authentication.
    pub fn builder_kubernetes(
        addr: impl Into<String>,
        role: impl Into<String>,
        token_path: impl Into<PathBuf>,
    ) -> VaultClientBuilder {
        VaultClientBuilder::kubernetes(addr, role, token_path)
    }

    /// Build the full URL for KV v2 `data` operations.
    fn data_url(&self, key: &str) -> String {
        let path = self.qualify_key(key);
        let encoded_mount = Self::encode_path_segment(&self.mount);
        format!("{}/v1/{}/data/{}", self.addr, encoded_mount, path)
    }

    /// Build the full URL for KV v2 `metadata` (used by hard-delete).
    fn metadata_url(&self, key: &str) -> String {
        let path = self.qualify_key(key);
        let encoded_mount = Self::encode_path_segment(&self.mount);
        format!("{}/v1/{}/metadata/{}", self.addr, encoded_mount, path)
    }

    /// Qualify a key by prepending the configured path prefix, then
    /// percent-encode each path segment so that characters such as `?`, `#`,
    /// or spaces cannot corrupt the HTTP request URL.
    fn qualify_key(&self, key: &str) -> String {
        let normalized = normalize_key(key);
        let raw = if self.path_prefix.is_empty() {
            normalized
        } else if self.path_prefix.ends_with('/') {
            format!("{}{}", self.path_prefix, normalized)
        } else {
            format!("{}/{}", self.path_prefix, normalized)
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
    pub(crate) fn encode_path_segment(segment: &str) -> String {
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

    /// Ensure the Vault token is valid, then add common headers to a request.
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

/// Authentication configuration for [`VaultClientBuilder`].
#[derive(Debug, Clone)]
enum AuthConfig {
    AppRole {
        role_id: String,
        secret_id: SecretString,
    },
    Kubernetes {
        role: String,
        token_path: PathBuf,
    },
}

/// Builder for constructing a [`VaultClient`] adapter with AppRole or Kubernetes authentication.
///
/// # Optional Fields & Default Behavior
/// - `mount`: KV v2 secret engine mount path. **Default**: `"secret"`
/// - `path_prefix`: Prefix prepended to all secret keys. **Default**: `""` (no prefix)
/// - `namespace`: Optional Vault Enterprise / OpenBao namespace header (`X-Vault-Namespace`). **Default**: `None`
/// - `auth_mount`: Auth engine mount path. **Default**: `"approle"` for AppRole, `"kubernetes"` for Kubernetes
/// - `secrets_cache_ttl`: In-memory TTL cache duration for fetched secrets. Setting to `Duration::ZERO` disables caching. **Default**: 5 minutes
/// - `timeout`: HTTP client request timeout. **Default**: 30 seconds
#[derive(Debug, Clone)]
pub struct VaultClientBuilder {
    addr: String,
    auth: AuthConfig,
    auth_mount: Option<String>,
    mount: String,
    path_prefix: String,
    namespace: Option<String>,
    secrets_cache_ttl: Duration,
    timeout: Duration,
}

impl VaultClientBuilder {
    /// Create a new [`VaultClientBuilder`] configured for AppRole authentication.
    pub fn approle(
        addr: impl Into<String>,
        role_id: impl Into<String>,
        secret_id: SecretString,
    ) -> Self {
        Self {
            addr: addr.into(),
            auth: AuthConfig::AppRole {
                role_id: role_id.into(),
                secret_id,
            },
            auth_mount: None,
            mount: "secret".to_string(),
            path_prefix: String::new(),
            namespace: None,
            secrets_cache_ttl: Duration::from_secs(300),
            timeout: Duration::from_secs(30),
        }
    }

    /// Create a new [`VaultClientBuilder`] configured for Kubernetes authentication.
    pub fn kubernetes(
        addr: impl Into<String>,
        role: impl Into<String>,
        token_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            addr: addr.into(),
            auth: AuthConfig::Kubernetes {
                role: role.into(),
                token_path: token_path.into(),
            },
            auth_mount: None,
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

    /// Set the auth engine mount path.
    ///
    /// **Default**: `"approle"` for AppRole auth, `"kubernetes"` for Kubernetes auth.
    pub fn auth_mount(mut self, auth_mount: impl Into<String>) -> Self {
        self.auth_mount = Some(auth_mount.into());
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
    /// Performs the initial login (AppRole or Kubernetes) during construction.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Backend` if:
    /// - `addr` is empty or not a valid URL.
    /// - `mount` is empty.
    /// - `auth_mount` is empty.
    /// - AppRole credentials (`role_id` or `secret_id`) are empty.
    /// - Kubernetes credentials (`role` must not be empty; `token_path` is read and validated during initial login).
    /// - The initial login fails.
    pub async fn build(self) -> Result<VaultClient, StorageError> {
        let addr = self.addr.trim().trim_end_matches('/').to_string();
        let mount = self.mount.trim().to_string();
        let path_prefix = self.path_prefix.trim().to_string();

        // Validate address, must be non-empty and parseable as a URL.
        if addr.is_empty() {
            return Err(StorageError::Backend(eyre!(
                "Vault configuration error: address must not be empty"
            )));
        }
        Url::parse(&addr).map_err(|e| {
            StorageError::Backend(eyre!("Vault configuration error: invalid address: {e}"))
        })?;

        // Mount must be non-empty.
        if mount.is_empty() {
            return Err(StorageError::Backend(eyre!(
                "Vault configuration error: mount path must not be empty"
            )));
        }

        let auth_mount = match self.auth_mount {
            Some(ref m) => m.trim().to_string(),
            None => match self.auth {
                AuthConfig::AppRole { .. } => "approle".to_string(),
                AuthConfig::Kubernetes { .. } => "kubernetes".to_string(),
            },
        };

        // Auth mount must be non-empty.
        if auth_mount.is_empty() {
            return Err(StorageError::Backend(eyre!(
                "Vault configuration error: auth_mount must not be empty"
            )));
        }

        let backend = match self.auth {
            AuthConfig::AppRole { role_id, secret_id } => {
                let role_id = role_id.trim().to_string();
                if role_id.is_empty() {
                    return Err(StorageError::Backend(eyre!(
                        "Vault configuration error: role_id must not be empty"
                    )));
                }
                if secret_id.expose_secret().trim().is_empty() {
                    return Err(StorageError::Backend(eyre!(
                        "Vault configuration error: secret_id must not be empty"
                    )));
                }
                AuthBackend::AppRole {
                    role_id,
                    secret_id,
                    auth_mount,
                }
            }
            AuthConfig::Kubernetes { role, token_path } => {
                let role = role.trim().to_string();
                if role.is_empty() {
                    return Err(StorageError::Backend(eyre!(
                        "Vault configuration error: role must not be empty"
                    )));
                }
                AuthBackend::Kubernetes {
                    role,
                    token_path,
                    auth_mount,
                }
            }
        };

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

        let auth = TokenManager::login(&client, &addr, backend, self.namespace.as_deref()).await?;

        Ok(VaultClient {
            client,
            addr,
            mount,
            path_prefix,
            namespace: self.namespace,
            cache,
            auth: Arc::new(auth),
        })
    }
}

/// Helper functions for OpenTelemetry Vault auth metrics.
fn record_vault_login(method: &'static str) {
    opentelemetry::global::meter("status-list-server")
        .u64_counter("vault_auth_logins_total")
        .with_description("Total number of successful Vault logins.")
        .build()
        .add(1, &[opentelemetry::KeyValue::new("method", method)]);
}

fn record_vault_renewal(method: &'static str) {
    opentelemetry::global::meter("status-list-server")
        .u64_counter("vault_auth_renewals_total")
        .with_description("Total number of successful Vault token renewals.")
        .build()
        .add(1, &[opentelemetry::KeyValue::new("method", method)]);
}

fn record_vault_reauth(method: &'static str) {
    opentelemetry::global::meter("status-list-server")
        .u64_counter("vault_auth_reauth_total")
        .with_description(
            "Total number of Vault re-authentications after token expiration or renewal failure.",
        )
        .build()
        .add(1, &[opentelemetry::KeyValue::new("method", method)]);
}

fn record_vault_auth_failure(operation: &'static str, result: &'static str, method: &'static str) {
    opentelemetry::global::meter("status-list-server")
        .u64_counter("vault_auth_failures_total")
        .with_description("Total number of Vault authentication and renewal failures.")
        .build()
        .add(
            1,
            &[
                opentelemetry::KeyValue::new("operation", operation),
                opentelemetry::KeyValue::new("result", result),
                opentelemetry::KeyValue::new("method", method),
            ],
        );
}

/// Authentication backend configuration for Vault.
#[derive(Debug)]
enum AuthBackend {
    AppRole {
        role_id: String,
        secret_id: SecretString,
        auth_mount: String,
    },
    Kubernetes {
        role: String,
        token_path: PathBuf,
        auth_mount: String,
    },
}

impl AuthBackend {
    fn method_name(&self) -> &'static str {
        match self {
            Self::AppRole { .. } => "approle",
            Self::Kubernetes { .. } => "kubernetes",
        }
    }

    async fn login(
        &self,
        client: &Client,
        addr: &str,
        namespace: Option<&str>,
    ) -> Result<(SecretString, u64, bool), StorageError> {
        let method = self.method_name();
        let auth_mount = match self {
            Self::AppRole { auth_mount, .. } | Self::Kubernetes { auth_mount, .. } => auth_mount,
        };
        let encoded_auth_mount = VaultClient::encode_path_segment(auth_mount);
        let url = format!("{addr}/v1/auth/{encoded_auth_mount}/login");

        let body: serde_json::Value = match self {
            Self::AppRole {
                role_id, secret_id, ..
            } => serde_json::json!({
                "role_id": role_id,
                "secret_id": secret_id.expose_secret(),
            }),
            Self::Kubernetes {
                role, token_path, ..
            } => {
                let token_content = tokio::fs::read_to_string(token_path).await.map_err(|e| {
                    record_vault_auth_failure("login", "token_read_error", method);
                    StorageError::Backend(eyre!(
                        "failed to read Kubernetes service account token from {token_path:?}: {e}"
                    ))
                })?;
                let trimmed = token_content.trim();
                if trimmed.is_empty() {
                    record_vault_auth_failure("login", "token_empty_error", method);
                    return Err(StorageError::Backend(eyre!(
                        "Kubernetes service account token in {token_path:?} is empty"
                    )));
                }
                serde_json::json!({ "role": role, "jwt": trimmed })
            }
        };

        Self::perform_login(client, &url, &body, namespace, method).await
    }

    /// Send the login POST and handle the response.
    ///
    /// Shared by both AppRole and Kubernetes auth methods; the caller builds
    /// the method-specific URL and body, then delegates here for the common
    /// HTTP round-trip, deserialization, and metrics recording.
    async fn perform_login(
        client: &Client,
        url: &str,
        body: &serde_json::Value,
        namespace: Option<&str>,
        method: &'static str,
    ) -> Result<(SecretString, u64, bool), StorageError> {
        let mut builder = client.post(url).json(body);
        if let Some(ns) = namespace {
            builder = builder.header("X-Vault-Namespace", ns);
        }

        let resp = match builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                record_vault_auth_failure("login", "network_error", method);
                return Err(StorageError::Backend(e.into()));
            }
        };

        let status = resp.status();

        if status.is_success() {
            let login: LoginOrRenewResponse = match resp.json().await {
                Ok(data) => data,
                Err(e) => {
                    record_vault_auth_failure("login", "deserialization_error", method);
                    return Err(StorageError::Backend(e.into()));
                }
            };
            info!(
                lease_duration = login.auth.lease_duration,
                renewable = login.auth.renewable,
                auth_method = method,
                "{method} login successful"
            );
            record_vault_login(method);
            Ok((
                SecretString::from(login.auth.client_token),
                login.auth.lease_duration,
                login.auth.renewable,
            ))
        } else if status == StatusCode::FORBIDDEN {
            record_vault_auth_failure("login", "forbidden", method);
            let label = match method {
                "approle" => "AppRole",
                "kubernetes" => "Kubernetes",
                other => other,
            };
            Err(StorageError::Backend(eyre!(
                "vault {label} login denied (HTTP 403)"
            )))
        } else {
            let body_text = resp.text().await.unwrap_or_default();
            record_vault_auth_failure("login", "http_error", method);
            let label = match method {
                "approle" => "AppRole",
                "kubernetes" => "Kubernetes",
                other => other,
            };
            Err(StorageError::Backend(eyre!(
                "vault {label} login failed: HTTP {status}: {body_text}"
            )))
        }
    }
}

/// Manages the Vault client token obtained via AppRole or Kubernetes login.
///
/// Handles:
/// - Initial login via `POST /v1/auth/{mount}/login`
/// - Proactive renewal at 80% of TTL via `POST /v1/auth/token/renew-self`
/// - Full re-authentication when renewal fails or the token exceeds `max_ttl`
/// - Double-checked locking to serialize token renewals and prevent concurrency stampedes
/// - Failure cooldown backoff to protect degraded/unreachable Vault instances
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
    /// Underlying authentication backend.
    backend: AuthBackend,
    /// Mutex serializing proactive renewal and re-login across concurrent requests.
    renewal_lock: tokio::sync::Mutex<()>,
    /// Timestamp of last auth/renewal failure for backoff cooldown.
    last_failure: RwLock<Option<Instant>>,
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

impl TokenManager {
    /// Fraction of TTL elapsed before proactive renewal/re-login (80%).
    const RENEW_MARGIN: f64 = 0.8;

    /// Cooldown window after an auth failure before retrying.
    const FAILURE_COOLDOWN: Duration = Duration::from_secs(5);

    /// Perform the initial login and return a ready manager.
    async fn login(
        client: &Client,
        addr: &str,
        backend: AuthBackend,
        namespace: Option<&str>,
    ) -> Result<Self, StorageError> {
        let (token, lease_duration, renewable) = backend.login(client, addr, namespace).await?;

        Ok(Self {
            token: RwLock::new(token),
            issued_at: RwLock::new(Instant::now()),
            lease_duration: RwLock::new(lease_duration),
            renewable: RwLock::new(renewable),
            backend,
            renewal_lock: tokio::sync::Mutex::new(()),
            last_failure: RwLock::new(None),
        })
    }

    /// Ensure the current token is still valid, renewing or re-authenticating
    /// as needed. Uses double-checked locking to serialize token renewal and prevent
    /// thundering-herd stampedes under high concurrency.
    async fn ensure_valid(
        &self,
        client: &Client,
        addr: &str,
        namespace: Option<&str>,
    ) -> Result<(), StorageError> {
        // Fast path: check under read lock if current token is still within safe window
        {
            let elapsed = self.issued_at.read().await.elapsed();
            let ttl = *self.lease_duration.read().await;
            let safe_window = Duration::from_secs_f64(ttl as f64 * Self::RENEW_MARGIN);
            if ttl == 0 || elapsed < safe_window {
                return Ok(());
            }
        }

        // Acquire serialization lock to prevent concurrent renew/login stampedes
        let _guard = self.renewal_lock.lock().await;

        // Re-check after acquiring lock in case another task already renewed/re-logged-in
        let elapsed = self.issued_at.read().await.elapsed();
        let ttl = *self.lease_duration.read().await;
        let safe_window = Duration::from_secs_f64(ttl as f64 * Self::RENEW_MARGIN);
        if ttl == 0 || elapsed < safe_window {
            return Ok(());
        }

        // Check failure cooldown backoff to protect degraded/unreachable Vault
        if let Some(last_fail) = *self.last_failure.read().await
            && last_fail.elapsed() < Self::FAILURE_COOLDOWN
        {
            return Err(StorageError::Backend(eyre!(
                "vault authentication in cooldown backoff after recent failure"
            )));
        }

        // Try renewal first if the token is renewable
        if *self.renewable.read().await {
            match self.try_renew(client, addr, namespace).await {
                Ok(()) => {
                    *self.last_failure.write().await = None;
                    return Ok(());
                }
                Err(e) => {
                    warn!("Token renewal failed, re-authenticating: {e}");
                }
            }
        }

        // Full re-login
        match self.re_login(client, addr, namespace).await {
            Ok(()) => {
                *self.last_failure.write().await = None;
                Ok(())
            }
            Err(e) => {
                *self.last_failure.write().await = Some(Instant::now());
                Err(e)
            }
        }
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

        let resp = match builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                record_vault_auth_failure("renewal", "network_error", self.backend.method_name());
                return Err(StorageError::Backend(e.into()));
            }
        };

        let status = resp.status();

        if status.is_success() {
            let renew: LoginOrRenewResponse = match resp.json().await {
                Ok(data) => data,
                Err(e) => {
                    record_vault_auth_failure(
                        "renewal",
                        "deserialization_error",
                        self.backend.method_name(),
                    );
                    return Err(StorageError::Backend(e.into()));
                }
            };
            info!(
                lease_duration = renew.auth.lease_duration,
                renewable = renew.auth.renewable,
                "Token renewal successful"
            );
            record_vault_renewal(self.backend.method_name());
            *self.token.write().await = SecretString::from(renew.auth.client_token);
            *self.issued_at.write().await = Instant::now();
            *self.lease_duration.write().await = renew.auth.lease_duration;
            *self.renewable.write().await = renew.auth.renewable;
            Ok(())
        } else {
            let body_text = resp.text().await.unwrap_or_default();
            record_vault_auth_failure("renewal", "http_error", self.backend.method_name());
            Err(StorageError::Backend(eyre!(
                "token renewal failed: HTTP {status}: {body_text}"
            )))
        }
    }

    /// Perform a full re-login.
    async fn re_login(
        &self,
        client: &Client,
        addr: &str,
        namespace: Option<&str>,
    ) -> Result<(), StorageError> {
        let (new_token, lease_duration, renewable) =
            match self.backend.login(client, addr, namespace).await {
                Ok(res) => res,
                Err(e) => {
                    record_vault_auth_failure("reauth", "login_error", self.backend.method_name());
                    return Err(e);
                }
            };

        record_vault_reauth(self.backend.method_name());
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
        let encoded_mount = Self::encode_path_segment(&self.mount);
        let url = format!("{}/v1/{}/config", self.addr, encoded_mount);
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

    /// Write a temp file with a unique name and return its path.
    fn write_temp_token(suffix: &str, content: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("k8s_token_{suffix}_{}.txt", uuid::Uuid::new_v4()));
        std::fs::write(&p, content).expect("write temp token");
        p
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

    async fn mock_k8s_login(server: &MockServer, jwt: &str, role: &str, token: &str, lease: u64) {
        Mock::given(method("POST"))
            .and(path("/v1/auth/kubernetes/login"))
            .and(body_json(json!({ "role": role, "jwt": jwt })))
            .respond_with(ResponseTemplate::new(200).set_body_json(auth_response(token, lease)))
            .mount(server)
            .await;
    }

    /// Mount KV v2 store/load/delete mocks for a given key.
    async fn mock_kv_round_trip(server: &MockServer, key: &str, value: &str, token: &str) {
        Mock::given(method("POST"))
            .and(path(format!("/v1/secret/data/{key}")))
            .and(header("X-Vault-Token", token))
            .and(body_json(json!({ "data": { "value": value } })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "data": { "version": 1 } })),
            )
            .mount(server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{key}")))
            .and(header("X-Vault-Token", token))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "data": { "value": value } }
            })))
            .mount(server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(format!("/v1/secret/metadata/{key}")))
            .and(header("X-Vault-Token", token))
            .respond_with(ResponseTemplate::new(204))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn build_validates_required_fields() {
        let token_path = write_temp_token("valid", "jwt-content");
        let empty_path = write_temp_token("empty", "   \n");
        let missing_path = std::env::temp_dir().join("k8s_nonexistent.txt");

        let cases: Vec<(VaultClientBuilder, &str)> = vec![
            (
                VaultClient::builder_approle("", valid_role_id(), valid_secret_id()),
                "address must not be empty",
            ),
            (
                VaultClient::builder_approle("   ", valid_role_id(), valid_secret_id()),
                "address must not be empty",
            ),
            (
                VaultClient::builder_approle("not a url @@", valid_role_id(), valid_secret_id()),
                "invalid address",
            ),
            (
                VaultClient::builder_approle(
                    "http://vault:8200",
                    valid_role_id(),
                    valid_secret_id(),
                )
                .mount(""),
                "mount path must not be empty",
            ),
            (
                VaultClient::builder_approle(
                    "http://vault:8200",
                    valid_role_id(),
                    valid_secret_id(),
                )
                .auth_mount(""),
                "auth_mount must not be empty",
            ),
            (
                VaultClient::builder_approle("http://vault:8200", "", valid_secret_id()),
                "role_id must not be empty",
            ),
            (
                VaultClient::builder_approle(
                    "http://vault:8200",
                    valid_role_id(),
                    SecretString::from(""),
                ),
                "secret_id must not be empty",
            ),
            (
                VaultClient::builder_kubernetes("http://vault:8200", "", &token_path),
                "role must not be empty",
            ),
            (
                VaultClient::builder_kubernetes("http://vault:8200", "r", &missing_path),
                "failed to read Kubernetes service account token",
            ),
            (
                VaultClient::builder_kubernetes("http://vault:8200", "r", &empty_path),
                "Kubernetes service account token in",
            ),
        ];

        for (builder, expected_err) in cases {
            let err = builder.build().await.unwrap_err();
            assert!(
                err.to_string().contains(expected_err),
                "expected error containing '{expected_err}', got: {err}"
            );
        }

        let _ = std::fs::remove_file(&token_path);
        let _ = std::fs::remove_file(&empty_path);
    }

    #[tokio::test]
    async fn approle_login_and_kv_round_trip() {
        let server = MockServer::start().await;
        mock_approle_login(&server, "s.test-token", 3600).await;
        mock_kv_round_trip(&server, "my-key", "secret-payload", "s.test-token").await;

        let client = VaultClient::builder_approle(server.uri(), valid_role_id(), valid_secret_id())
            .secrets_cache_ttl(Duration::ZERO)
            .build()
            .await
            .unwrap();

        client.store("my-key", "secret-payload").await.unwrap();
        assert_eq!(
            client.load("my-key").await.unwrap(),
            Some("secret-payload".to_string())
        );
        client.delete("my-key").await.unwrap();
    }

    #[tokio::test]
    async fn kubernetes_login_and_kv_round_trip() {
        let token_path = write_temp_token("roundtrip", "  my-k8s-jwt \n");
        let server = MockServer::start().await;
        mock_k8s_login(&server, "my-k8s-jwt", "my-role", "s.k8s-token", 3600).await;
        mock_kv_round_trip(&server, "k8s-key", "k8s-payload", "s.k8s-token").await;

        let client = VaultClient::builder_kubernetes(server.uri(), "my-role", &token_path)
            .secrets_cache_ttl(Duration::ZERO)
            .build()
            .await
            .unwrap();

        client.store("k8s-key", "k8s-payload").await.unwrap();
        assert_eq!(
            client.load("k8s-key").await.unwrap(),
            Some("k8s-payload".to_string())
        );
        client.delete("k8s-key").await.unwrap();
        let _ = std::fs::remove_file(&token_path);
    }

    #[tokio::test]
    async fn login_failure_returns_denied_error() {
        // AppRole
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let err = VaultClient::builder_approle(server.uri(), valid_role_id(), valid_secret_id())
            .build()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("AppRole login denied"));

        // Kubernetes
        let token_path = write_temp_token("fail", "jwt");
        let k8s_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/kubernetes/login"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&k8s_server)
            .await;
        let err = VaultClient::builder_kubernetes(k8s_server.uri(), "role", &token_path)
            .build()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Kubernetes login denied"));
        let _ = std::fs::remove_file(&token_path);
    }

    #[tokio::test]
    async fn login_custom_mount_and_namespace() {
        // AppRole
        let ar_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/custom-auth/login"))
            .and(header("X-Vault-Namespace", "tenant-corp"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(auth_response("s.ns-token", 3600)),
            )
            .mount(&ar_server)
            .await;
        let client =
            VaultClient::builder_approle(ar_server.uri(), valid_role_id(), valid_secret_id())
                .auth_mount("custom-auth")
                .namespace(Some("tenant-corp"))
                .build()
                .await
                .expect("AppRole custom mount + namespace");
        assert_eq!(
            client.auth.current_token().await.expose_secret(),
            "s.ns-token"
        );

        // Kubernetes
        let token_path = write_temp_token("custom", "custom-jwt");
        let k8s_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/custom-k8s/login"))
            .and(header("X-Vault-Namespace", "tenant-k8s"))
            .and(body_json(
                json!({ "role": "k8s-role", "jwt": "custom-jwt" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(auth_response("s.k8s-ns", 3600)))
            .mount(&k8s_server)
            .await;
        let client = VaultClient::builder_kubernetes(k8s_server.uri(), "k8s-role", &token_path)
            .auth_mount("custom-k8s")
            .namespace(Some("tenant-k8s"))
            .build()
            .await
            .expect("K8s custom mount + namespace");
        assert_eq!(
            client.auth.current_token().await.expose_secret(),
            "s.k8s-ns"
        );
        let _ = std::fs::remove_file(&token_path);
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
        let client = VaultClient::builder_approle(server.uri(), valid_role_id(), valid_secret_id())
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
        let client = VaultClient::builder_approle(server.uri(), valid_role_id(), valid_secret_id())
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

        let client = VaultClient::builder_approle(server.uri(), valid_role_id(), valid_secret_id())
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

    #[tokio::test]
    async fn kubernetes_token_renewal_and_rotation_reauth() {
        let token_path = write_temp_token("rotation", "jwt-initial");
        let server = MockServer::start().await;

        mock_k8s_login(&server, "jwt-initial", "role", "s.k8s-1", 1).await;

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "s.k8s-1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(auth_response("s.k8s-renewed", 1)),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "s.k8s-renewed"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        mock_k8s_login(&server, "jwt-rotated", "role", "s.k8s-relogged", 3600).await;

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/k"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "data": { "value": "v" } }
            })))
            .mount(&server)
            .await;

        let client = VaultClient::builder_kubernetes(server.uri(), "role", &token_path)
            .secrets_cache_ttl(Duration::ZERO)
            .build()
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(850)).await;
        client.load("k").await.unwrap();
        assert_eq!(
            client.auth.current_token().await.expose_secret(),
            "s.k8s-renewed"
        );

        std::fs::write(&token_path, "jwt-rotated").expect("write rotated token");
        tokio::time::sleep(Duration::from_millis(850)).await;
        client.load("k").await.unwrap();
        assert_eq!(
            client.auth.current_token().await.expose_secret(),
            "s.k8s-relogged"
        );

        let _ = std::fs::remove_file(&token_path);
    }

    #[tokio::test]
    async fn secrets_redacted_in_debug_and_errors() {
        let ar_fail = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(403).set_body_string("denied"))
            .mount(&ar_fail)
            .await;

        let secret = SecretString::from("super-sensitive-secret-id");
        let err = VaultClient::builder_approle(ar_fail.uri(), "my-role", secret.clone())
            .build()
            .await
            .unwrap_err();
        assert!(!format!("{err:?}").contains("super-sensitive-secret-id"));
        assert!(!format!("{err}").contains("super-sensitive-secret-id"));

        let ar_ok = MockServer::start().await;
        mock_approle_login(&ar_ok, "s.secret-token-xyz", 3600).await;
        let client = VaultClient::builder_approle(ar_ok.uri(), "my-role", secret)
            .build()
            .await
            .unwrap();
        let dbg = format!("{:?}", client.auth);
        assert!(!dbg.contains("super-sensitive-secret-id"));
        assert!(!dbg.contains("s.secret-token-xyz"));
        assert!(dbg.contains("[REDACTED]"));

        let token_path = write_temp_token("redact", "sens-jwt");
        let k_fail = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/kubernetes/login"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&k_fail)
            .await;
        let err = VaultClient::builder_kubernetes(k_fail.uri(), "role", &token_path)
            .build()
            .await
            .unwrap_err();
        assert!(!format!("{err:?}").contains("sens-jwt"));

        let k_ok = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/kubernetes/login"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(auth_response("s.k8s-secret", 3600)),
            )
            .mount(&k_ok)
            .await;
        let client = VaultClient::builder_kubernetes(k_ok.uri(), "role", &token_path)
            .build()
            .await
            .unwrap();
        let dbg = format!("{:?}", client.auth);
        assert!(!dbg.contains("s.k8s-secret"));
        assert!(dbg.contains("[REDACTED]"));
        let _ = std::fs::remove_file(&token_path);
    }

    #[tokio::test]
    async fn vault_concurrency_renewal_stampede_prevention() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(auth_response("s.initial-token", 1)),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "s.initial-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(auth_response("s.renewed-concurrent", 3600)),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/concurrent-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "data": { "value": "concurrent-val" } }
            })))
            .mount(&server)
            .await;

        let client = Arc::new(
            VaultClient::builder_approle(server.uri(), valid_role_id(), valid_secret_id())
                .secrets_cache_ttl(Duration::ZERO)
                .build()
                .await
                .unwrap(),
        );

        // Wait past renewal threshold (0.8s)
        tokio::time::sleep(Duration::from_millis(850)).await;

        // Launch 10 concurrent requests
        let mut handles = Vec::new();
        for _ in 0..10 {
            let client_clone = Arc::clone(&client);
            handles.push(tokio::spawn(async move {
                client_clone.load("concurrent-key").await
            }));
        }

        for handle in handles {
            let res = handle.await.unwrap();
            assert_eq!(res.unwrap(), Some("concurrent-val".to_string()));
        }

        server.verify().await;
        assert_eq!(
            client.auth.current_token().await.expose_secret(),
            "s.renewed-concurrent"
        );
    }

    #[tokio::test]
    async fn vault_auth_cooldown_backoff() {
        let server = MockServer::start().await;

        // Initial login with short 1s TTL (non-renewable to force re-login)
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "client_token": "s.token-1", "lease_duration": 1, "renewable": false }
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Re-login fails with 500
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let client = VaultClient::builder_approle(server.uri(), valid_role_id(), valid_secret_id())
            .secrets_cache_ttl(Duration::ZERO)
            .build()
            .await
            .unwrap();

        // Wait past TTL
        tokio::time::sleep(Duration::from_millis(850)).await;

        // First attempt triggers re-login and fails
        let err1 = client.load("key").await.unwrap_err();
        assert!(err1.to_string().contains("HTTP 500"));

        // Immediate second attempt should hit cooldown backoff
        let err2 = client.load("key").await.unwrap_err();
        assert!(err2.to_string().contains("cooldown backoff"));
    }

    #[test]
    fn vault_url_encoding_special_characters() {
        assert_eq!(
            VaultClient::encode_path_segment("standard-name_123.test~"),
            "standard-name_123.test~"
        );
        assert_eq!(
            VaultClient::encode_path_segment("name with spaces"),
            "name%20with%20spaces"
        );
        assert_eq!(
            VaultClient::encode_path_segment("mount?query#fragment/slash"),
            "mount%3Fquery%23fragment%2Fslash"
        );
    }
}
