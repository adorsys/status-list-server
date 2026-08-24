use std::path::PathBuf;
use std::{collections::HashMap, fmt, marker::PhantomData};

use config::builder::DefaultState;
use config::{Config as ConfigLib, ConfigBuilder, ConfigError, Environment};
#[cfg(feature = "redis")]
use redis::{
    Client as RedisClient, ClientTlsConfig, RedisResult, TlsCertificates,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer};
use serde_aux::field_attributes::deserialize_vec_from_string_or_vec;
#[cfg(feature = "redis")]
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseBackend {
    #[default]
    Memory,
    Postgres,
    MySql,
    Sqlite,
}

#[derive(Clone, Copy)]
struct DatabaseBackendScheme {
    prefixes: &'static [&'static str],
    description: &'static str,
}

impl DatabaseBackend {
    fn scheme(&self) -> DatabaseBackendScheme {
        match self {
            DatabaseBackend::Memory => DatabaseBackendScheme {
                prefixes: &["memory:", "memory"],
                description: "'memory:' or 'memory'",
            },
            DatabaseBackend::Postgres => DatabaseBackendScheme {
                prefixes: &["postgres://", "postgresql://"],
                description: "'postgres://' or 'postgresql://'",
            },
            DatabaseBackend::MySql => DatabaseBackendScheme {
                prefixes: &["mysql://"],
                description: "'mysql://'",
            },
            DatabaseBackend::Sqlite => DatabaseBackendScheme {
                prefixes: &["sqlite:"],
                description: "'sqlite:'",
            },
        }
    }

    /// Returns a human-readable description of the expected URL scheme(s).
    pub fn expected_scheme_description(&self) -> &'static str {
        self.scheme().description
    }

    /// Returns the lowercase name matching the config value (`"memory"`, `"postgres"`,
    /// `"mysql"`, `"sqlite"`), useful for user-facing messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseBackend::Memory => "memory",
            DatabaseBackend::Postgres => "postgres",
            DatabaseBackend::MySql => "mysql",
            DatabaseBackend::Sqlite => "sqlite",
        }
    }

    /// Validates that the given URL matches the expected scheme for this backend.
    pub fn validate_url_scheme(&self, url: &str) -> bool {
        self.scheme()
            .prefixes
            .iter()
            .any(|prefix| url.starts_with(prefix))
    }
}

/// Recognized values of the APP_ENV environment variable
pub const ENV_PRODUCTION: &str = "production";
pub const ENV_DEVELOPMENT: &str = "development";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub aws: AwsConfig,
    pub vault: VaultConfig,
    pub gcp_secret_manager: GcpSecretManagerConfig,
    pub azure_keyvault: AzureKeyVaultConfig,
    pub cache: CacheConfig,
    pub status_list: StatusListConfig,
    pub rate_limit: RateLimitConfig,
    pub limits: LimitsConfig,
    pub telemetry: TelemetryConfig,
}

/// Rate-limit configuration with strict (writes) and permissive (reads) tiers.
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub strict_burst_size: u32,
    pub strict_period_secs: u64,
    pub permissive_burst_size: u32,
    pub permissive_period_secs: u64,
}

/// Hard bounds on incoming requests and persisted status lists.
#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    pub max_body_size_bytes: usize,
    pub max_status_index: i32,
    pub max_statuses_per_request: usize,
    pub max_serialized_list_size: usize,
}

/// Telemetry configuration controlling tracing and metrics export.
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    /// Environment mode: `"development"` (stdout) or `"production"` (OTLP export).
    pub environment: TelemetryEnvironment,
    /// OTLP gRPC endpoint for trace, metric, and log export (prod mode only).
    pub otlp_endpoint: String,
    /// Trace sampling ratio from 0.0 (none) to 1.0 (all).
    #[serde(deserialize_with = "deserialize_sampler_ratio")]
    pub sampler_ratio: f64,
    /// Whether the OpenTelemetry tracing pipeline is enabled.
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryEnvironment {
    Development,
    Production,
}

impl TelemetryEnvironment {
    pub fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

impl<'de> Deserialize<'de> for TelemetryEnvironment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "production" | "prod" => Ok(Self::Production),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["development", "dev", "production", "prod"],
            )),
        }
    }
}

fn deserialize_sampler_ratio<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = f64::deserialize(deserializer)?;
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "telemetry.sampler_ratio must be a finite value in 0.0..=1.0",
        ))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub domain: String,
    pub port: u16,
    pub cert: CertConfig,
    pub enable_metrics: bool,
    pub aggregation_uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertConfig {
    pub provisioning_strategy: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(deserialize_with = "deserialize_vec_from_string_or_vec")]
    #[serde(default)]
    pub eku: Vec<u64>,
    pub acme_directory_url: String,
    /// Cache TTL for private signing-key reads in seconds. `0` disables this cache.
    pub signing_key_cache_ttl: u64,
    pub renewal_cron_schedule: String,
    #[serde(default)]
    pub dns_challenge_server_url: Option<String>,
    pub store: CertStoreConfig,
    #[serde(default)]
    pub dns: DnsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertStoreConfig {
    #[serde(default)]
    pub certificate_path: Option<String>,
    #[serde(default)]
    pub signing_key_path: Option<String>,
    #[serde(default)]
    pub certificate_key: Option<String>,
    #[serde(default)]
    pub signing_key_key: Option<String>,
}

/// DNS provider used to solve ACME DNS-01 challenges
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProviderKind {
    Route53,
    Cloudflare,
    Gcloud,
    Azure,
    Acmedns,
    Pebble,
}

/// A DNS provider resolved by [`DnsConfig::resolve`], carrying its validated
/// settings so the boot path can build the provider without re-checking them
#[derive(Debug, Clone, Copy)]
pub enum ResolvedDnsProvider<'a> {
    /// Uses the ambient AWS credentials; no provider-specific settings
    Route53,
    Cloudflare(&'a CloudflareDnsConfig),
    Gcloud(GcloudKeySource<'a>),
    Azure(&'a AzureDnsConfig),
    Acmedns(&'a AcmeDnsConfig),
    /// Development-only; its challenge server URL lives outside [`DnsConfig`]
    Pebble,
}

/// The Google Cloud service account key source, with empty values counting
/// as unset and the inline key winning when both are configured
#[derive(Debug, Clone, Copy)]
pub enum GcloudKeySource<'a> {
    /// The key JSON itself
    Inline(&'a SecretString),
    /// Path to the key JSON file
    Path(&'a str),
}

impl ResolvedDnsProvider<'_> {
    /// The plain provider kind, without the settings
    pub fn kind(&self) -> DnsProviderKind {
        match self {
            Self::Route53 => DnsProviderKind::Route53,
            Self::Cloudflare(_) => DnsProviderKind::Cloudflare,
            Self::Gcloud(_) => DnsProviderKind::Gcloud,
            Self::Azure(_) => DnsProviderKind::Azure,
            Self::Acmedns(_) => DnsProviderKind::Acmedns,
            Self::Pebble => DnsProviderKind::Pebble,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DnsConfig {
    /// Selected DNS provider. When unset, defaults to Route53 in production
    /// and Pebble in development, preserving the historical behavior.
    #[serde(default)]
    pub provider: Option<DnsProviderKind>,
    pub cloudflare: Option<CloudflareDnsConfig>,
    pub gcloud: Option<GcloudDnsConfig>,
    pub azure: Option<AzureDnsConfig>,
    pub acmedns: Option<AcmeDnsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GcloudDnsConfig {
    /// Service account key JSON, inline
    pub service_account_key: Option<SecretString>,
    /// Path to the service account key JSON file
    pub service_account_key_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AzureDnsConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: SecretString,
    pub subscription_id: String,
    /// Resource group holding the DNS zones
    pub resource_group: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CloudflareDnsConfig {
    /// API token with Zone:Read and DNS:Edit permissions
    pub api_token: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeDnsConfig {
    /// Base URL of the ACME-DNS server, e.g. <https://auth.example.org>
    pub server_url: String,
    /// Default account, used for domains without an entry in `accounts`.
    /// The three fields must be set together.
    pub username: Option<String>,
    pub password: Option<SecretString>,
    /// Subdomain returned by the ACME-DNS registration
    pub subdomain: Option<String>,
    /// Per-domain accounts keyed by identifier (e.g. `status.example.com`),
    /// so each identifier gets its own two-value TXT window. Accepts a map
    /// or a JSON object string, allowing the whole map in one env var.
    #[serde(default, deserialize_with = "deserialize_map_from_string_or_map")]
    pub accounts: HashMap<String, AcmeDnsAccount>,
}

/// A single registered ACME-DNS account
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeDnsAccount {
    pub username: String,
    pub password: SecretString,
    pub subdomain: String,
}

/// Treat unset and empty (e.g. an env var set to an empty string) alike
fn non_empty(value: &Option<String>) -> Option<&String> {
    value.as_ref().filter(|v| !v.trim().is_empty())
}

impl AcmeDnsConfig {
    /// The default account, when username, password and subdomain are all set
    /// (empty values count as unset)
    pub fn default_account(&self) -> Option<AcmeDnsAccount> {
        let password = self
            .password
            .as_ref()
            .filter(|p| !p.expose_secret().trim().is_empty())?;
        Some(AcmeDnsAccount {
            username: non_empty(&self.username)?.clone(),
            password: password.clone(),
            subdomain: non_empty(&self.subdomain)?.clone(),
        })
    }

    /// Validate that the settings describe at least one usable account
    fn validate(&self) -> Result<(), ConfigError> {
        if self.server_url.trim().is_empty() {
            return Err(ConfigError::Message(
                "ACME-DNS settings have an empty server_url".to_string(),
            ));
        }
        let set = [
            non_empty(&self.username).is_some(),
            self.password
                .as_ref()
                .is_some_and(|p| !p.expose_secret().trim().is_empty()),
            non_empty(&self.subdomain).is_some(),
        ];
        if set.iter().any(|&s| s) && !set.iter().all(|&s| s) {
            return Err(ConfigError::Message(
                "Incomplete ACME-DNS default account: username, password and subdomain \
                 must be set together"
                    .to_string(),
            ));
        }
        if self.default_account().is_none() && self.accounts.is_empty() {
            return Err(ConfigError::Message(
                "ACME-DNS settings need a default account (username/password/subdomain) \
                 or a non-empty accounts map"
                    .to_string(),
            ));
        }
        // Reject unusable per-domain entries here instead of as an opaque
        // HTTP 401 at the first renewal. Key conflicts under normalization
        // are the provider's own invariant and are rejected in
        // AcmeDnsProvider::new, also at startup.
        for (domain, account) in &self.accounts {
            let name = domain.trim();
            let name = name.strip_prefix("*.").unwrap_or(name);
            if name.trim_end_matches('.').is_empty() {
                return Err(ConfigError::Message(format!(
                    "ACME-DNS accounts entry {domain:?} does not name a domain"
                )));
            }
            let empty: Vec<&str> = [
                ("username", account.username.trim().is_empty()),
                (
                    "password",
                    account.password.expose_secret().trim().is_empty(),
                ),
                ("subdomain", account.subdomain.trim().is_empty()),
            ]
            .into_iter()
            .filter_map(|(field, is_empty)| is_empty.then_some(field))
            .collect();
            if !empty.is_empty() {
                return Err(ConfigError::Message(format!(
                    "ACME-DNS account for {domain} has empty required fields: {}",
                    empty.join(", ")
                )));
            }
        }
        Ok(())
    }
}

/// Deserialize a map either directly or from a JSON object string, so it can
/// be provided via a single environment variable (map keys such as domain
/// names cannot be encoded in `__`-separated env var names).
fn deserialize_map_from_string_or_map<'de, D, V>(
    deserializer: D,
) -> Result<HashMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: serde::de::DeserializeOwned,
{
    // A visitor (rather than an untagged enum) so errors inside a map value
    // surface as-is instead of as "did not match any variant"
    struct MapOrString<V>(PhantomData<V>);

    impl<'de, V: serde::de::DeserializeOwned> serde::de::Visitor<'de> for MapOrString<V> {
        type Value = HashMap<String, V>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map or a JSON object string")
        }

        fn visit_str<E: serde::de::Error>(self, raw: &str) -> Result<Self::Value, E> {
            if raw.trim().is_empty() {
                return Ok(HashMap::new());
            }
            serde_json::from_str(raw).map_err(E::custom)
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut map = HashMap::with_capacity(access.size_hint().unwrap_or(0));
            while let Some((key, value)) = access.next_entry()? {
                map.insert(key, value);
            }
            Ok(map)
        }
    }

    deserializer.deserialize_any(MapOrString(PhantomData))
}

impl AzureDnsConfig {
    /// Reject empty required fields so misconfigurations fail at startup
    /// instead of surfacing as opaque API errors at the first renewal
    fn validate(&self) -> Result<(), ConfigError> {
        let empty: Vec<&str> = [
            ("tenant_id", self.tenant_id.trim().is_empty()),
            ("client_id", self.client_id.trim().is_empty()),
            (
                "client_secret",
                self.client_secret.expose_secret().trim().is_empty(),
            ),
            ("subscription_id", self.subscription_id.trim().is_empty()),
            ("resource_group", self.resource_group.trim().is_empty()),
        ]
        .into_iter()
        .filter_map(|(name, is_empty)| is_empty.then_some(name))
        .collect();
        if !empty.is_empty() {
            return Err(ConfigError::Message(format!(
                "Azure DNS settings have empty required fields: {}",
                empty.join(", ")
            )));
        }
        Ok(())
    }
}

impl CloudflareDnsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.api_token.expose_secret().trim().is_empty() {
            return Err(ConfigError::Message(
                "Cloudflare DNS settings have an empty api_token".to_string(),
            ));
        }
        Ok(())
    }
}

impl DnsConfig {
    /// Resolve the DNS provider to use, validate its settings and return them
    /// borrowed, so consumers need no re-validation. Synchronous and
    /// network-free by design; anything needing I/O belongs to the boot path.
    pub fn resolve(&self, app_env: &str) -> Result<ResolvedDnsProvider<'_>, ConfigError> {
        let kind = self.provider.unwrap_or(if app_env == ENV_PRODUCTION {
            DnsProviderKind::Route53
        } else {
            DnsProviderKind::Pebble
        });

        let missing = |section: &str| {
            ConfigError::Message(format!(
                "DNS provider {kind:?} selected but the server.cert.{section} settings are missing"
            ))
        };
        let resolved = match kind {
            DnsProviderKind::Route53 => ResolvedDnsProvider::Route53,
            DnsProviderKind::Pebble => ResolvedDnsProvider::Pebble,
            DnsProviderKind::Cloudflare => {
                let cloudflare = self
                    .cloudflare
                    .as_ref()
                    .ok_or_else(|| missing("dns.cloudflare"))?;
                cloudflare.validate()?;
                ResolvedDnsProvider::Cloudflare(cloudflare)
            }
            DnsProviderKind::Gcloud => {
                let key = self.gcloud.as_ref().and_then(|g| {
                    g.service_account_key
                        .as_ref()
                        .filter(|k| !k.expose_secret().trim().is_empty())
                        .map(GcloudKeySource::Inline)
                        .or_else(|| {
                            non_empty(&g.service_account_key_path)
                                .map(|path| GcloudKeySource::Path(path))
                        })
                });
                ResolvedDnsProvider::Gcloud(key.ok_or_else(|| missing("dns.gcloud"))?)
            }
            DnsProviderKind::Azure => {
                let azure = self.azure.as_ref().ok_or_else(|| missing("dns.azure"))?;
                azure.validate()?;
                ResolvedDnsProvider::Azure(azure)
            }
            DnsProviderKind::Acmedns => {
                let acmedns = self
                    .acmedns
                    .as_ref()
                    .ok_or_else(|| missing("dns.acmedns"))?;
                acmedns.validate()?;
                ResolvedDnsProvider::Acmedns(acmedns)
            }
        };
        Ok(resolved)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URI. Leave empty to disable the optional Redis-backed
    /// certificate-material cache, even when the `redis` feature is compiled.
    ///
    /// Production Kubernetes deployments should prefer the split host/password
    /// fields below so pod metadata does not contain a fully assembled URI.
    pub uri: SecretString,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<SecretString>,
    #[serde(default)]
    pub database: Option<u8>,
    pub require_client_auth: bool,
    /// Cache TTL for Redis TLS certificates in seconds.
    /// Setting this to 0 disables caching entirely.
    pub cert_cache_ttl: u64,
}

/// Connection-pool tuning for the production (Postgres/MySQL) backends.
///
/// Defaults are chosen so a single-replica deployment with a fresh Postgres
/// instance works out of the box, while still being safe to run in
/// production. Adjust `max` according to your server's `max_connections`
/// divided by the number of application replicas.
///
/// PostgreSQL default `max_connections` = 100.
/// Rule of thumb: pool.max = floor(pg_max_connections / replicas) - 5 (headroom)
#[derive(Debug, Clone, Deserialize)]
pub struct DatabasePoolConfig {
    /// Maximum number of connections in the pool. Default: 5
    pub max_connections: u32,
    /// Minimum number of idle connections kept alive. Default: 1
    pub min_connections: u32,
    /// Seconds to wait for an available connection before returning an error. Default: 5
    pub acquire_timeout_secs: u64,
    /// Seconds for the TCP connect+auth handshake to the server. Default: 10
    pub connect_timeout_secs: u64,
    /// Seconds a connection may sit idle before being closed. Default: 600 (10 min)
    pub idle_timeout_secs: u64,
    /// Maximum age in seconds of any connection, regardless of activity. Default: 1800 (30 min)
    pub max_lifetime_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Full database URL. This remains supported for local and non-Kubernetes
    /// deployments, but Kubernetes manifests should prefer the split fields
    /// below to avoid exposing an assembled credential URL in pod metadata.
    pub url: SecretString,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<SecretString>,
    #[serde(default)]
    pub name: Option<String>,
    /// Validated against the URL scheme at startup.
    #[serde(default)]
    pub backend: DatabaseBackend,
    pub pool: DatabasePoolConfig,
}

fn trim_non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn encode_url_part(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .fold(String::with_capacity(value.len()), |mut encoded, byte| {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    encoded.push(char::from(*byte))
                }
                _ => {
                    let _ = fmt::Write::write_fmt(&mut encoded, format_args!("%{byte:02X}"));
                }
            }
            encoded
        })
}

fn required_config_field<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str, ConfigError> {
    trim_non_empty(value)
        .ok_or_else(|| ConfigError::Message(format!("Missing required config field: {field}")))
}

impl DatabaseConfig {
    fn has_split_connection_fields(&self) -> bool {
        self.host
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || self
                .username
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || self
                .password
                .as_ref()
                .is_some_and(|value| !value.expose_secret().trim().is_empty())
            || self
                .name
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || self.port.is_some()
    }

    /// Resolve the database connection string from either the backward-compatible
    /// full URL or the split connection fields used by the Helm chart.
    pub fn resolved_url(&self) -> Result<SecretString, ConfigError> {
        if !self.has_split_connection_fields() {
            return Ok(self.url.clone());
        }

        let scheme = match self.backend {
            DatabaseBackend::Postgres => "postgres",
            DatabaseBackend::MySql => "mysql",
            DatabaseBackend::Memory | DatabaseBackend::Sqlite => {
                return Err(ConfigError::Message(format!(
                    "Split database connection fields are only supported for postgres/mysql; configured backend is '{}'",
                    self.backend.as_str()
                )));
            }
        };
        let default_port = match self.backend {
            DatabaseBackend::Postgres => 5432,
            DatabaseBackend::MySql => 3306,
            DatabaseBackend::Memory | DatabaseBackend::Sqlite => unreachable!(),
        };

        let host = required_config_field(self.host.as_deref(), "database.host")?;
        let username = required_config_field(self.username.as_deref(), "database.username")?;
        let password = self
            .password
            .as_ref()
            .and_then(|value| trim_non_empty(Some(value.expose_secret())))
            .ok_or_else(|| {
                ConfigError::Message("Missing required config field: database.password".to_string())
            })?;
        let name = required_config_field(self.name.as_deref(), "database.name")?;
        let port = self.port.unwrap_or(default_port);

        Ok(SecretString::from(format!(
            "{scheme}://{}:{}@{host}:{port}/{}",
            encode_url_part(username),
            encode_url_part(password),
            encode_url_part(name)
        )))
    }
}

impl RedisConfig {
    fn has_split_connection_fields(&self) -> bool {
        self.host
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || self
                .password
                .as_ref()
                .is_some_and(|value| !value.expose_secret().trim().is_empty())
            || self
                .username
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || self
                .scheme
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || self.port.is_some()
            || self.database.is_some()
    }

    /// Resolve the Redis connection URI from either the full URI or split fields.
    /// Missing-field errors mention only config keys, never secret values.
    pub fn resolved_uri(&self) -> Result<SecretString, ConfigError> {
        if !self.has_split_connection_fields() {
            return Ok(self.uri.clone());
        }

        let scheme = trim_non_empty(self.scheme.as_deref()).unwrap_or("redis");
        if scheme != "redis" && scheme != "rediss" {
            return Err(ConfigError::Message(
                "Invalid redis.scheme: expected 'redis' or 'rediss'".to_string(),
            ));
        }

        let host = required_config_field(self.host.as_deref(), "redis.host")?;
        let port = self.port.unwrap_or(6379);
        let database = self.database.map(|db| format!("/{db}")).unwrap_or_default();
        let authority = match (
            trim_non_empty(self.username.as_deref()),
            self.password
                .as_ref()
                .and_then(|value| trim_non_empty(Some(value.expose_secret()))),
        ) {
            (Some(username), Some(password)) => {
                format!(
                    "{}:{}@",
                    encode_url_part(username),
                    encode_url_part(password)
                )
            }
            (None, Some(password)) => format!(":{}@", encode_url_part(password)),
            (Some(_), None) => {
                return Err(ConfigError::Message(
                    "Missing required config field: redis.password".to_string(),
                ));
            }
            (None, None) => String::new(),
        };

        Ok(SecretString::from(format!(
            "{scheme}://{authority}{host}:{port}{database}"
        )))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub s3_bucket: String,
    pub s3_key_prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VaultConfig {
    /// Vault / OpenBao API address (e.g. `http://vault:8200`).
    pub addr: String,
    /// AppRole role_id (can be baked into config).
    pub role_id: String,
    /// AppRole secret_id (deliver via env/secrets injector in production).
    #[serde(default)]
    pub secret_id: Option<SecretString>,
    /// Optional path to file containing AppRole secret_id (e.g. Kubernetes volume mount or Docker secret).
    #[serde(default)]
    pub secret_id_path: Option<PathBuf>,
    /// AppRole auth engine mount path (default: `approle`).
    pub auth_mount: String,
    /// KV v2 engine mount path.
    pub mount: String,
    /// Prefix prepended to all secret paths. Default: empty.
    pub path_prefix: String,
    /// Optional Vault Enterprise / OpenBao namespace.
    #[serde(default)]
    pub namespace: Option<String>,
    /// HTTP request timeout in seconds.
    pub timeout_secs: u64,
}

impl VaultConfig {
    /// Resolve the AppRole secret_id either directly from `secret_id`
    /// or by reading from `secret_id_path` on disk.
    pub fn resolve_secret_id(&self) -> Result<SecretString, ConfigError> {
        if let Some(secret_id) = &self.secret_id
            && !secret_id.expose_secret().trim().is_empty()
        {
            return Ok(secret_id.clone());
        }

        if let Some(path) = &self.secret_id_path {
            let content = std::fs::read_to_string(path).map_err(|e| {
                ConfigError::Message(format!(
                    "Failed to read Vault secret_id from file {path:?}: {e}"
                ))
            })?;
            let trimmed = content.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::Message(format!(
                    "Vault secret_id file {path:?} is empty"
                )));
            }
            return Ok(SecretString::from(trimmed.to_string()));
        }

        Err(ConfigError::Message(
            "Vault configuration missing secret_id: provide 'secret_id' or 'secret_id_path'"
                .to_string(),
        ))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GcpSecretManagerConfig {
    /// GCP project ID.
    pub project_id: String,
    /// Service account key JSON, inline.
    #[serde(default)]
    pub service_account_key: Option<SecretString>,
    /// Path to the service account key JSON file.
    #[serde(default)]
    pub service_account_key_path: Option<String>,
    /// Optional custom gRPC endpoint URL (e.g. for regional endpoints, VPC-SC, or emulator testing).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Allow anonymous credentials (for local testing/emulator only).
    #[serde(default)]
    pub allow_anonymous_credentials: bool,
    /// Cache TTL for GCP secrets in seconds.
    /// Setting this to 0 disables caching entirely.
    pub secrets_cache_ttl: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AzureKeyVaultConfig {
    /// Azure Key Vault URL (e.g. `https://my-vault.vault.azure.net/`).
    #[serde(default)]
    pub vault_url: Option<url::Url>,
    /// Service principal tenant ID.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Service principal client ID.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Service principal client secret.
    #[serde(default)]
    pub client_secret: Option<SecretString>,
    /// Cache TTL for Azure Key Vault secrets in seconds.
    /// Setting this to 0 disables caching entirely.
    pub secrets_cache_ttl: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// Time-to-live for cached status list items in seconds.
    /// Setting this to 0 disables caching entirely.
    pub ttl: u64,
    pub max_capacity: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatusListConfig {
    pub token_exp_secs: u64,
    pub token_ttl_secs: u64,
    /// Retention period for status list snapshots in seconds.
    /// Snapshots older than this will be deleted by a scheduled cleanup task.
    /// Default is 90 days (7776000 seconds).
    ///
    /// **Privacy note:** Set to 0 to disable snapshots entirely.
    /// This prevents unbounded database growth and mitigates timing leak
    /// risks described in draft-21 §12.7. When disabled, historical resolution
    /// via `?time=` query parameter will not be available.
    ///
    /// **Deprecation:** The old name `history_retention_secs`
    /// (`APP_STATUS_LIST__HISTORY_RETENTION_SECS`) is accepted for backward
    /// compatibility but will be removed in a future release. Use
    /// `snapshot_retention_secs` (`APP_STATUS_LIST__SNAPSHOT_RETENTION_SECS`).
    #[serde(alias = "history_retention_secs")]
    pub snapshot_retention_secs: u64,
}

#[cfg(feature = "redis")]
impl RedisConfig {
    /// Establishes a new Redis connection based on the configuration.
    ///
    /// If it is `true`, the connection will use TLS with client authentication, and the URI **must** use the `rediss://` scheme.
    ///
    /// To enable mutual TLS (mTLS), both `cert_pem` and `key_pem` must be provided.
    /// If one is missing, the client-side authentication will not be effective.
    ///
    /// # Parameters
    /// - `cert_pem`: The client certificate in PEM format (required for mTLS).
    /// - `key_pem`: The client private key in PEM format (required for mTLS).
    /// - `root_cert`: The custom root certificate in PEM format (required for client authentication).
    ///
    /// # Errors
    /// Returns an error if the connection cannot be established.
    pub async fn start(
        &self,
        cert_pem: Option<&str>,
        key_pem: Option<&str>,
        root_cert: Option<&str>,
    ) -> RedisResult<ConnectionManager> {
        let uri = self.resolved_uri().map_err(|err| {
            redis::RedisError::from((
                redis::ErrorKind::InvalidClientConfig,
                "invalid Redis configuration",
                err.to_string(),
            ))
        })?;

        let client = if !self.require_client_auth {
            tracing::info!("Connecting to Redis (no client authentication)");
            RedisClient::open(uri.expose_secret())?
        } else {
            tracing::info!("Connecting to Redis with TLS and client authentication");

            let client_tls = match (cert_pem, key_pem) {
                (Some(cert), Some(key)) => {
                    tracing::debug!("Using client TLS certificates");
                    Some(ClientTlsConfig {
                        client_cert: cert.as_bytes().to_vec(),
                        client_key: key.as_bytes().to_vec(),
                    })
                }
                _ => {
                    tracing::warn!("Client authentication required but no certificates provided");
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Io,
                        "Client authentication required but no certificates provided",
                    )));
                }
            };

            let root_cert = root_cert.map(|cert| cert.as_bytes().to_vec());

            RedisClient::build_with_tls(
                uri.expose_secret(),
                TlsCertificates {
                    client_tls,
                    root_cert,
                },
            )?
        };

        let config =
            ConnectionManagerConfig::new().set_connection_timeout(Some(Duration::from_secs(60)));
        client.get_connection_manager_with_config(config).await
    }
}

impl Config {
    /// Loads configuration from built-in defaults, then overrides them with
    /// values sourced from the process environment.
    ///
    /// Environment variables must be prefixed with `APP_` and use `__` as the
    /// separator between nested keys. For example `APP_SERVER__PORT=5002`
    /// maps to the `server.port` configuration value.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_overrides(&[])
    }

    pub fn load_from_overrides(overrides: &[(&str, &str)]) -> Result<Self, ConfigError> {
        let mut builder = base_builder()?
            // Override config values via environment variables
            // The environment variables should be prefixed with 'APP_' and use '__' as a separator
            // Example: APP_REDIS__REQUIRE_CLIENT_AUTH=false
            .add_source(
                Environment::with_prefix("APP")
                    .prefix_separator("_")
                    .separator("__"),
            );

        for &(key, val) in overrides {
            let normalized_key = key
                .strip_prefix("APP_")
                .or_else(|| key.strip_prefix("app_"))
                .unwrap_or(key)
                .replace("__", ".")
                .to_lowercase();
            builder = builder.set_override(normalized_key, val)?;
        }

        let config = builder.build()?;
        let config: Config = config.try_deserialize()?;
        Ok(config)
    }
}

/// Returns a `config::ConfigBuilder` seeded with the built-in default values.
///
/// Both production loading (via [`Config::load`]) and test loading (via
/// `Config::load_from_overrides`) start from this shared set of defaults so
/// that there is exactly one source of truth for the default configuration.
fn base_builder() -> Result<ConfigBuilder<DefaultState>, ConfigError> {
    #[cfg(feature = "postgres")]
    let (default_db_url, default_db_backend) = (
        "postgres://postgres:postgres@localhost:5432/status-list",
        "postgres",
    );
    #[cfg(all(not(feature = "postgres"), feature = "sqlite"))]
    let (default_db_url, default_db_backend) = ("sqlite::memory:", "sqlite");
    #[cfg(all(not(feature = "postgres"), not(feature = "sqlite"), feature = "mysql"))]
    let (default_db_url, default_db_backend) =
        ("mysql://mysql:mysql@localhost:3306/status-list", "mysql");
    #[cfg(all(
        not(feature = "postgres"),
        not(feature = "sqlite"),
        not(feature = "mysql")
    ))]
    let (default_db_url, default_db_backend) = ("memory:", "memory");

    #[cfg(feature = "acme")]
    let (default_provisioning_strategy, default_cert_path, default_key_path) =
        ("acme", Option::<String>::None, Option::<String>::None);
    #[cfg(not(feature = "acme"))]
    let (default_provisioning_strategy, default_cert_path, default_key_path) =
        ("store", Option::<String>::None, Option::<String>::None);

    let telemetry_environment = match std::env::var("APP_ENV")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "production" | "prod" => ENV_PRODUCTION,
        _ => ENV_DEVELOPMENT,
    };

    let builder = ConfigLib::builder()
        .set_default("server.host", "localhost")?
        .set_default("server.domain", "localhost")?
        .set_default("server.port", 8000)?
        .set_default("server.enable_metrics", false)?
        .set_default("server.aggregation_uri", Option::<String>::None)?
        .set_default("database.url", default_db_url)?
        .set_default("database.backend", default_db_backend)?
        .set_default("database.pool.max_connections", 5u32)?
        .set_default("database.pool.min_connections", 1u32)?
        .set_default("database.pool.acquire_timeout_secs", 5u64)?
        .set_default("database.pool.connect_timeout_secs", 10u64)?
        .set_default("database.pool.idle_timeout_secs", 600u64)?
        .set_default("database.pool.max_lifetime_secs", 1800u64)?
        .set_default("redis.uri", "")?
        .set_default("redis.require_client_auth", false)?
        .set_default("redis.cert_cache_ttl", 3600)?
        .set_default("aws.s3_bucket", "status-list-adorsys")?
        .set_default("aws.s3_key_prefix", "")?
        .set_default(
            "server.cert.provisioning_strategy",
            default_provisioning_strategy,
        )?
        .set_default("server.cert.email", "admin@example.com")?
        .set_default("server.cert.eku", vec![1, 3, 6, 1, 5, 5, 7, 3, 30])?
        .set_default("server.cert.organization", "adorsys GmbH & CO KG")?
        .set_default(
            "server.cert.acme_directory_url",
            "https://acme-v02.api.letsencrypt.org/directory",
        )?
        .set_default("server.cert.signing_key_cache_ttl", 0)?
        .set_default("server.cert.renewal_cron_schedule", "0 0 0 * * *")?
        .set_default("server.cert.store.certificate_path", default_cert_path)?
        .set_default("server.cert.store.signing_key_path", default_key_path)?
        .set_default("server.cert.store.certificate_key", Option::<String>::None)?
        .set_default("server.cert.store.signing_key_key", Option::<String>::None)?
        .set_default("aws.region", "us-east-1")?
        .set_default("vault.addr", "http://localhost:8200")?
        .set_default("vault.role_id", "")?
        .set_default("vault.secret_id", Option::<String>::None)?
        .set_default("vault.secret_id_path", Option::<String>::None)?
        .set_default("vault.auth_mount", "approle")?
        .set_default("vault.mount", "secret")?
        .set_default("vault.path_prefix", "")?
        .set_default("vault.namespace", Option::<String>::None)?
        .set_default("vault.timeout_secs", 30)?
        .set_default("gcp_secret_manager.project_id", "")?
        .set_default("gcp_secret_manager.allow_anonymous_credentials", false)?
        .set_default("gcp_secret_manager.secrets_cache_ttl", 300)?
        .set_default("azure_keyvault.vault_url", Option::<String>::None)?
        .set_default("azure_keyvault.secrets_cache_ttl", 300)?
        .set_default("cache.ttl", 5 * 60)?
        .set_default("cache.max_capacity", 100)?
        .set_default("status_list.token_exp_secs", 900)?
        .set_default("status_list.token_ttl_secs", 300)?
        .set_default("status_list.snapshot_retention_secs", 7776000)?
        .set_default("rate_limit.strict_burst_size", 10)?
        .set_default("rate_limit.strict_period_secs", 60)?
        .set_default("rate_limit.permissive_burst_size", 100)?
        .set_default("rate_limit.permissive_period_secs", 60)?
        .set_default("limits.max_body_size_bytes", 2_097_152)?
        .set_default("limits.max_status_index", 100_000)?
        .set_default("limits.max_statuses_per_request", 5_000)?
        .set_default("limits.max_serialized_list_size", 1_048_576)?
        .set_default("telemetry.environment", telemetry_environment)?
        .set_default("telemetry.otlp_endpoint", "http://localhost:4317")?
        .set_default("telemetry.sampler_ratio", 1.0)?
        .set_default("telemetry.enabled", true)?;
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_config_loading() {
        // 1. Default configuration loading & helper methods
        let config = Config::load_from_overrides(&[]).expect("Failed to load default config");

        assert_eq!(config.server.host, "localhost");
        assert_eq!(config.server.port, 8000);
        assert_eq!(config.server.cert.email, "admin@example.com");
        assert_eq!(
            config.server.cert.acme_directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(config.aws.region, "us-east-1");
        assert_eq!(config.aws.s3_bucket, "status-list-adorsys");
        assert_eq!(config.aws.s3_key_prefix, "");
        assert_eq!(config.gcp_secret_manager.project_id, "");
        assert_eq!(config.gcp_secret_manager.secrets_cache_ttl, 300);
        assert_eq!(config.azure_keyvault.vault_url, None);
        assert_eq!(config.azure_keyvault.secrets_cache_ttl, 300);
        assert_eq!(config.status_list.token_exp_secs, 900);
        assert_eq!(config.status_list.token_ttl_secs, 300);
        assert_eq!(config.server.cert.renewal_cron_schedule, "0 0 0 * * *");
        assert_eq!(config.server.cert.dns_challenge_server_url, None);
        assert_eq!(config.server.aggregation_uri, None);

        // Feature-gated default database expectations
        #[cfg(feature = "postgres")]
        let (expected_db_url, expected_db_backend) = (
            "postgres://postgres:postgres@localhost:5432/status-list",
            DatabaseBackend::Postgres,
        );
        #[cfg(all(not(feature = "postgres"), feature = "sqlite"))]
        let (expected_db_url, expected_db_backend) = ("sqlite::memory:", DatabaseBackend::Sqlite);
        #[cfg(all(not(feature = "postgres"), not(feature = "sqlite"), feature = "mysql"))]
        let (expected_db_url, expected_db_backend) = (
            "mysql://mysql:mysql@localhost:3306/status-list",
            DatabaseBackend::MySql,
        );
        #[cfg(all(
            not(feature = "postgres"),
            not(feature = "sqlite"),
            not(feature = "mysql")
        ))]
        let (expected_db_url, expected_db_backend) = ("memory:", DatabaseBackend::Memory);

        assert_eq!(config.database.url.expose_secret(), expected_db_url);
        assert_eq!(config.database.backend, expected_db_backend);
        assert_eq!(config.redis.uri.expose_secret(), "");
        assert!(!config.redis.require_client_auth);
        #[cfg(feature = "acme")]
        let (expected_strategy, expected_cert_path, expected_key_path) =
            ("acme", Option::<String>::None, Option::<String>::None);
        #[cfg(not(feature = "acme"))]
        let (expected_strategy, expected_cert_path, expected_key_path) =
            ("store", Option::<String>::None, Option::<String>::None);
        assert_eq!(config.server.cert.provisioning_strategy, expected_strategy);
        assert_eq!(config.server.cert.signing_key_cache_ttl, 0);
        assert_eq!(
            config.server.cert.store.certificate_path,
            expected_cert_path
        );
        assert_eq!(config.server.cert.store.signing_key_path, expected_key_path);

        assert_eq!(config.rate_limit.strict_burst_size, 10);
        assert_eq!(config.rate_limit.strict_period_secs, 60);
        assert_eq!(config.rate_limit.permissive_burst_size, 100);
        assert_eq!(config.rate_limit.permissive_period_secs, 60);
        assert_eq!(config.limits.max_body_size_bytes, 2_097_152);
        assert_eq!(config.limits.max_status_index, 100_000);
        assert_eq!(config.limits.max_statuses_per_request, 5_000);
        assert_eq!(config.limits.max_serialized_list_size, 1_048_576);

        assert_eq!(config.database.pool.max_connections, 5);
        assert_eq!(config.database.pool.min_connections, 1);
        assert_eq!(config.database.pool.acquire_timeout_secs, 5);
        assert_eq!(config.database.pool.connect_timeout_secs, 10);
        assert_eq!(config.database.pool.idle_timeout_secs, 600);
        assert_eq!(config.database.pool.max_lifetime_secs, 1800);

        assert_eq!(
            config.telemetry.environment,
            TelemetryEnvironment::Development
        );
        assert_eq!(config.telemetry.sampler_ratio, 1.0);

        // DatabaseBackend helper unit tests
        assert_eq!(DatabaseBackend::default(), DatabaseBackend::Memory);
        assert_eq!(DatabaseBackend::Memory.as_str(), "memory");
        assert_eq!(DatabaseBackend::Postgres.as_str(), "postgres");
        assert_eq!(DatabaseBackend::MySql.as_str(), "mysql");
        assert_eq!(DatabaseBackend::Sqlite.as_str(), "sqlite");
        assert!(DatabaseBackend::Postgres.validate_url_scheme("postgres://user:pass@host:5432/db"));
        assert!(
            DatabaseBackend::Postgres.validate_url_scheme("postgresql://user:pass@host:5432/db")
        );
        assert!(DatabaseBackend::MySql.validate_url_scheme("mysql://user:pass@host:3306/db"));
        assert!(DatabaseBackend::Sqlite.validate_url_scheme("sqlite::memory:"));
        assert!(!DatabaseBackend::MySql.validate_url_scheme("postgres://user:pass@host:5432/db"));

        // 2. Comprehensive environment variable override testing
        let overridden = Config::load_from_overrides(&[
            ("server.host", "0.0.0.0"),
            ("server.port", "5002"),
            ("server.aggregation_uri", "https://example.com/aggregation"),
            (
                "database.url",
                "postgres://user:password@localhost:5432/status-list",
            ),
            ("redis.uri", "rediss://user:password@localhost:6379/redis"),
            ("redis.require_client_auth", "true"),
            ("server.cert.email", "test@gmail.com"),
            (
                "server.cert.acme_directory_url",
                "https://acme-v02.api.letsencrypt.org/directory",
            ),
            ("server.cert.organization", "Test Org"),
            ("server.cert.eku", "1,3,6,1,5,5,7,3,30"),
            ("server.cert.provisioning_strategy", "store"),
            ("server.cert.signing_key_cache_ttl", "0"),
            ("server.cert.store.certificate_path", "/certs/tls.crt"),
            ("server.cert.store.signing_key_path", "/certs/tls.key"),
            ("server.cert.renewal_cron_schedule", "0 0 12 * * *"),
            ("server.cert.dns_challenge_server_url", "http://pebble:8055"),
            ("aws.region", "us-west-2"),
            ("aws.s3_bucket", "my-custom-bucket"),
            ("aws.s3_key_prefix", "status-list/prod"),
            ("cache.ttl", "600"),
            ("cache.max_capacity", "2000"),
            ("status_list.token_exp_secs", "1800"),
            ("status_list.token_ttl_secs", "600"),
            ("rate_limit.strict_burst_size", "3"),
            ("rate_limit.strict_period_secs", "120"),
            ("rate_limit.permissive_burst_size", "500"),
            ("rate_limit.permissive_period_secs", "10"),
            ("limits.max_body_size_bytes", "65536"),
            ("limits.max_status_index", "4096"),
            ("limits.max_statuses_per_request", "256"),
            ("limits.max_serialized_list_size", "32768"),
            ("APP_DATABASE__POOL__MAX_CONNECTIONS", "20"),
            ("APP_DATABASE__POOL__MIN_CONNECTIONS", "2"),
            ("APP_DATABASE__POOL__ACQUIRE_TIMEOUT_SECS", "3"),
            ("APP_DATABASE__POOL__CONNECT_TIMEOUT_SECS", "15"),
            ("APP_DATABASE__POOL__IDLE_TIMEOUT_SECS", "300"),
            ("APP_DATABASE__POOL__MAX_LIFETIME_SECS", "900"),
        ])
        .expect("Failed to load config with overrides");

        assert_eq!(overridden.server.host, "0.0.0.0");
        assert_eq!(overridden.server.port, 5002);
        assert_eq!(
            overridden.server.aggregation_uri.as_deref(),
            Some("https://example.com/aggregation")
        );
        assert_eq!(
            overridden.database.url.expose_secret(),
            "postgres://user:password@localhost:5432/status-list"
        );
        assert_eq!(
            overridden.redis.uri.expose_secret(),
            "rediss://user:password@localhost:6379/redis"
        );
        assert!(overridden.redis.require_client_auth);
        assert_eq!(overridden.server.cert.email, "test@gmail.com");
        assert_eq!(
            overridden.server.cert.acme_directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(overridden.aws.region, "us-west-2");
        assert_eq!(overridden.aws.s3_bucket, "my-custom-bucket");
        assert_eq!(overridden.aws.s3_key_prefix, "status-list/prod");
        assert_eq!(overridden.cache.ttl, 600);
        assert_eq!(overridden.cache.max_capacity, 2000);
        assert_eq!(overridden.status_list.token_exp_secs, 1800);
        assert_eq!(overridden.status_list.token_ttl_secs, 600);
        assert_eq!(overridden.server.cert.renewal_cron_schedule, "0 0 12 * * *");
        assert_eq!(
            overridden.server.cert.dns_challenge_server_url.as_deref(),
            Some("http://pebble:8055")
        );
        assert_eq!(overridden.server.cert.provisioning_strategy, "store");
        assert_eq!(overridden.server.cert.signing_key_cache_ttl, 0);
        assert_eq!(
            overridden.server.cert.store.certificate_path.as_deref(),
            Some("/certs/tls.crt")
        );
        assert_eq!(
            overridden.server.cert.store.signing_key_path.as_deref(),
            Some("/certs/tls.key")
        );
        assert_eq!(overridden.rate_limit.strict_burst_size, 3);
        assert_eq!(overridden.rate_limit.strict_period_secs, 120);
        assert_eq!(overridden.rate_limit.permissive_burst_size, 500);
        assert_eq!(overridden.rate_limit.permissive_period_secs, 10);
        assert_eq!(overridden.limits.max_body_size_bytes, 65_536);
        assert_eq!(overridden.limits.max_status_index, 4_096);
        assert_eq!(overridden.limits.max_statuses_per_request, 256);
        assert_eq!(overridden.limits.max_serialized_list_size, 32_768);
        assert_eq!(overridden.database.pool.max_connections, 20);
        assert_eq!(overridden.database.pool.min_connections, 2);
        assert_eq!(overridden.database.pool.acquire_timeout_secs, 3);
        assert_eq!(overridden.database.pool.connect_timeout_secs, 15);
        assert_eq!(overridden.database.pool.idle_timeout_secs, 300);
        assert_eq!(overridden.database.pool.max_lifetime_secs, 900);

        let split_db_cfg = Config::load_from_overrides(&[
            ("database.backend", "postgres"),
            ("database.host", "postgres.statuslist.svc.cluster.local"),
            ("database.port", "5432"),
            ("database.username", "user@example.com"),
            ("database.password", "secret value"),
            ("database.name", "status/list"),
        ])
        .expect("Failed to load split database config");
        assert_eq!(
            split_db_cfg
                .database
                .resolved_url()
                .expect("split database config should resolve")
                .expose_secret(),
            "postgres://user%40example.com:secret%20value@postgres.statuslist.svc.cluster.local:5432/status%2Flist"
        );

        let missing_db_password = Config::load_from_overrides(&[
            ("database.backend", "postgres"),
            ("database.host", "postgres.statuslist.svc.cluster.local"),
            ("database.username", "postgres"),
            ("database.name", "status-list"),
        ])
        .expect("Failed to load incomplete split database config")
        .database
        .resolved_url()
        .expect_err("missing split database password should fail");
        let missing_db_password = missing_db_password.to_string();
        assert!(missing_db_password.contains("database.password"));
        assert!(!missing_db_password.contains("postgres://"));
        assert!(!missing_db_password.contains("status-list"));

        let split_redis_cfg = Config::load_from_overrides(&[
            ("redis.scheme", "rediss"),
            ("redis.host", "redis.example.com"),
            ("redis.port", "6379"),
            ("redis.password", "redis secret"),
            ("redis.database", "2"),
        ])
        .expect("Failed to load split Redis config");
        assert_eq!(
            split_redis_cfg
                .redis
                .resolved_uri()
                .expect("split Redis config should resolve")
                .expose_secret(),
            "rediss://:redis%20secret@redis.example.com:6379/2"
        );

        let missing_redis_host = Config::load_from_overrides(&[
            ("redis.scheme", "rediss"),
            ("redis.password", "redis secret"),
        ])
        .expect("Failed to load incomplete split Redis config")
        .redis
        .resolved_uri()
        .expect_err("missing split Redis host should fail");
        let missing_redis_host = missing_redis_host.to_string();
        assert!(missing_redis_host.contains("redis.host"));
        assert!(!missing_redis_host.contains("redis secret"));

        // 3. Database backend overrides (MySQL & SQLite)
        let mysql_cfg = Config::load_from_overrides(&[
            ("database.backend", "mysql"),
            (
                "database.url",
                "mysql://user:password@localhost:3306/status-list",
            ),
        ])
        .expect("Failed to load mysql config");
        assert_eq!(mysql_cfg.database.backend, DatabaseBackend::MySql);
        assert_eq!(
            mysql_cfg.database.url.expose_secret(),
            "mysql://user:password@localhost:3306/status-list"
        );

        let sqlite_cfg = Config::load_from_overrides(&[
            ("database.backend", "sqlite"),
            ("database.url", "sqlite::memory:"),
        ])
        .expect("Failed to load sqlite config");
        assert_eq!(sqlite_cfg.database.backend, DatabaseBackend::Sqlite);
        assert_eq!(sqlite_cfg.database.url.expose_secret(), "sqlite::memory:");
    }

    #[test]
    fn test_dns_provider_resolution() {
        // Environment defaults & explicit selection override
        let default_dns = DnsConfig::default();
        assert_eq!(
            default_dns.resolve("production").unwrap().kind(),
            DnsProviderKind::Route53
        );
        assert_eq!(
            default_dns.resolve("development").unwrap().kind(),
            DnsProviderKind::Pebble
        );

        let explicit_dns = DnsConfig {
            provider: Some(DnsProviderKind::Pebble),
            ..Default::default()
        };
        assert_eq!(
            explicit_dns.resolve("production").unwrap().kind(),
            DnsProviderKind::Pebble
        );

        let env_override_cfg =
            Config::load_from_overrides(&[("server.cert.dns.provider", "route53")])
                .expect("Failed to load config");
        assert_eq!(
            env_override_cfg.server.cert.dns.provider,
            Some(DnsProviderKind::Route53)
        );

        // Valid provider settings resolve successfully
        let cloudflare_dns = DnsConfig {
            provider: Some(DnsProviderKind::Cloudflare),
            cloudflare: Some(CloudflareDnsConfig {
                api_token: "token".into(),
            }),
            ..Default::default()
        };
        assert_eq!(
            cloudflare_dns.resolve("production").unwrap().kind(),
            DnsProviderKind::Cloudflare
        );

        let acmedns_helper = |cfg: AcmeDnsConfig| DnsConfig {
            provider: Some(DnsProviderKind::Acmedns),
            acmedns: Some(cfg),
            ..Default::default()
        };
        let valid_acmedns = acmedns_helper(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: Some("user".into()),
            password: Some("password".into()),
            subdomain: Some("subdomain".into()),
            accounts: Default::default(),
        });
        assert_eq!(
            valid_acmedns.resolve("production").unwrap().kind(),
            DnsProviderKind::Acmedns
        );

        let account = AcmeDnsAccount {
            username: "user".into(),
            password: "password".into(),
            subdomain: "subdomain".into(),
        };
        let acmedns_map = acmedns_helper(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: None,
            password: None,
            subdomain: None,
            accounts: [("status.example.com".to_string(), account)].into(),
        });
        assert_eq!(
            acmedns_map.resolve("production").unwrap().kind(),
            DnsProviderKind::Acmedns
        );

        let azure_dns = DnsConfig {
            provider: Some(DnsProviderKind::Azure),
            azure: Some(AzureDnsConfig {
                tenant_id: "tenant".into(),
                client_id: "client".into(),
                client_secret: "secret".into(),
                subscription_id: "sub".into(),
                resource_group: "rg".into(),
            }),
            ..Default::default()
        };
        assert_eq!(
            azure_dns.resolve("production").unwrap().kind(),
            DnsProviderKind::Azure
        );

        let gcloud_path_dns = DnsConfig {
            provider: Some(DnsProviderKind::Gcloud),
            gcloud: Some(GcloudDnsConfig {
                service_account_key: None,
                service_account_key_path: Some("/etc/gcloud/key.json".into()),
            }),
            ..Default::default()
        };
        assert_eq!(
            gcloud_path_dns.resolve("production").unwrap().kind(),
            DnsProviderKind::Gcloud
        );

        // GCloud key source precedence (Inline key vs Path)
        let gcloud_inline_and_path = DnsConfig {
            provider: Some(DnsProviderKind::Gcloud),
            gcloud: Some(GcloudDnsConfig {
                service_account_key: Some("inline-key-json".into()),
                service_account_key_path: Some("/etc/gcloud/key.json".into()),
            }),
            ..Default::default()
        };
        match gcloud_inline_and_path.resolve("production").unwrap() {
            ResolvedDnsProvider::Gcloud(GcloudKeySource::Inline(key)) => {
                assert_eq!(key.expose_secret(), "inline-key-json");
            }
            other => panic!("Expected an inline key source, got {other:?}"),
        }

        let gcloud_empty_inline_uses_path = DnsConfig {
            provider: Some(DnsProviderKind::Gcloud),
            gcloud: Some(GcloudDnsConfig {
                service_account_key: Some("".into()),
                service_account_key_path: Some("/etc/gcloud/key.json".into()),
            }),
            ..Default::default()
        };
        match gcloud_empty_inline_uses_path.resolve("production").unwrap() {
            ResolvedDnsProvider::Gcloud(GcloudKeySource::Path(path)) => {
                assert_eq!(path, "/etc/gcloud/key.json");
            }
            other => panic!("Expected a path key source, got {other:?}"),
        }

        // ACME-DNS accounts JSON parsing from environment overrides
        let server_url = "https://auth.example.org";
        let accounts_json = r#"{"a.example.com": {"username": "u1", "password": "p1", "subdomain": "s1"}, "b.example.com": {"username": "u2", "password": "p2", "subdomain": "s2"}}"#;
        let acme_json_cfg = Config::load_from_overrides(&[
            ("server.cert.dns.acmedns.server_url", server_url),
            ("server.cert.dns.acmedns.accounts", accounts_json),
        ])
        .expect("Failed to load config with acmedns accounts JSON");

        let acmedns = acme_json_cfg
            .server
            .cert
            .dns
            .acmedns
            .expect("acmedns settings");
        assert_eq!(acmedns.server_url, "https://auth.example.org");
        assert!(acmedns.default_account().is_none());
        assert_eq!(acmedns.accounts.len(), 2);
        let b_acct = &acmedns.accounts["b.example.com"];
        assert_eq!(b_acct.username, "u2");
        assert_eq!(b_acct.password.expose_secret(), "p2");
        assert_eq!(b_acct.subdomain, "s2");

        let empty_acme_json_cfg = Config::load_from_overrides(&[
            ("server.cert.dns.acmedns.server_url", server_url),
            ("server.cert.dns.acmedns.accounts", ""),
        ])
        .expect("Failed to load config with empty acmedns accounts var");
        assert!(
            empty_acme_json_cfg
                .server
                .cert
                .dns
                .acmedns
                .unwrap()
                .accounts
                .is_empty()
        );
    }

    #[test]
    fn test_critical_validations() {
        // Invalid database backend configuration
        let invalid_db_res = Config::load_from_overrides(&[
            ("database.backend", "redis"),
            (
                "database.url",
                "postgres://user:password@localhost:5432/status-list",
            ),
        ]);
        assert!(
            invalid_db_res.is_err(),
            "an unknown database backend value should fail config loading"
        );

        // DNS provider missing or empty required settings rejections
        let missing_cloudflare = DnsConfig {
            provider: Some(DnsProviderKind::Cloudflare),
            ..Default::default()
        };
        assert!(
            missing_cloudflare
                .resolve("production")
                .unwrap_err()
                .to_string()
                .contains("dns.cloudflare")
        );

        let empty_cloudflare_token = DnsConfig {
            provider: Some(DnsProviderKind::Cloudflare),
            cloudflare: Some(CloudflareDnsConfig {
                api_token: "".into(),
            }),
            ..Default::default()
        };
        assert!(
            empty_cloudflare_token
                .resolve("production")
                .unwrap_err()
                .to_string()
                .contains("api_token")
        );

        let acmedns_helper = |cfg: AcmeDnsConfig| DnsConfig {
            provider: Some(DnsProviderKind::Acmedns),
            acmedns: Some(cfg),
            ..Default::default()
        };

        let missing_acmedns = DnsConfig {
            provider: Some(DnsProviderKind::Acmedns),
            ..Default::default()
        };
        assert!(
            missing_acmedns
                .resolve("production")
                .unwrap_err()
                .to_string()
                .contains("dns.acmedns")
        );

        let partial_acmedns_default = acmedns_helper(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: Some("user".into()),
            password: None,
            subdomain: None,
            accounts: Default::default(),
        });
        assert!(
            partial_acmedns_default
                .resolve("production")
                .unwrap_err()
                .to_string()
                .contains("must be set together")
        );

        let empty_acmedns_account = acmedns_helper(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: None,
            password: None,
            subdomain: None,
            accounts: Default::default(),
        });
        assert!(
            empty_acmedns_account
                .resolve("production")
                .unwrap_err()
                .to_string()
                .contains("default account")
        );

        let empty_acmedns_url = acmedns_helper(AcmeDnsConfig {
            server_url: " ".into(),
            username: Some("user".into()),
            password: Some("password".into()),
            subdomain: Some("subdomain".into()),
            accounts: Default::default(),
        });
        assert!(
            empty_acmedns_url
                .resolve("production")
                .unwrap_err()
                .to_string()
                .contains("server_url")
        );

        let empty_acmedns_subdomain = acmedns_helper(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: Some("user".into()),
            password: Some("password".into()),
            subdomain: Some("".into()),
            accounts: Default::default(),
        });
        assert!(
            empty_acmedns_subdomain
                .resolve("production")
                .unwrap_err()
                .to_string()
                .contains("must be set together")
        );

        // ACME-DNS unusable account entries validation
        let acmedns_accounts_helper = |accounts: HashMap<String, AcmeDnsAccount>| DnsConfig {
            provider: Some(DnsProviderKind::Acmedns),
            acmedns: Some(AcmeDnsConfig {
                server_url: "https://auth.example.org".into(),
                username: None,
                password: None,
                subdomain: None,
                accounts,
            }),
            ..Default::default()
        };
        let make_acct = |username: &str, subdomain: &str| AcmeDnsAccount {
            username: username.into(),
            password: "password".into(),
            subdomain: subdomain.into(),
        };

        let empty_fields_err = acmedns_accounts_helper(
            [("status.example.com".to_string(), make_acct("", " "))].into(),
        )
        .resolve("production")
        .unwrap_err()
        .to_string();
        assert!(empty_fields_err.contains("status.example.com"));
        assert!(empty_fields_err.contains("username"));
        assert!(empty_fields_err.contains("subdomain"));
        assert!(!empty_fields_err.contains("password"));

        for invalid_key in ["", "  ", "*.", "."] {
            let invalid_key_err = acmedns_accounts_helper(
                [(invalid_key.to_string(), make_acct("user", "sub"))].into(),
            )
            .resolve("production")
            .unwrap_err()
            .to_string();
            assert!(
                invalid_key_err.contains("does not name a domain"),
                "key {invalid_key:?}: {invalid_key_err}"
            );
        }

        let missing_gcloud_key = DnsConfig {
            provider: Some(DnsProviderKind::Gcloud),
            gcloud: Some(GcloudDnsConfig {
                service_account_key: None,
                service_account_key_path: None,
            }),
            ..Default::default()
        };
        assert!(
            missing_gcloud_key
                .resolve("production")
                .unwrap_err()
                .to_string()
                .contains("dns.gcloud")
        );

        let empty_gcloud_keys = DnsConfig {
            provider: Some(DnsProviderKind::Gcloud),
            gcloud: Some(GcloudDnsConfig {
                service_account_key: Some("".into()),
                service_account_key_path: Some(" ".into()),
            }),
            ..Default::default()
        };
        assert!(
            empty_gcloud_keys
                .resolve("production")
                .unwrap_err()
                .to_string()
                .contains("dns.gcloud")
        );

        let azure_helper = |tenant_id: &str, subscription_id: &str| DnsConfig {
            provider: Some(DnsProviderKind::Azure),
            azure: Some(AzureDnsConfig {
                tenant_id: tenant_id.into(),
                client_id: "client".into(),
                client_secret: "secret".into(),
                subscription_id: subscription_id.into(),
                resource_group: "rg".into(),
            }),
            ..Default::default()
        };
        let azure_err = azure_helper("", " ")
            .resolve("production")
            .unwrap_err()
            .to_string();
        assert!(azure_err.contains("tenant_id"));
        assert!(azure_err.contains("subscription_id"));
        assert!(!azure_err.contains("client_id"));

        // Malformed ACME-DNS accounts JSON rejection
        assert!(
            Config::load_from_overrides(&[
                (
                    "server.cert.dns.acmedns.server_url",
                    "https://auth.example.org",
                ),
                (
                    "server.cert.dns.acmedns.accounts",
                    "{\"a.example.com\": not valid json",
                ),
            ])
            .is_err(),
            "malformed accounts JSON must fail config loading"
        );

        // Security check: Default config contains no repository-specific test_data references
        let default_config =
            Config::load_from_overrides(&[]).expect("Failed to load default config");
        if let Some(path) = default_config.server.cert.store.certificate_path.as_deref() {
            assert!(
                !path.contains("test_data"),
                "Default config certificate_path references test_data: {path}"
            );
        }
        if let Some(path) = default_config.server.cert.store.signing_key_path.as_deref() {
            assert!(
                !path.contains("test_data"),
                "Default config signing_key_path references test_data: {path}"
            );
        }
        let db_url = default_config.database.url.expose_secret();
        assert!(
            !db_url.contains("test_data"),
            "Default config database URL references test_data: {db_url}"
        );
        if let Some(key) = default_config.server.cert.store.certificate_key.as_deref() {
            assert!(
                !key.contains("test_data"),
                "Default config certificate_key references test_data: {key}"
            );
        }
        if let Some(key) = default_config.server.cert.store.signing_key_key.as_deref() {
            assert!(
                !key.contains("test_data"),
                "Default config signing_key_key references test_data: {key}"
            );
        }

        // Vault AppRole defaults
        assert_eq!(default_config.vault.addr, "http://localhost:8200");
        assert_eq!(default_config.vault.role_id, "");
        assert!(default_config.vault.secret_id.is_none());
        assert_eq!(default_config.vault.secret_id_path, None);
        assert_eq!(default_config.vault.auth_mount, "approle");
        assert_eq!(default_config.vault.mount, "secret");
        assert_eq!(default_config.vault.path_prefix, "");
        assert_eq!(default_config.vault.namespace, None);
        assert_eq!(default_config.vault.timeout_secs, 30);
        assert!(default_config.vault.resolve_secret_id().is_err());

        // Vault AppRole overrides with inline secret_id
        let overridden_config = Config::load_from_overrides(&[
            ("vault.addr", "http://vault.example.com:8200"),
            ("vault.role_id", "my-role-id"),
            ("vault.secret_id", "my-secret-id"),
            ("vault.auth_mount", "custom-approle"),
            ("vault.mount", "kv-secrets"),
            ("vault.path_prefix", "services/status-list"),
            ("vault.namespace", "tenant-1"),
            ("vault.timeout_secs", "15"),
        ])
        .expect("Failed to load overridden config");

        assert_eq!(
            overridden_config.vault.addr,
            "http://vault.example.com:8200"
        );
        assert_eq!(overridden_config.vault.role_id, "my-role-id");
        assert_eq!(
            overridden_config
                .vault
                .resolve_secret_id()
                .expect("failed to resolve secret_id")
                .expose_secret(),
            "my-secret-id"
        );
        assert_eq!(overridden_config.vault.auth_mount, "custom-approle");
        assert_eq!(overridden_config.vault.mount, "kv-secrets");
        assert_eq!(overridden_config.vault.path_prefix, "services/status-list");
        assert_eq!(
            overridden_config.vault.namespace,
            Some("tenant-1".to_string())
        );
        assert_eq!(overridden_config.vault.timeout_secs, 15);

        // Vault AppRole overrides with secret_id_path
        let secret_file = std::env::temp_dir().join(format!(
            "vault_secret_id_test_{}.txt",
            time::OffsetDateTime::now_utc().nanosecond()
        ));
        std::fs::write(&secret_file, "  file-secret-id-value \n").expect("write secret file");

        let file_auth_config = Config::load_from_overrides(&[
            ("vault.role_id", "my-file-role"),
            ("vault.secret_id_path", secret_file.to_str().unwrap()),
        ])
        .expect("Failed to load file auth config");

        assert_eq!(
            file_auth_config
                .vault
                .resolve_secret_id()
                .expect("failed to resolve secret_id from path")
                .expose_secret(),
            "file-secret-id-value"
        );
        let _ = std::fs::remove_file(&secret_file);
    }
}
