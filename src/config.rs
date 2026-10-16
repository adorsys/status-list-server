use std::path::PathBuf;
use std::{collections::HashMap, fmt, marker::PhantomData};

use config::builder::DefaultState;
use config::{Config as ConfigLib, ConfigBuilder, ConfigError, Environment};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer};
use serde_aux::field_attributes::deserialize_vec_from_string_or_vec;
use url::Url;

use crate::domain::models::status_list::AGGREGATION_DEFAULT_LIMIT;

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

    pub fn expected_scheme_description(&self) -> &'static str {
        self.scheme().description
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseBackend::Memory => "memory",
            DatabaseBackend::Postgres => "postgres",
            DatabaseBackend::MySql => "mysql",
            DatabaseBackend::Sqlite => "sqlite",
        }
    }

    pub fn validate_url_scheme(&self, url: &str) -> bool {
        self.scheme()
            .prefixes
            .iter()
            .any(|prefix| url.starts_with(prefix))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheBackend {
    #[default]
    Memory,
    Redis,
}

impl CacheBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            CacheBackend::Memory => "memory",
            CacheBackend::Redis => "redis",
        }
    }
}

pub const ENV_PRODUCTION: &str = "production";
pub const ENV_DEVELOPMENT: &str = "development";

/// Use this instead of reading `APP_ENV` directly so callers agree with config.
pub fn normalize_app_env() -> &'static str {
    match classify_app_env(&std::env::var("APP_ENV").unwrap_or_default()) {
        TelemetryEnvironment::Production => ENV_PRODUCTION,
        TelemetryEnvironment::Development => ENV_DEVELOPMENT,
    }
}

/// The only place that decides which `APP_ENV` spellings mean production.
pub fn classify_app_env(raw: &str) -> TelemetryEnvironment {
    match raw.trim().to_ascii_lowercase().as_str() {
        "production" | "prod" => TelemetryEnvironment::Production,
        _ => TelemetryEnvironment::Development,
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub aws: AwsConfig,
    pub vault: VaultConfig,
    pub gcp_secret_manager: GcpSecretManagerConfig,
    pub azure_keyvault: AzureKeyVaultConfig,
    pub cache: CacheConfig,
    pub token_bytes_cache: TokenBytesCacheConfig,
    pub status_list: StatusListConfig,
    pub management_auth: ManagementAuthConfig,
    pub rate_limit: RateLimitConfig,
    pub limits: LimitsConfig,
    pub telemetry: TelemetryConfig,
    pub watcher: WatcherConfig,
}

/// Watches mounted secret files for rotation.
#[derive(Debug, Clone, Deserialize)]
pub struct WatcherConfig {
    pub poll_interval_secs: u64,
}

/// Strict tier covers writes, permissive covers reads.
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub strict_burst_size: u32,
    pub strict_period_secs: u64,
    pub permissive_burst_size: u32,
    pub permissive_period_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    pub max_body_size_bytes: usize,
    pub max_status_index: i32,
    pub max_statuses_per_request: usize,
    pub max_serialized_list_size: usize,
    pub max_lists_per_issuer: u64,
    /// Lets pods start with the quota off while upgrading from a release without it.
    pub list_quota_transition: bool,
}

impl LimitsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_lists_per_issuer == 0 {
            return Err(ConfigError::Message(
                "limits.max_lists_per_issuer must be greater than 0".to_string(),
            ));
        }
        if self.max_lists_per_issuer > AGGREGATION_DEFAULT_LIMIT as u64 {
            return Err(ConfigError::Message(format!(
                "limits.max_lists_per_issuer ({}) must not exceed AGGREGATION_DEFAULT_LIMIT \
                 ({AGGREGATION_DEFAULT_LIMIT}), the aggregation page size: an issuer's \
                 aggregation would no longer fit in one response, and clients that do not page \
                 would silently see part of it",
                self.max_lists_per_issuer
            )));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagementAuthConfig {
    pub leeway_secs: u64,
    /// Checked as `exp - iat`.
    pub max_token_lifetime_secs: u64,
    /// Empty means the `aud` claim is not required.
    #[serde(deserialize_with = "deserialize_audience_list")]
    pub audiences: Vec<String>,
}

impl ManagementAuthConfig {
    fn validate(&self, environment: TelemetryEnvironment) -> Result<(), ConfigError> {
        if self.max_token_lifetime_secs == 0 {
            return Err(ConfigError::Message(
                "management_auth.max_token_lifetime_secs must be greater than 0".to_string(),
            ));
        }

        if self.audiences.is_empty() {
            if environment.is_production() {
                return Err(ConfigError::Message(
                    "management_auth.audiences must not be empty in production".to_string(),
                ));
            }
            tracing::warn!(
                "management_auth.audiences is empty; audience validation is disabled in development"
            );
        }

        Ok(())
    }
}

fn deserialize_audience_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = deserialize_vec_from_string_or_vec(deserializer)?;
    Ok(values
        .into_iter()
        .map(|value: String| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect())
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    /// Development logs to stdout, production exports over OTLP.
    pub environment: TelemetryEnvironment,
    /// OTLP gRPC endpoint, only used in production.
    pub otlp_endpoint: String,
    #[serde(deserialize_with = "deserialize_sampler_ratio")]
    pub sampler_ratio: f64,
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
        // Stricter than `classify_app_env`: reject anything that isn't a known dev spelling.
        match classify_app_env(&raw) {
            Self::Production => Ok(Self::Production),
            Self::Development => match raw.trim().to_ascii_lowercase().as_str() {
                "development" | "dev" => Ok(Self::Development),
                other => Err(serde::de::Error::unknown_variant(
                    other,
                    &["development", "dev", "production", "prod"],
                )),
            },
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

pub const REPOSITORY_URL: &str = "https://github.com/adorsys/status-list-server";

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub domain: String,
    pub port: u16,
    pub management: ListenerConfig,
    pub admin: ListenerConfig,
    pub links: LinksConfig,
    pub cert: CertConfig,
    pub enable_metrics: bool,
    pub aggregation_uri: Option<String>,
    /// Defaults to `https://{domain}/api/v1` when unset.
    #[serde(default)]
    pub public_base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinksConfig {
    pub documentation: String,
    #[serde(default, deserialize_with = "deserialize_optional_uri_string")]
    pub portal: Option<String>,
}

impl ServerConfig {
    pub fn duplicate_listener_pair(&self) -> Option<(&'static str, &'static str)> {
        let listeners: &[(&'static str, &str, u16)] = &[
            ("server.host:server.port", &self.host, self.port),
            (
                "server.management.host:server.management.port",
                &self.management.host,
                self.management.port,
            ),
            (
                "server.admin.host:server.admin.port",
                &self.admin.host,
                self.admin.port,
            ),
        ];
        for (i, (name_a, host_a, port_a)) in listeners.iter().enumerate() {
            for (name_b, host_b, port_b) in listeners.iter().skip(i + 1) {
                // Port 0 binds a distinct ephemeral port each time, so it never clashes.
                if *port_a == 0 && *port_b == 0 {
                    continue;
                }
                if port_a == port_b && hosts_resolve_equal(host_a, host_b) {
                    return Some((name_a, name_b));
                }
            }
        }
        None
    }

    pub fn has_duplicate_listener(&self) -> bool {
        self.duplicate_listener_pair().is_some()
    }
}

impl ServerConfig {
    /// Normalized form of the base URL; this exact value is signed into `sub`.
    pub fn resolved_public_base_url(&self) -> String {
        url::Url::parse(&self.raw_resolved_public_base_url())
            .expect("resolved public base URL was validated at config load")
            .to_string()
    }

    /// Unnormalized, so validation sees the trailing slash the operator typed.
    fn raw_resolved_public_base_url(&self) -> String {
        match trim_non_empty(self.public_base_url.as_deref()) {
            Some(base) => base.to_string(),
            None => format!(
                "https://{}{API_V1_PREFIX}",
                url_authority_host(&self.domain)
            ),
        }
    }
}

fn url_authority_host(domain: &str) -> String {
    if domain.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{domain}]")
    } else {
        domain.to_string()
    }
}

fn hosts_resolve_equal(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    let ips_a = host_bind_ips(a);
    let ips_b = host_bind_ips(b);
    if ips_a.is_empty() || ips_b.is_empty() {
        return false;
    }
    let wildcard_a = ips_a.iter().any(|ip| ip.is_unspecified());
    let wildcard_b = ips_b.iter().any(|ip| ip.is_unspecified());
    if wildcard_a || wildcard_b {
        // A wildcard bind covers every interface in its address family.
        return ips_a
            .iter()
            .any(|a| ips_b.iter().any(|b| a.is_ipv4() == b.is_ipv4()));
    }
    ips_a.iter().any(|ip_a| ips_b.contains(ip_a))
}

/// Uses the system resolver; a host that doesn't resolve yields no addresses.
fn host_bind_ips(host: &str) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![ip];
    }
    (host, 0u16)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// `url::Host::parse` accepts leading or trailing dots and hyphens, so we reject those ourselves.
fn validate_server_domain(domain: &str) -> Result<(), ConfigError> {
    // `Host::parse` rejects bare IPv6 like `::1`, so check that form separately.
    let parsed_as_host = url::Host::parse(domain).is_ok() || is_ipv6_host(domain);

    let unhygienic = domain.starts_with('-')
        || domain.ends_with('-')
        || domain.starts_with('.')
        || domain.trim_end_matches('.').is_empty();

    if !parsed_as_host || unhygienic {
        return Err(ConfigError::Message(
            "Invalid server.domain: expected a bare hostname or IP address without scheme, port, path, userinfo, query, or fragment".to_string(),
        ));
    }

    Ok(())
}

/// Public and management routes mount under this prefix.
/// The default `public_base_url` includes it so the `sub` URI resolves.
pub const API_V1_PREFIX: &str = "/api/v1";

/// Any path is allowed so the server can sit behind a path-prefixing proxy.
fn validate_public_base_url(base_url: &str) -> Result<(), ConfigError> {
    let parsed = url::Url::parse(base_url).map_err(|err| {
        // Don't echo the value: it may hold a password in the userinfo.
        ConfigError::Message(format!(
            "Invalid server.public_base_url: not a valid URL ({err})"
        ))
    })?;
    if parsed.scheme() != "https" {
        return Err(ConfigError::Message(
            "Invalid server.public_base_url: scheme must be https".to_string(),
        ));
    }
    if parsed.host_str().is_none() {
        return Err(ConfigError::Message(
            "Invalid server.public_base_url: expected an absolute URL with a host".to_string(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ConfigError::Message(
            "Invalid server.public_base_url: must not contain userinfo (username or password)"
                .to_string(),
        ));
    }
    if parsed.query().is_some() {
        return Err(ConfigError::Message(
            "Invalid server.public_base_url: must not contain a query".to_string(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(ConfigError::Message(
            "Invalid server.public_base_url: must not contain a fragment".to_string(),
        ));
    }
    if base_url.ends_with('/') {
        return Err(ConfigError::Message(
            "Invalid server.public_base_url: must not end with a trailing slash".to_string(),
        ));
    }
    Ok(())
}

impl ServerConfig {
    /// Must be `{public_base_url}/aggregation`, since tokens append `/<aggregation_id>` to it.
    pub fn aggregation_uri(
        &self,
        environment: TelemetryEnvironment,
    ) -> Result<Option<Url>, ConfigError> {
        let Some(uri) = trim_non_empty(self.aggregation_uri.as_deref()) else {
            return Ok(None);
        };
        let uri = Url::parse(uri).map_err(|e| {
            ConfigError::Message(format!("server.aggregation_uri is not a valid URL: {e}"))
        })?;
        match uri.scheme() {
            "https" => {}
            "http" if !environment.is_production() => {}
            "http" => {
                return Err(ConfigError::Message(
                    "server.aggregation_uri must use https in production".to_string(),
                ));
            }
            _ => {
                return Err(ConfigError::Message(
                    "server.aggregation_uri must be an http or https URL".to_string(),
                ));
            }
        }
        if !uri.username().is_empty() || uri.password().is_some() {
            return Err(ConfigError::Message(
                "server.aggregation_uri must not contain credentials".to_string(),
            ));
        }
        // Routed under the same base path as `sub`, which may carry a proxy prefix.
        let base = Url::parse(&self.resolved_public_base_url())
            .expect("the resolved public base URL is a valid URL");
        let route = format!("{}/aggregation", base.path().trim_end_matches('/'));
        if uri.path() != route {
            return Err(ConfigError::Message(format!(
                "server.aggregation_uri path '{}' does not match the aggregation route '{route}'",
                uri.path()
            )));
        }
        if uri.query().is_some() || uri.fragment().is_some() {
            return Err(ConfigError::Message(
                "server.aggregation_uri must not have a query or fragment".to_string(),
            ));
        }
        Ok(Some(uri))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertConfig {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(deserialize_with = "deserialize_vec_from_string_or_vec")]
    #[serde(default)]
    pub eku: Vec<u64>,
    pub acme_directory_url: String,
    /// Seconds; 0 disables the cache.
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
    pub certificate: Option<String>,
    #[serde(default)]
    pub signing_key: Option<String>,
}

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

/// Settings here were already validated by `DnsConfig::resolve`.
#[derive(Debug, Clone, Copy)]
pub enum ResolvedDnsProvider<'a> {
    /// Uses the ambient AWS credentials.
    Route53,
    Cloudflare(&'a CloudflareDnsConfig),
    Gcloud(&'a GcloudDnsConfig),
    Azure(&'a AzureDnsConfig),
    Acmedns(&'a AcmeDnsConfig),
    /// Dev only; its URL lives outside `DnsConfig`.
    Pebble,
}

impl ResolvedDnsProvider<'_> {
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
    /// Defaults to Route53 in production and Pebble in development.
    #[serde(default)]
    pub provider: Option<DnsProviderKind>,
    pub cloudflare: Option<CloudflareDnsConfig>,
    pub gcloud: Option<GcloudDnsConfig>,
    pub azure: Option<AzureDnsConfig>,
    pub acmedns: Option<AcmeDnsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GcloudDnsConfig {
    pub project_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AzureDnsConfig {
    pub subscription_id: String,
    pub resource_group: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CloudflareDnsConfig {
    /// API token with Zone:Read and DNS:Edit permissions
    pub api_token: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeDnsConfig {
    pub server_url: String,
    /// Fallback account for domains not in `accounts`; set all three or none.
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub subdomain: Option<String>,
    /// One account per domain, since an ACME-DNS account only holds two TXT values.
    #[serde(default, deserialize_with = "deserialize_map_from_string_or_map")]
    pub accounts: HashMap<String, AcmeDnsAccount>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeDnsAccount {
    pub username: String,
    pub password: SecretString,
    pub subdomain: String,
}

/// An env var set to "" counts as unset.
fn non_empty(value: &Option<String>) -> Option<&String> {
    value.as_ref().filter(|v| !v.trim().is_empty())
}

impl AcmeDnsConfig {
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
        // Fail at startup instead of with a 401 at the first renewal.
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

/// Domain keys can't be spelled in env var names, so a JSON string is accepted too.
fn deserialize_map_from_string_or_map<'de, D, V>(
    deserializer: D,
) -> Result<HashMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: serde::de::DeserializeOwned,
{
    // Visitor instead of an untagged enum so inner errors aren't swallowed.
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
    fn validate(&self) -> Result<(), ConfigError> {
        let empty: Vec<&str> = [
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

impl GcloudDnsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.project_id.trim().is_empty() {
            return Err(ConfigError::Message(
                "Google Cloud DNS settings have an empty project_id".to_string(),
            ));
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
    /// Keep this free of I/O; network checks belong to the boot path.
    pub fn resolve(&self, app_env: &str) -> Result<ResolvedDnsProvider<'_>, ConfigError> {
        let kind = self
            .provider
            .unwrap_or(if classify_app_env(app_env).is_production() {
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
                let gcloud = self.gcloud.as_ref().ok_or_else(|| missing("dns.gcloud"))?;
                gcloud.validate()?;
                ResolvedDnsProvider::Gcloud(gcloud)
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

/// Size `max_connections` as floor(db max_connections / replicas) - 5.
#[derive(Debug, Clone, Deserialize)]
pub struct DatabasePoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Prefer the split fields on Kubernetes so no full credential URL lands in the pod spec.
    pub url: Option<SecretString>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<SecretString>,
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    #[serde(default)]
    pub name: Option<String>,
    /// Extra driver or TLS params, e.g. `sslmode=verify-full&sslrootcert=/certs/ca.crt`.
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub backend: DatabaseBackend,
    pub pool: DatabasePoolConfig,
}

fn trim_non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// Treats "" (what an empty env var becomes) as `None`, so `portal` never breaks `format: uri`.
fn deserialize_optional_uri_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Option<String> = Option::deserialize(deserializer)?;
    Ok(raw.and_then(|s| {
        let trimmed = s.trim().to_owned();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }))
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

fn format_database_url_host(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn is_ipv6_host(host: &str) -> bool {
    host.parse::<std::net::Ipv6Addr>().is_ok()
        || host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .is_some_and(|value| value.parse::<std::net::Ipv6Addr>().is_ok())
}

fn required_config_field<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str, ConfigError> {
    trim_non_empty(value)
        .ok_or_else(|| ConfigError::Message(format!("Missing required config field: {field}")))
}

fn required_secret_field<'a>(
    value: Option<&'a SecretString>,
    field: &str,
) -> Result<&'a str, ConfigError> {
    value
        .map(SecretString::expose_secret)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ConfigError::Message(format!("Missing required config field: {field}")))
}

fn validate_database_query(query: &str) -> Result<(), ConfigError> {
    let query = query.trim_start_matches('?');
    if query.is_empty() {
        return Ok(());
    }

    for (key, _) in url::form_urlencoded::parse(query.as_bytes()) {
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(ConfigError::Message(
                "Invalid database.query: query parameter keys must be non-empty and contain only ASCII letters, digits, '.', '_' or '-'".to_string(),
            ));
        }

        let key = key.to_ascii_lowercase();
        if key.contains("password")
            || key.contains("passwd")
            || key.contains("secret")
            || key.contains("token")
            || key == "user"
            || key == "username"
        {
            return Err(ConfigError::Message(format!(
                "Invalid database.query: credential-like query parameter key '{key}' is not allowed"
            )));
        }
    }

    Ok(())
}

fn validate_database_host(host: &str) -> Result<(), ConfigError> {
    if is_ipv6_host(host) {
        return Ok(());
    }

    let invalid = host.chars().any(char::is_whitespace)
        || host.contains('/')
        || host.contains('@')
        || host.contains('?')
        || host.contains('#')
        || host.contains(':')
        || host.contains('\\')
        || host.starts_with('-')
        || host.ends_with('-')
        || host.starts_with('.')
        || host.trim_end_matches('.').is_empty();

    if invalid {
        return Err(ConfigError::Message(
            "Invalid database.host: expected a hostname or IP address without scheme, port, path, userinfo, query, or fragment".to_string(),
        ));
    }

    Ok(())
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
                .is_some_and(|value| !value.expose_secret().is_empty())
            || self
                .password_file
                .as_ref()
                .is_some_and(|value| !value.as_os_str().is_empty())
            || self
                .name
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
    }

    pub fn resolved_url(&self) -> Result<SecretString, ConfigError> {
        if !self.has_split_connection_fields() {
            return self.url.clone().ok_or_else(|| {
                ConfigError::Message(
                    "Missing required config field: database.url or split database fields"
                        .to_string(),
                )
            });
        }
        if self.url.is_some() {
            return Err(ConfigError::Message(
                "Ambiguous database configuration: use either database.url or split database fields, not both".to_string(),
            ));
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
        validate_database_host(host)?;
        let url_host = format_database_url_host(host);
        let username = required_config_field(self.username.as_deref(), "database.username")?;
        let password = required_secret_field(self.password.as_ref(), "database.password")?;
        let password = password.trim();
        let name = required_config_field(self.name.as_deref(), "database.name")?;
        let port = self.port.unwrap_or(default_port);
        let query = trim_non_empty(self.query.as_deref())
            .map(|query| {
                validate_database_query(query)?;
                Ok(format!("?{}", query.trim_start_matches('?')))
            })
            .transpose()?
            .unwrap_or_default();

        Ok(SecretString::from(format!(
            "{scheme}://{}:{}@{url_host}:{port}/{}{query}",
            encode_url_part(username),
            encode_url_part(password),
            encode_url_part(name)
        )))
    }

    pub async fn load_resolved_url(&self) -> Result<SecretString, ConfigError> {
        let Some(path) = &self.password_file else {
            return self.resolved_url();
        };
        let password = tokio::fs::read_to_string(path).await.map_err(|err| {
            ConfigError::Message(format!(
                "Failed to read database.password_file '{}': {err}",
                path.display()
            ))
        })?;
        let mut config = self.clone();
        config.password = Some(SecretString::from(password.trim().to_string()));
        config.resolved_url()
    }

    pub fn redacted_target(&self) -> String {
        match (
            self.has_split_connection_fields(),
            self.backend,
            trim_non_empty(self.host.as_deref()),
            trim_non_empty(self.name.as_deref()),
        ) {
            (true, DatabaseBackend::Postgres, Some(host), Some(name)) => format!(
                "backend=postgres, host={}, port={}, database={}",
                host,
                self.port.unwrap_or(5432),
                name
            ),
            (true, DatabaseBackend::MySql, Some(host), Some(name)) => format!(
                "backend=mysql, host={}, port={}, database={}",
                host,
                self.port.unwrap_or(3306),
                name
            ),
            _ => format!("backend={}", self.backend.as_str()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsConfig {
    pub region: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultAuthMethod {
    #[default]
    Approle,
    Kubernetes,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VaultConfig {
    #[serde(default)]
    pub auth_method: VaultAuthMethod,
    pub addr: String,
    pub role_id: String,
    /// Keep out of config files; inject it via env or a secrets mount.
    #[serde(default)]
    pub secret_id: Option<SecretString>,
    #[serde(default)]
    pub secret_id_path: Option<PathBuf>,
    pub auth_mount: String,
    #[serde(default)]
    pub k8s_role: Option<String>,
    pub k8s_token_path: PathBuf,
    pub k8s_auth_mount: String,
    /// Must be a KV v2 engine.
    pub mount: String,
    pub path_prefix: String,
    #[serde(default)]
    pub namespace: Option<String>,
    pub timeout_secs: u64,
}

impl VaultConfig {
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
    pub project_id: String,
    #[serde(default)]
    pub service_account_key: Option<SecretString>,
    #[serde(default)]
    pub service_account_key_path: Option<String>,
    /// Override for regional endpoints, VPC-SC or the emulator.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Emulator only.
    #[serde(default)]
    pub allow_anonymous_credentials: bool,
    /// Seconds; 0 disables caching.
    pub secrets_cache_ttl: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AzureKeyVaultConfig {
    #[serde(default)]
    pub vault_url: Option<url::Url>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<SecretString>,
    /// Seconds; 0 disables caching.
    pub secrets_cache_ttl: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default)]
    pub backend: CacheBackend,
    /// Seconds; 0 disables caching.
    pub ttl: u64,
    pub max_capacity: u64,
    #[serde(default)]
    pub host: Option<String>,
    /// Defaults to 6379, or 6380 with TLS.
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<SecretString>,
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    #[serde(default)]
    pub database: Option<u8>,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default = "default_cache_key_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_cache_response_timeout_ms")]
    pub response_timeout_ms: u64,
    #[serde(default = "default_cache_connection_timeout_ms")]
    pub connection_timeout_ms: u64,
    #[serde(default = "default_cache_reconnect_cooldown_ms")]
    pub reconnect_cooldown_ms: u64,
}

fn default_cache_key_prefix() -> String {
    "status-list-server:status-list:".to_string()
}

fn default_cache_response_timeout_ms() -> u64 {
    250
}

fn default_cache_connection_timeout_ms() -> u64 {
    250
}

fn default_cache_reconnect_cooldown_ms() -> u64 {
    250
}

impl CacheConfig {
    fn validate(&self, environment: TelemetryEnvironment) -> Result<(), ConfigError> {
        if self.password.is_some() && self.password_file.is_some() {
            return Err(ConfigError::Message(
                "Ambiguous Redis cache configuration: use either cache.password or cache.password_file, not both".to_string(),
            ));
        }
        if self.backend == CacheBackend::Redis {
            if environment.is_production() {
                if !self.tls {
                    return Err(ConfigError::Message(
                        "cache.backend=redis requires cache.tls=true in production".to_string(),
                    ));
                }
                if self.password.is_none() && self.password_file.is_none() {
                    return Err(ConfigError::Message(
                        "cache.backend=redis requires cache.password or cache.password_file in production".to_string(),
                    ));
                }
            }
            if let Some(ca_file) = &self.ca_file {
                if !self.tls {
                    return Err(ConfigError::Message(
                        "cache.ca_file requires cache.tls=true".to_string(),
                    ));
                }
                if ca_file.as_os_str().is_empty() {
                    return Err(ConfigError::Message(
                        "cache.ca_file must not be empty".to_string(),
                    ));
                }
            }
            if trim_non_empty(Some(&self.key_prefix)).is_none() {
                return Err(ConfigError::Message(
                    "cache.key_prefix must not be empty".to_string(),
                ));
            }
            if self.response_timeout_ms == 0
                || self.connection_timeout_ms == 0
                || self.reconnect_cooldown_ms == 0
            {
                return Err(ConfigError::Message(
                    "cache Redis timeout values must be greater than zero".to_string(),
                ));
            }
            if self.password_file.is_some() {
                let mut config = self.clone();
                config.password = Some(SecretString::from("placeholder".to_string()));
                config.resolved_redis_url()?;
            } else {
                self.resolved_redis_url()?;
            }
        }
        Ok(())
    }

    pub fn resolved_redis_url(&self) -> Result<SecretString, ConfigError> {
        let host = required_config_field(self.host.as_deref(), "cache.host")?;
        validate_database_host(host)?;
        let url_host = format_database_url_host(host);
        let scheme = if self.tls { "rediss" } else { "redis" };
        let port = self.port.unwrap_or(if self.tls { 6380 } else { 6379 });
        let database = self.database.unwrap_or(0);
        let password = self
            .password
            .as_ref()
            .map(SecretString::expose_secret)
            .filter(|value| !value.is_empty());

        let auth = match (trim_non_empty(self.username.as_deref()), password) {
            (Some(username), Some(password)) => {
                format!(
                    "{}:{}@",
                    encode_url_part(username),
                    encode_url_part(password.trim())
                )
            }
            (None, Some(password)) => format!(":{}@", encode_url_part(password.trim())),
            (Some(username), None) => {
                return Err(ConfigError::Message(format!(
                    "Missing required config field: cache.password for Redis username '{}'",
                    username
                )));
            }
            (None, None) => String::new(),
        };

        Ok(SecretString::from(format!(
            "{scheme}://{auth}{url_host}:{port}/{database}"
        )))
    }

    pub async fn load_resolved_redis_url(&self) -> Result<SecretString, ConfigError> {
        let Some(path) = &self.password_file else {
            return self.resolved_redis_url();
        };
        let password = tokio::fs::read_to_string(path).await.map_err(|err| {
            ConfigError::Message(format!(
                "Failed to read cache.password_file '{}': {err}",
                path.display()
            ))
        })?;
        let mut config = self.clone();
        config.password = Some(SecretString::from(password.trim().to_string()));
        config.resolved_redis_url()
    }

    pub fn redacted_redis_target(&self) -> String {
        match trim_non_empty(self.host.as_deref()) {
            Some(host) => format!(
                "backend=redis, host={}, port={}, database={}, tls={}",
                host,
                self.port.unwrap_or(if self.tls { 6380 } else { 6379 }),
                self.database.unwrap_or(0),
                self.tls
            ),
            None => "backend=redis, host=<unset>".to_string(),
        }
    }
}

/// Per-replica cache of signed token bytes, not shared across pods.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenBytesCacheConfig {
    /// Bytes; 0 disables the cache.
    pub max_capacity: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatusListConfig {
    pub token_exp_secs: u64,
    pub token_ttl_secs: u64,
    /// 0 disables snapshots, and with them `?time=` lookups.
    /// `history_retention_secs` is a deprecated alias.
    #[serde(alias = "history_retention_secs")]
    pub snapshot_retention_secs: u64,
}

/// Ceiling from draft-21 §11.5 so tokens can't effectively never expire.
pub const MAX_TOKEN_LIFETIME_SECS: u64 = 365 * 24 * 3600;

impl StatusListConfig {
    /// Static checks only; `checked_add` catches overflow at issuance.
    fn validate(&self) -> Result<(), ConfigError> {
        validate_positive_secs("APP_STATUS_LIST__TOKEN_TTL_SECS", self.token_ttl_secs)?;
        validate_positive_secs("APP_STATUS_LIST__TOKEN_EXP_SECS", self.token_exp_secs)?;
        if self.token_ttl_secs >= self.token_exp_secs {
            return Err(ConfigError::Message(format!(
                "APP_STATUS_LIST__TOKEN_TTL_SECS ({}) must be less than \
                 APP_STATUS_LIST__TOKEN_EXP_SECS ({}); a ttl >= exp leaves no usable token lifetime",
                self.token_ttl_secs, self.token_exp_secs
            )));
        }
        Ok(())
    }
}

fn validate_positive_secs(env_var: &str, secs: u64) -> Result<(), ConfigError> {
    if secs == 0 {
        return Err(ConfigError::Message(format!(
            "{env_var} must be a positive number (greater than 0)"
        )));
    }
    if secs > MAX_TOKEN_LIFETIME_SECS {
        return Err(ConfigError::Message(format!(
            "{env_var} ({secs}) exceeds the maximum supported token lifetime \
             (MAX_TOKEN_LIFETIME_SECS = {MAX_TOKEN_LIFETIME_SECS} seconds, one year); \
             larger values would effectively never expire and let revoked credentials look valid"
        )));
    }
    Ok(())
}

impl Config {
    /// Env vars override the defaults, e.g. `APP_SERVER__PORT` sets `server.port`.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_overrides(&[])
    }

    pub fn load_from_overrides(overrides: &[(&str, &str)]) -> Result<Self, ConfigError> {
        let mut builder = base_builder()?.add_source(
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
        if let Some(host) = trim_non_empty(config.database.host.as_deref()) {
            validate_database_host(host)?;
        }
        if let Some(query) = trim_non_empty(config.database.query.as_deref()) {
            validate_database_query(query)?;
        }
        validate_server_domain(&config.server.domain)?;
        if let Some((name_a, name_b)) = config.server.duplicate_listener_pair() {
            return Err(ConfigError::Message(format!(
                "Duplicate listener: {name_a} and {name_b} resolve to the same host:port, which \
                 would collapse the public/management/admin network boundary. Give each listener \
                 a distinct port (or host)."
            )));
        }

        // Check the resolved URL so a bad derived default also fails at startup.
        validate_public_base_url(&config.server.raw_resolved_public_base_url())?;
        if let Some(portal) = trim_non_empty(config.server.links.portal.as_deref()) {
            url::Url::parse(portal).map_err(|err| {
                ConfigError::Message(format!(
                    "Invalid server.links.portal: not a valid URI ({err})"
                ))
            })?;
        }
        config.cache.validate(config.telemetry.environment)?;
        config
            .management_auth
            .validate(config.telemetry.environment)?;
        config.status_list.validate()?;
        config.limits.validate()?;
        config
            .server
            .aggregation_uri(config.telemetry.environment)?;
        Ok(config)
    }
}

fn base_builder() -> Result<ConfigBuilder<DefaultState>, ConfigError> {
    #[cfg(feature = "postgres")]
    let default_db_backend = "postgres";
    #[cfg(all(not(feature = "postgres"), feature = "sqlite"))]
    let default_db_backend = "sqlite";
    #[cfg(all(not(feature = "postgres"), not(feature = "sqlite"), feature = "mysql"))]
    let default_db_backend = "mysql";
    #[cfg(all(
        not(feature = "postgres"),
        not(feature = "sqlite"),
        not(feature = "mysql")
    ))]
    let default_db_backend = "memory";

    let telemetry_environment = normalize_app_env();

    let builder = ConfigLib::builder()
        .set_default("server.host", "localhost")?
        .set_default("server.domain", "localhost")?
        .set_default("server.port", 8000)?
        .set_default("server.management.host", "localhost")?
        .set_default("server.management.port", 8001)?
        .set_default("server.admin.host", "localhost")?
        .set_default("server.admin.port", 8002)?
        .set_default("server.links.documentation", REPOSITORY_URL)?
        .set_default("server.links.portal", Option::<String>::None)?
        .set_default("server.enable_metrics", false)?
        .set_default("server.aggregation_uri", Option::<String>::None)?
        .set_default("database.url", Option::<String>::None)?
        .set_default("database.password_file", Option::<String>::None)?
        .set_default("database.backend", default_db_backend)?
        .set_default("database.pool.max_connections", 5u32)?
        .set_default("database.pool.min_connections", 1u32)?
        .set_default("database.pool.acquire_timeout_secs", 5u64)?
        .set_default("database.pool.connect_timeout_secs", 10u64)?
        .set_default("database.pool.idle_timeout_secs", 600u64)?
        .set_default("database.pool.max_lifetime_secs", 1800u64)?
        .set_default("server.cert.email", "admin@example.com")?
        .set_default("server.cert.eku", vec![1, 3, 6, 1, 5, 5, 7, 3, 30])?
        .set_default("server.cert.organization", "adorsys GmbH & CO KG")?
        .set_default(
            "server.cert.acme_directory_url",
            "https://acme-v02.api.letsencrypt.org/directory",
        )?
        .set_default("server.cert.signing_key_cache_ttl", 0)?
        .set_default("server.cert.renewal_cron_schedule", "0 0 0 * * *")?
        .set_default("server.cert.store.certificate_path", Option::<String>::None)?
        .set_default("server.cert.store.signing_key_path", Option::<String>::None)?
        .set_default("server.cert.store.certificate", Option::<String>::None)?
        .set_default("server.cert.store.signing_key", Option::<String>::None)?
        .set_default("aws.region", "us-east-1")?
        .set_default("vault.auth_method", "approle")?
        .set_default("vault.addr", "http://localhost:8200")?
        .set_default("vault.role_id", "")?
        .set_default("vault.secret_id", Option::<String>::None)?
        .set_default("vault.secret_id_path", Option::<String>::None)?
        .set_default("vault.auth_mount", "approle")?
        .set_default("vault.k8s_role", Option::<String>::None)?
        .set_default(
            "vault.k8s_token_path",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        )?
        .set_default("vault.k8s_auth_mount", "kubernetes")?
        .set_default("vault.mount", "secret")?
        .set_default("vault.path_prefix", "")?
        .set_default("vault.namespace", Option::<String>::None)?
        .set_default("vault.timeout_secs", 30)?
        .set_default("gcp_secret_manager.project_id", "")?
        .set_default("gcp_secret_manager.allow_anonymous_credentials", false)?
        .set_default("gcp_secret_manager.secrets_cache_ttl", 300)?
        .set_default("azure_keyvault.vault_url", Option::<String>::None)?
        .set_default("azure_keyvault.secrets_cache_ttl", 300)?
        .set_default("cache.backend", "memory")?
        .set_default("cache.ttl", 5 * 60)?
        .set_default("cache.max_capacity", 1000)?
        .set_default("cache.host", Option::<String>::None)?
        .set_default("cache.port", Option::<u16>::None)?
        .set_default("cache.username", Option::<String>::None)?
        .set_default("cache.password", Option::<String>::None)?
        .set_default("cache.password_file", Option::<String>::None)?
        .set_default("cache.database", Option::<u8>::None)?
        .set_default("cache.tls", false)?
        .set_default("cache.ca_file", Option::<String>::None)?
        .set_default("cache.key_prefix", default_cache_key_prefix())?
        .set_default(
            "cache.response_timeout_ms",
            default_cache_response_timeout_ms(),
        )?
        .set_default(
            "cache.connection_timeout_ms",
            default_cache_connection_timeout_ms(),
        )?
        .set_default(
            "cache.reconnect_cooldown_ms",
            default_cache_reconnect_cooldown_ms(),
        )?
        .set_default("token_bytes_cache.max_capacity", 67108864)?
        .set_default("status_list.token_exp_secs", 900)?
        .set_default("status_list.token_ttl_secs", 300)?
        .set_default("status_list.snapshot_retention_secs", 7776000)?
        .set_default("management_auth.leeway_secs", 60)?
        .set_default("management_auth.max_token_lifetime_secs", 300)?
        .set_default("management_auth.audiences", Vec::<String>::new())?
        .set_default("rate_limit.strict_burst_size", 10)?
        .set_default("rate_limit.strict_period_secs", 60)?
        .set_default("rate_limit.permissive_burst_size", 100)?
        .set_default("rate_limit.permissive_period_secs", 60)?
        .set_default("limits.max_body_size_bytes", 2_097_152)?
        .set_default("limits.max_status_index", 100_000)?
        .set_default("limits.max_statuses_per_request", 5_000)?
        .set_default("limits.max_serialized_list_size", 1_048_576)?
        .set_default("limits.max_lists_per_issuer", 1_000)?
        .set_default("limits.list_quota_transition", false)?
        .set_default("telemetry.environment", telemetry_environment)?
        .set_default("telemetry.otlp_endpoint", "http://localhost:4317")?
        .set_default("telemetry.sampler_ratio", 1.0)?
        .set_default("telemetry.enabled", true)?
        .set_default("watcher.poll_interval_secs", 30u64)?;
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::path::{Path, PathBuf};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "status-list-config-test-{}-{}",
                std::process::id(),
                time::OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn test_config_loading() {
        let config = Config::load_from_overrides(&[]).expect("Failed to load default config");

        assert_eq!(config.server.host, "localhost");
        assert_eq!(config.server.port, 8000);
        assert_eq!(config.server.management.host, "localhost");
        assert_eq!(config.server.management.port, 8001);
        assert_eq!(config.server.admin.host, "localhost");
        assert_eq!(config.server.admin.port, 8002);
        assert_eq!(config.server.links.documentation, REPOSITORY_URL);
        assert_eq!(config.server.links.portal, None);
        assert!(!config.server.has_duplicate_listener());
        assert_eq!(config.server.cert.email, "admin@example.com");
        assert_eq!(
            config.server.cert.acme_directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(config.aws.region, "us-east-1");
        assert_eq!(config.gcp_secret_manager.project_id, "");
        assert_eq!(config.gcp_secret_manager.secrets_cache_ttl, 300);
        assert_eq!(config.azure_keyvault.vault_url, None);
        assert_eq!(config.azure_keyvault.secrets_cache_ttl, 300);
        assert_eq!(config.token_bytes_cache.max_capacity, 67108864);
        assert_eq!(config.status_list.token_exp_secs, 900);
        assert_eq!(config.status_list.token_ttl_secs, 300);
        assert_eq!(config.management_auth.leeway_secs, 60);
        assert_eq!(config.management_auth.max_token_lifetime_secs, 300);
        assert!(config.management_auth.audiences.is_empty());
        assert_eq!(config.server.cert.renewal_cron_schedule, "0 0 0 * * *");
        assert_eq!(config.server.cert.dns_challenge_server_url, None);
        assert_eq!(config.server.aggregation_uri, None);

        #[cfg(feature = "postgres")]
        let expected_db_backend = DatabaseBackend::Postgres;
        #[cfg(all(not(feature = "postgres"), feature = "sqlite"))]
        let expected_db_backend = DatabaseBackend::Sqlite;
        #[cfg(all(not(feature = "postgres"), not(feature = "sqlite"), feature = "mysql"))]
        let expected_db_backend = DatabaseBackend::MySql;
        #[cfg(all(
            not(feature = "postgres"),
            not(feature = "sqlite"),
            not(feature = "mysql")
        ))]
        let expected_db_backend = DatabaseBackend::Memory;

        assert!(
            config.database.url.is_none(),
            "database.url should not have a credential-bearing built-in default"
        );
        assert_eq!(config.database.backend, expected_db_backend);
        assert_eq!(config.server.cert.store.certificate_path, None);
        assert_eq!(config.server.cert.store.signing_key_path, None);
        assert_eq!(config.server.cert.store.certificate, None);
        assert_eq!(config.server.cert.store.signing_key, None);
        assert_eq!(config.server.cert.signing_key_cache_ttl, 0);

        assert_eq!(config.rate_limit.strict_burst_size, 10);
        assert_eq!(config.rate_limit.strict_period_secs, 60);
        assert_eq!(config.rate_limit.permissive_burst_size, 100);
        assert_eq!(config.rate_limit.permissive_period_secs, 60);
        assert_eq!(config.limits.max_body_size_bytes, 2_097_152);
        assert_eq!(config.limits.max_status_index, 100_000);
        assert_eq!(config.limits.max_statuses_per_request, 5_000);
        assert_eq!(config.limits.max_serialized_list_size, 1_048_576);
        assert_eq!(config.limits.max_lists_per_issuer, 1_000);
        assert!(!config.limits.list_quota_transition);

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

        let overridden = Config::load_from_overrides(&[
            ("server.host", "0.0.0.0"),
            ("server.port", "5002"),
            (
                "server.aggregation_uri",
                "https://example.com/api/v1/aggregation",
            ),
            (
                "database.url",
                "postgres://user:password@localhost:5432/status-list",
            ),
            ("server.cert.email", "test@gmail.com"),
            (
                "server.cert.acme_directory_url",
                "https://acme-v02.api.letsencrypt.org/directory",
            ),
            ("server.cert.organization", "Test Org"),
            ("server.cert.eku", "1,3,6,1,5,5,7,3,30"),
            ("server.cert.signing_key_cache_ttl", "0"),
            ("server.cert.store.certificate_path", "/certs/tls.crt"),
            ("server.cert.store.signing_key_path", "/certs/tls.key"),
            ("server.cert.renewal_cron_schedule", "0 0 12 * * *"),
            ("server.cert.dns_challenge_server_url", "http://pebble:8055"),
            ("aws.region", "us-west-2"),
            ("cache.backend", "redis"),
            ("cache.ttl", "600"),
            ("cache.max_capacity", "2000"),
            ("token_bytes_cache.max_capacity", "500"),
            ("cache.host", "redis"),
            ("cache.port", "6380"),
            ("cache.username", "default"),
            ("cache.password", "redis-password"),
            ("cache.database", "2"),
            ("cache.tls", "true"),
            ("cache.ca_file", "/etc/redis/ca.pem"),
            ("cache.key_prefix", "tenant-a:status-list:"),
            ("cache.response_timeout_ms", "150"),
            ("cache.connection_timeout_ms", "200"),
            ("cache.reconnect_cooldown_ms", "300"),
            ("status_list.token_exp_secs", "1800"),
            ("status_list.token_ttl_secs", "600"),
            ("management_auth.leeway_secs", "30"),
            ("management_auth.max_token_lifetime_secs", "900"),
            (
                "management_auth.audiences",
                "status-list-server-management,internal-management",
            ),
            ("rate_limit.strict_burst_size", "3"),
            ("rate_limit.strict_period_secs", "120"),
            ("rate_limit.permissive_burst_size", "500"),
            ("rate_limit.permissive_period_secs", "10"),
            ("limits.max_body_size_bytes", "65536"),
            ("limits.max_status_index", "4096"),
            ("limits.max_statuses_per_request", "256"),
            ("limits.max_serialized_list_size", "32768"),
            ("limits.max_lists_per_issuer", "25"),
            ("limits.list_quota_transition", "true"),
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
            Some("https://example.com/api/v1/aggregation")
        );
        assert_eq!(
            overridden
                .database
                .url
                .as_ref()
                .expect("database.url override should be set")
                .expose_secret(),
            "postgres://user:password@localhost:5432/status-list"
        );
        assert_eq!(overridden.server.cert.email, "test@gmail.com");
        assert_eq!(
            overridden.server.cert.acme_directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(overridden.aws.region, "us-west-2");
        assert_eq!(overridden.cache.backend, CacheBackend::Redis);
        assert_eq!(overridden.cache.ttl, 600);
        assert_eq!(overridden.cache.max_capacity, 2000);
        assert_eq!(overridden.token_bytes_cache.max_capacity, 500);
        assert_eq!(overridden.cache.host.as_deref(), Some("redis"));
        assert_eq!(overridden.cache.port, Some(6380));
        assert_eq!(overridden.cache.username.as_deref(), Some("default"));
        assert_eq!(
            overridden
                .cache
                .password
                .as_ref()
                .expect("redis password override")
                .expose_secret(),
            "redis-password"
        );
        assert_eq!(overridden.cache.database, Some(2));
        assert!(overridden.cache.tls);
        assert_eq!(
            overridden.cache.ca_file.as_deref(),
            Some(std::path::Path::new("/etc/redis/ca.pem"))
        );
        assert_eq!(overridden.cache.key_prefix, "tenant-a:status-list:");
        assert_eq!(overridden.cache.response_timeout_ms, 150);
        assert_eq!(overridden.cache.connection_timeout_ms, 200);
        assert_eq!(overridden.cache.reconnect_cooldown_ms, 300);
        assert_eq!(
            overridden
                .cache
                .resolved_redis_url()
                .expect("redis url")
                .expose_secret(),
            "rediss://default:redis-password@redis:6380/2"
        );

        let redis_without_tls_in_prod = Config::load_from_overrides(&[
            ("telemetry.environment", "production"),
            ("cache.backend", "redis"),
            ("cache.host", "redis"),
            ("cache.password", "redis-password"),
        ])
        .expect_err("production Redis without TLS should be rejected");
        assert!(
            redis_without_tls_in_prod
                .to_string()
                .contains("cache.tls=true"),
            "unexpected error: {redis_without_tls_in_prod}"
        );

        let redis_without_auth_in_prod = Config::load_from_overrides(&[
            ("telemetry.environment", "production"),
            ("cache.backend", "redis"),
            ("cache.host", "redis"),
            ("cache.tls", "true"),
        ])
        .expect_err("production Redis without auth should be rejected");
        assert!(
            redis_without_auth_in_prod
                .to_string()
                .contains("cache.password or cache.password_file"),
            "unexpected error: {redis_without_auth_in_prod}"
        );
        assert_eq!(overridden.status_list.token_exp_secs, 1800);
        assert_eq!(overridden.status_list.token_ttl_secs, 600);
        assert_eq!(overridden.management_auth.leeway_secs, 30);
        assert_eq!(overridden.management_auth.max_token_lifetime_secs, 900);
        assert_eq!(
            overridden.management_auth.audiences,
            vec![
                "status-list-server-management".to_string(),
                "internal-management".to_string()
            ]
        );
        assert_eq!(overridden.server.cert.renewal_cron_schedule, "0 0 12 * * *");
        assert_eq!(
            overridden.server.cert.dns_challenge_server_url.as_deref(),
            Some("http://pebble:8055")
        );
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
        assert_eq!(overridden.limits.max_lists_per_issuer, 25);
        assert!(overridden.limits.list_quota_transition);
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
            ("database.password", " secret value "),
            ("database.name", "status/list"),
            (
                "database.query",
                "sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt",
            ),
        ])
        .expect("Failed to load split database config");
        assert_eq!(
            split_db_cfg
                .database
                .resolved_url()
                .expect("split database config should resolve")
                .expose_secret(),
            "postgres://user%40example.com:secret%20value@postgres.statuslist.svc.cluster.local:5432/status%2Flist?sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt"
        );
        assert_eq!(
            split_db_cfg.database.redacted_target(),
            "backend=postgres, host=postgres.statuslist.svc.cluster.local, port=5432, database=status/list"
        );
        assert!(!split_db_cfg.database.redacted_target().contains("secret"));

        let password_dir = TempDir::new();
        let password_path = password_dir.path().join("postgres-password");
        std::fs::write(&password_path, "file secret\n").expect("write password file");
        let password_file_cfg = Config::load_from_overrides(&[
            ("database.backend", "postgres"),
            ("database.host", "postgres.statuslist.svc.cluster.local"),
            ("database.port", "5432"),
            ("database.username", "user"),
            (
                "database.password_file",
                password_path
                    .to_str()
                    .expect("password path should be unicode for test"),
            ),
            ("database.name", "status-list"),
        ])
        .expect("Failed to load password-file database config");
        let resolved = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(password_file_cfg.database.load_resolved_url())
            .expect("password-file database config should resolve");
        assert_eq!(
            resolved.expose_secret(),
            "postgres://user:file%20secret@postgres.statuslist.svc.cluster.local:5432/status-list"
        );

        let ipv6_db_cfg = Config::load_from_overrides(&[
            ("database.backend", "postgres"),
            ("database.host", "fd00::1"),
            ("database.username", "postgres"),
            ("database.password", "secret"),
            ("database.name", "status-list"),
        ])
        .expect("Failed to load IPv6 split database config");
        assert_eq!(
            ipv6_db_cfg
                .database
                .resolved_url()
                .expect("IPv6 split database config should resolve")
                .expose_secret(),
            "postgres://postgres:secret@[fd00::1]:5432/status-list"
        );

        let bracketed_ipv6_db_cfg = Config::load_from_overrides(&[
            ("database.backend", "postgres"),
            ("database.host", "[fd00::1]"),
            ("database.username", "postgres"),
            ("database.password", "secret"),
            ("database.name", "status-list"),
        ])
        .expect("Failed to load bracketed IPv6 split database config");
        assert_eq!(
            bracketed_ipv6_db_cfg
                .database
                .resolved_url()
                .expect("bracketed IPv6 split database config should resolve")
                .expose_secret(),
            "postgres://postgres:secret@[fd00::1]:5432/status-list"
        );

        let fqdn_db_cfg = Config::load_from_overrides(&[
            ("database.backend", "postgres"),
            ("database.host", "db.example.internal."),
            ("database.username", "postgres"),
            ("database.password", "secret"),
            ("database.name", "status-list"),
        ])
        .expect("Failed to load trailing-dot FQDN split database config");
        assert_eq!(
            fqdn_db_cfg
                .database
                .resolved_url()
                .expect("trailing-dot FQDN split database config should resolve")
                .expose_secret(),
            "postgres://postgres:secret@db.example.internal.:5432/status-list"
        );

        let missing_db_url = Config::load_from_overrides(&[])
            .expect("Failed to load default config")
            .database
            .resolved_url()
            .expect_err(
                "database config should fail closed when neither URL nor split fields are set",
            )
            .to_string();
        assert!(missing_db_url.contains("database.url or split database fields"));

        let mixed_db_cfg = Config::load_from_overrides(&[
            ("database.backend", "postgres"),
            (
                "database.url",
                "postgres://custom:secret@custom-db:5432/custom",
            ),
            ("database.host", "postgres.statuslist.svc.cluster.local"),
            ("database.username", "postgres"),
            ("database.password", "split secret"),
            ("database.name", "status-list"),
        ])
        .expect("Failed to load mixed database config");
        let mixed_db_error = mixed_db_cfg
            .database
            .resolved_url()
            .expect_err("mixed database.url and split fields should fail")
            .to_string();
        assert!(mixed_db_error.contains("Ambiguous database configuration"));
        assert!(!mixed_db_error.contains("custom:secret"));
        assert!(!mixed_db_error.contains("split secret"));

        let invalid_host_error = Config::load_from_overrides(&[
            ("database.backend", "postgres"),
            ("database.host", "postgres://db.internal:5432/status-list"),
            ("database.username", "postgres"),
            ("database.password", "secret"),
            ("database.name", "status-list"),
        ])
        .expect_err("database.host must reject URL-shaped values")
        .to_string();
        assert!(invalid_host_error.contains("database.host"));
        assert!(!invalid_host_error.contains("secret"));

        let invalid_query_error = Config::load_from_overrides(&[
            ("database.backend", "postgres"),
            ("database.host", "postgres.statuslist.svc.cluster.local"),
            ("database.username", "postgres"),
            ("database.password", "secret"),
            ("database.name", "status-list"),
            ("database.query", "sslmode=verify-full&password=secret"),
        ])
        .expect_err("database.query must reject credential-like keys")
        .to_string();
        assert!(invalid_query_error.contains("database.query"));
        assert!(!invalid_query_error.contains("postgres://"));
        assert!(!invalid_query_error.contains("secret"));

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

        let valid_ttl = Config::load_from_overrides(&[
            ("status_list.token_ttl_secs", "300"),
            ("status_list.token_exp_secs", "900"),
        ])
        .expect("ttl < exp is valid");
        assert_eq!(valid_ttl.status_list.token_ttl_secs, 300);

        let ttl_ge_exp = Config::load_from_overrides(&[
            ("status_list.token_ttl_secs", "900"),
            ("status_list.token_exp_secs", "900"),
        ])
        .expect_err("ttl == exp must be rejected");
        let ttl_ge_exp_msg = ttl_ge_exp.to_string();
        assert!(
            ttl_ge_exp_msg.contains("APP_STATUS_LIST__TOKEN_TTL_SECS"),
            "the refusal must name the APP_STATUS_LIST__TOKEN_TTL_SECS env var: {ttl_ge_exp_msg}"
        );
        assert!(
            ttl_ge_exp_msg.contains("APP_STATUS_LIST__TOKEN_EXP_SECS"),
            "the refusal must name the APP_STATUS_LIST__TOKEN_EXP_SECS env var: {ttl_ge_exp_msg}"
        );

        let _ttl_gt_exp = Config::load_from_overrides(&[
            ("status_list.token_ttl_secs", "600"),
            ("status_list.token_exp_secs", "300"),
        ])
        .expect_err("ttl > exp must be rejected");

        let _exp_zero = Config::load_from_overrides(&[
            ("status_list.token_ttl_secs", "0"),
            ("status_list.token_exp_secs", "0"),
        ])
        .expect_err("exp == 0 must be rejected (ttl >= 0 can never be < 0)");

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
            mysql_cfg
                .database
                .url
                .as_ref()
                .expect("mysql database.url override should be set")
                .expose_secret(),
            "mysql://user:password@localhost:3306/status-list"
        );

        let sqlite_cfg = Config::load_from_overrides(&[
            ("database.backend", "sqlite"),
            ("database.url", "sqlite::memory:"),
        ])
        .expect("Failed to load sqlite config");
        assert_eq!(sqlite_cfg.database.backend, DatabaseBackend::Sqlite);
        assert_eq!(
            sqlite_cfg
                .database
                .url
                .as_ref()
                .expect("sqlite database.url override should be set")
                .expose_secret(),
            "sqlite::memory:"
        );
    }

    #[test]
    fn test_dns_provider_resolution() {
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
                project_id: "dns-project".into(),
            }),
            ..Default::default()
        };
        assert_eq!(
            gcloud_path_dns.resolve("production").unwrap().kind(),
            DnsProviderKind::Gcloud
        );

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
    fn test_classify_app_env() {
        for raw in ["production", "prod", "PRODUCTION", "PROD", "  Production "] {
            assert!(
                classify_app_env(raw).is_production(),
                "{raw:?} must classify as production"
            );
        }

        for raw in [
            "development",
            "dev",
            "",
            "   ",
            "staging",
            "PRODUCTIONx",
            "development ",
        ] {
            assert!(
                !classify_app_env(raw).is_production(),
                "{raw:?} must not classify as production"
            );
        }

        let default_dns = DnsConfig::default();
        assert_eq!(
            default_dns.resolve("PROD").unwrap().kind(),
            DnsProviderKind::Route53
        );
    }

    #[test]
    fn test_management_auth_validations() {
        let zero_lifetime =
            Config::load_from_overrides(&[("management_auth.max_token_lifetime_secs", "0")]);
        assert!(
            zero_lifetime.is_err(),
            "zero management token lifetime should fail config loading"
        );

        let empty_audiences =
            Config::load_from_overrides(&[("APP_MANAGEMENT_AUTH__AUDIENCES", "")])
                .expect("empty audience env value should load");
        assert!(empty_audiences.management_auth.audiences.is_empty());

        let production_empty_audiences = Config::load_from_overrides(&[
            ("telemetry.environment", "production"),
            ("APP_MANAGEMENT_AUTH__AUDIENCES", ""),
        ]);
        assert!(production_empty_audiences.is_err());

        let trimmed_audiences = Config::load_from_overrides(&[(
            "APP_MANAGEMENT_AUTH__AUDIENCES",
            "status-list-server-management, internal-management, ",
        )])
        .expect("comma-separated audiences should load");
        assert_eq!(
            trimmed_audiences.management_auth.audiences,
            vec![
                "status-list-server-management".to_string(),
                "internal-management".to_string()
            ]
        );
    }

    #[test]
    fn test_duplicate_listeners_are_rejected() {
        assert!(Config::load_from_overrides(&[]).is_ok());

        let mgmt_collides = Config::load_from_overrides(&[("server.management.port", "8000")]);
        let err = mgmt_collides
            .expect_err("management on the public port must be rejected")
            .to_string();
        assert!(err.contains("Duplicate listener"), "{err}");

        let admin_collides = Config::load_from_overrides(&[("server.admin.port", "8001")]);
        let err = admin_collides
            .expect_err("admin on the management port must be rejected")
            .to_string();
        assert!(err.contains("Duplicate listener"), "{err}");

        assert!(
            Config::load_from_overrides(&[
                ("server.host", "0.0.0.0"),
                ("server.management.host", "::1"),
                ("server.management.port", "8000"),
            ])
            .is_ok()
        );

        let wildcard_loopback = Config::load_from_overrides(&[
            ("server.host", "0.0.0.0"),
            ("server.management.host", "127.0.0.1"),
            ("server.management.port", "8000"),
        ]);
        let err = wildcard_loopback
            .expect_err("a wildcard bind and a loopback bind on the same port must be rejected")
            .to_string();
        assert!(err.contains("Duplicate listener"), "{err}");

        let localhost_loopback = Config::load_from_overrides(&[
            ("server.host", "localhost"),
            ("server.management.host", "127.0.0.1"),
            ("server.management.port", "8000"),
        ]);
        let err = localhost_loopback
            .expect_err("localhost and 127.0.0.1 on the same port must be rejected")
            .to_string();
        assert!(err.contains("Duplicate listener"), "{err}");
    }

    #[test]
    fn test_links_config_loads_and_defaults() {
        let config = Config::load_from_overrides(&[]).unwrap();
        assert_eq!(config.server.links.documentation, REPOSITORY_URL);
        assert_eq!(config.server.links.portal, None);

        let overridden = Config::load_from_overrides(&[
            (
                "server.links.documentation",
                "https://docs.example.com/status-list",
            ),
            ("server.links.portal", "https://portal.example.com"),
        ])
        .unwrap();
        assert_eq!(
            overridden.server.links.documentation,
            "https://docs.example.com/status-list"
        );
        assert_eq!(
            overridden.server.links.portal.as_deref(),
            Some("https://portal.example.com")
        );
    }

    #[test]
    fn test_status_list_validations() {
        let defaults = Config::load_from_overrides(&[]).expect("default config should load");
        assert_eq!(defaults.status_list.token_exp_secs, 900);
        assert_eq!(defaults.status_list.token_ttl_secs, 300);

        let above_ceiling = (MAX_TOKEN_LIFETIME_SECS + 1).to_string();
        let rejects: Vec<(Vec<(&str, &str)>, &str)> = vec![
            (
                vec![("status_list.token_exp_secs", "0")],
                "APP_STATUS_LIST__TOKEN_EXP_SECS must be a positive number",
            ),
            (
                vec![("status_list.token_ttl_secs", "0")],
                "APP_STATUS_LIST__TOKEN_TTL_SECS must be a positive number",
            ),
            (
                vec![("status_list.token_exp_secs", "9223372036854775808")],
                "APP_STATUS_LIST__TOKEN_EXP_SECS (9223372036854775808) exceeds the maximum \
                 supported token lifetime",
            ),
            (
                vec![("status_list.token_ttl_secs", "9223372036854775808")],
                "APP_STATUS_LIST__TOKEN_TTL_SECS (9223372036854775808) exceeds the maximum \
                 supported token lifetime",
            ),
            (
                vec![("status_list.token_exp_secs", &above_ceiling)],
                "exceeds the maximum supported token lifetime",
            ),
            (
                vec![("status_list.token_ttl_secs", "900")],
                "APP_STATUS_LIST__TOKEN_TTL_SECS (900) must be less than",
            ),
            (
                vec![
                    ("status_list.token_exp_secs", "300"),
                    ("status_list.token_ttl_secs", "600"),
                ],
                "APP_STATUS_LIST__TOKEN_TTL_SECS (600) must be less than",
            ),
        ];
        for (overrides, expected) in rejects {
            let err = match Config::load_from_overrides(&overrides) {
                Ok(_) => panic!("overrides {overrides:?} should fail config loading"),
                Err(e) => e,
            };
            assert!(
                err.to_string().contains(expected),
                "expected error to mention {expected:?}, got: {err}"
            );
        }

        let max_exp = Config::load_from_overrides(&[(
            "status_list.token_exp_secs",
            &MAX_TOKEN_LIFETIME_SECS.to_string(),
        )]);
        assert!(
            max_exp.is_ok(),
            "token_exp_secs == MAX_TOKEN_LIFETIME_SECS should load"
        );
    }

    #[test]
    fn test_zero_list_quota_is_rejected() {
        let zero_quota = Config::load_from_overrides(&[("limits.max_lists_per_issuer", "0")]);
        assert!(
            zero_quota.is_err(),
            "a zero list quota would refuse every publish and must fail config loading"
        );
    }

    #[test]
    fn test_list_quota_above_aggregation_page_is_rejected() {
        let over = (AGGREGATION_DEFAULT_LIMIT + 1).to_string();
        let err = Config::load_from_overrides(&[("limits.max_lists_per_issuer", &over)])
            .expect_err("a quota larger than one aggregation page must fail config loading")
            .to_string();
        assert!(
            err.contains(&format!("limits.max_lists_per_issuer ({over})")),
            "{err}"
        );
        assert!(
            err.contains(&format!(
                "AGGREGATION_DEFAULT_LIMIT ({AGGREGATION_DEFAULT_LIMIT})"
            )),
            "{err}"
        );

        let at_page = AGGREGATION_DEFAULT_LIMIT.to_string();
        assert!(Config::load_from_overrides(&[("limits.max_lists_per_issuer", &at_page)]).is_ok());
    }

    fn aggregation_uri(uri: &str) -> Result<Option<Url>, ConfigError> {
        aggregation_uri_in("development", uri)
    }

    fn aggregation_uri_in(environment: &str, uri: &str) -> Result<Option<Url>, ConfigError> {
        let mut overrides = vec![
            ("telemetry.environment", environment),
            ("server.aggregation_uri", uri),
        ];
        if classify_app_env(environment).is_production() {
            overrides.push(("management_auth.audiences", "status-list-server-management"));
        }
        Config::load_from_overrides(&overrides).map(|config| {
            config
                .server
                .aggregation_uri(config.telemetry.environment)
                .expect("a config that loaded has a valid aggregation_uri")
        })
    }

    #[test]
    fn test_aggregation_uri_accepts_the_endpoint_url() {
        let uri = aggregation_uri(" https://statuslist.example.com/api/v1/aggregation ").unwrap();
        assert_eq!(
            uri.unwrap().as_str(),
            "https://statuslist.example.com/api/v1/aggregation"
        );
    }

    #[test]
    fn test_aggregation_uri_follows_the_public_base_url_path() {
        let behind_proxy = |uri: &str| {
            Config::load_from_overrides(&[
                (
                    "server.public_base_url",
                    "https://host.example.com/statuslist/api/v1",
                ),
                ("server.aggregation_uri", uri),
            ])
        };
        assert!(behind_proxy("https://host.example.com/statuslist/api/v1/aggregation").is_ok());
        let err = behind_proxy("https://host.example.com/api/v1/aggregation")
            .expect_err("the route sits under the proxy prefix")
            .to_string();
        assert!(err.contains("'/statuslist/api/v1/aggregation'"), "{err}");
    }

    #[test]
    fn test_aggregation_uri_unset_or_blank_is_none() {
        let config = Config::load_from_overrides(&[]).unwrap();
        assert_eq!(
            config
                .server
                .aggregation_uri(config.telemetry.environment)
                .unwrap(),
            None
        );
        assert_eq!(aggregation_uri("  ").unwrap(), None);
    }

    #[test]
    fn test_aggregation_uri_allows_plain_http_only_outside_production() {
        let uri = "http://localhost:8000/api/v1/aggregation";
        assert!(aggregation_uri(uri).unwrap().is_some());
        let err = aggregation_uri_in("production", uri)
            .expect_err("plain http must be rejected in production")
            .to_string();
        assert!(err.contains("https in production"), "{err}");
    }

    #[test]
    fn test_aggregation_uri_rejects_anything_but_the_endpoint_url() {
        for uri in [
            "not a url",
            "file:///api/v1/aggregation",
            "ftp://statuslist.example.com/api/v1/aggregation",
            "https://user:secret@statuslist.example.com/api/v1/aggregation",
            "https://user@statuslist.example.com/api/v1/aggregation",
            "https://statuslist.example.com/statuslists/aggregation",
            "https://statuslist.example.com/api/v1/aggregation/",
            "https://statuslist.example.com/api/v1/aggregation?aggregation_id=x",
            "https://statuslist.example.com/api/v1/aggregation?",
            "https://statuslist.example.com/api/v1/aggregation#top",
        ] {
            let err = aggregation_uri(uri).expect_err(uri).to_string();
            assert!(err.contains("server.aggregation_uri"), "{uri}: {err}");
        }
    }

    #[test]
    fn test_status_list_ttl_exp_validation_boundaries() {
        let valid = StatusListConfig {
            token_exp_secs: 900,
            token_ttl_secs: 300,
            snapshot_retention_secs: 7776000,
        };
        assert!(valid.validate().is_ok(), "ttl < exp must be accepted");

        let equal = StatusListConfig {
            token_exp_secs: 600,
            token_ttl_secs: 600,
            snapshot_retention_secs: 7776000,
        };
        let err = equal
            .validate()
            .expect_err("ttl == exp must be rejected")
            .to_string();
        assert!(
            err.contains("APP_STATUS_LIST__TOKEN_TTL_SECS"),
            "refusal must name the APP_STATUS_LIST__TOKEN_TTL_SECS env var: {err}"
        );
        assert!(
            err.contains("APP_STATUS_LIST__TOKEN_EXP_SECS"),
            "refusal must name the APP_STATUS_LIST__TOKEN_EXP_SECS env var: {err}"
        );

        let gt = StatusListConfig {
            token_exp_secs: 300,
            token_ttl_secs: 600,
            snapshot_retention_secs: 7776000,
        };
        assert!(gt.validate().is_err(), "ttl > exp must be rejected");

        let exp_zero = StatusListConfig {
            token_exp_secs: 0,
            token_ttl_secs: 0,
            snapshot_retention_secs: 7776000,
        };
        assert!(
            exp_zero.validate().is_err(),
            "exp == 0 must be rejected (ttl >= 0 can never be < 0)"
        );
    }

    #[test]
    fn test_public_base_url_derives_from_domain_by_default() {
        let config = Config::load_from_overrides(&[("server.domain", "statuslist.example.com")])
            .expect("config loads");
        assert_eq!(config.server.public_base_url, None);
        assert_eq!(
            config.server.resolved_public_base_url(),
            "https://statuslist.example.com/api/v1"
        );

        let config = Config::load_from_overrides(&[
            ("server.domain", "statuslist.example.com"),
            (
                "server.public_base_url",
                "https://status.example.org/api/v1",
            ),
        ])
        .expect("config loads");
        assert_eq!(
            config.server.resolved_public_base_url(),
            "https://status.example.org/api/v1"
        );
    }

    #[test]
    fn test_public_base_url_rejects_non_https_query_and_fragment() {
        for (value, expected) in [
            (
                "http://statuslist.example.com/api/v1",
                "scheme must be https",
            ),
            (
                "https://statuslist.example.com/api/v1?x=1",
                "must not contain a query",
            ),
            (
                "https://statuslist.example.com/api/v1#frag",
                "must not contain a fragment",
            ),
            (
                "https://statuslist.example.com/api/v1/",
                "must not end with a trailing slash",
            ),
            (
                "https://user@statuslist.example.com/api/v1",
                "must not contain userinfo",
            ),
            (
                "https://user:password@statuslist.example.com/api/v1",
                "must not contain userinfo",
            ),
            ("not a url", "not a valid URL"),
        ] {
            let err = Config::load_from_overrides(&[("server.public_base_url", value)])
                .expect_err(&format!("public_base_url {value:?} must be rejected"));
            assert!(
                err.to_string().contains(expected),
                "expected {expected:?} in: {err}"
            );
        }

        Config::load_from_overrides(&[(
            "server.public_base_url",
            "https://statuslist.example.com/api/v1",
        )])
        .expect("a valid public_base_url must load");
    }

    #[test]
    fn test_public_base_url_allows_non_api_v1_path() {
        for value in [
            "https://statuslist.example.com",
            "https://statuslist.example.com/api/v2",
            "https://statuslist.example.com/proxy",
            "https://statuslist.example.com/api/v1/status-lists/foo",
        ] {
            Config::load_from_overrides(&[("server.public_base_url", value)])
                .unwrap_or_else(|_| panic!("public_base_url {value:?} must load"));
        }
    }

    #[test]
    fn test_public_base_url_rejects_userinfo() {
        for (value, expected) in [
            (
                "https://user@statuslist.example.com/api/v1",
                "must not contain userinfo",
            ),
            (
                "https://user:password@statuslist.example.com/api/v1",
                "must not contain userinfo",
            ),
            (
                "https://:password@statuslist.example.com/api/v1",
                "must not contain userinfo",
            ),
        ] {
            let err = Config::load_from_overrides(&[("server.public_base_url", value)])
                .expect_err(&format!("public_base_url {value:?} must be rejected"));
            assert!(
                err.to_string().contains(expected),
                "expected {expected:?} in: {err}"
            );
        }
    }

    #[test]
    fn test_resolved_public_base_url_is_normalized() {
        let config = Config::load_from_overrides(&[(
            "server.public_base_url",
            "HTTPS://StatusList.Example.COM:443/api/../api/v1",
        )])
        .expect("config loads");
        assert_eq!(
            config.server.resolved_public_base_url(),
            "https://statuslist.example.com/api/v1"
        );
    }

    #[test]
    fn test_public_base_url_derived_from_ipv6_domain_is_bracketed_and_valid() {
        let config = Config::load_from_overrides(&[("server.domain", "2001:db8::1")])
            .expect("a bare IPv6 server.domain should load");
        assert_eq!(
            config.server.resolved_public_base_url(),
            "https://[2001:db8::1]/api/v1"
        );

        let config = Config::load_from_overrides(&[("server.domain", "[2001:db8::1]")])
            .expect("a bracketed IPv6 server.domain should load");
        assert_eq!(
            config.server.resolved_public_base_url(),
            "https://[2001:db8::1]/api/v1"
        );
    }

    #[test]
    fn test_server_domain_must_be_bare_host() {
        for (value, expected) in [
            (
                "https://example.com",
                "scheme, port, path, userinfo, query, or fragment",
            ),
            (
                "example.com/path",
                "scheme, port, path, userinfo, query, or fragment",
            ),
            (
                "example.com:443",
                "scheme, port, path, userinfo, query, or fragment",
            ),
            (
                "user@example.com",
                "scheme, port, path, userinfo, query, or fragment",
            ),
            (
                "example.com?x",
                "scheme, port, path, userinfo, query, or fragment",
            ),
            (
                "example.com#x",
                "scheme, port, path, userinfo, query, or fragment",
            ),
            (
                "example.com\\path",
                "scheme, port, path, userinfo, query, or fragment",
            ),
            (
                "example .com",
                "scheme, port, path, userinfo, query, or fragment",
            ),
            (
                "-example.com",
                "scheme, port, path, userinfo, query, or fragment",
            ),
            (
                "example.com-",
                "scheme, port, path, userinfo, query, or fragment",
            ),
            (
                ".example.com",
                "scheme, port, path, userinfo, query, or fragment",
            ),
        ] {
            let err = Config::load_from_overrides(&[("server.domain", value)])
                .expect_err(&format!("server.domain {value:?} must be rejected"));
            assert!(
                err.to_string().contains(expected),
                "expected {expected:?} in: {err}"
            );
        }
    }

    #[test]
    fn test_critical_validations() {
        let invalid_db_res = Config::load_from_overrides(&[
            ("database.backend", "invalid-backend"),
            (
                "database.url",
                "postgres://user:password@localhost:5432/status-list",
            ),
        ]);
        assert!(
            invalid_db_res.is_err(),
            "an unknown database backend value should fail config loading"
        );

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

        let empty_gcloud_project = DnsConfig {
            provider: Some(DnsProviderKind::Gcloud),
            gcloud: Some(GcloudDnsConfig {
                project_id: " ".into(),
            }),
            ..Default::default()
        };
        assert!(
            empty_gcloud_project
                .resolve("production")
                .unwrap_err()
                .to_string()
                .contains("project_id")
        );

        let gcloud_dns = DnsConfig {
            provider: Some(DnsProviderKind::Gcloud),
            gcloud: Some(GcloudDnsConfig {
                project_id: "dns-project".into(),
            }),
            ..Default::default()
        };
        match gcloud_dns.resolve("production").unwrap() {
            ResolvedDnsProvider::Gcloud(cfg) => {
                assert_eq!(cfg.project_id, "dns-project");
            }
            other => panic!("Expected GCloud DNS config, got {other:?}"),
        }

        let azure_helper = |subscription_id: &str, resource_group: &str| DnsConfig {
            provider: Some(DnsProviderKind::Azure),
            azure: Some(AzureDnsConfig {
                subscription_id: subscription_id.into(),
                resource_group: resource_group.into(),
            }),
            ..Default::default()
        };
        let azure_err = azure_helper("", " ")
            .resolve("production")
            .unwrap_err()
            .to_string();
        assert!(azure_err.contains("subscription_id"));
        assert!(azure_err.contains("resource_group"));

        let azure_dns = DnsConfig {
            provider: Some(DnsProviderKind::Azure),
            azure: Some(AzureDnsConfig {
                subscription_id: "sub".into(),
                resource_group: "rg".into(),
            }),
            ..Default::default()
        };
        match azure_dns.resolve("production").unwrap() {
            ResolvedDnsProvider::Azure(cfg) => {
                assert_eq!(cfg.subscription_id, "sub");
            }
            other => panic!("Expected Azure DNS config, got {other:?}"),
        }

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
        if let Some(db_url) = default_config.database.url.as_ref() {
            let db_url = db_url.expose_secret();
            assert!(
                !db_url.contains("test_data"),
                "Default config database URL must not reference test_data"
            );
        }
        if let Some(cert) = default_config.server.cert.store.certificate.as_deref() {
            assert!(
                !cert.contains("test_data"),
                "Default config certificate references test_data: {cert}"
            );
        }
        if let Some(key) = default_config.server.cert.store.signing_key.as_deref() {
            assert!(
                !key.contains("test_data"),
                "Default config signing_key references test_data: {key}"
            );
        }

        assert_eq!(default_config.vault.auth_method, VaultAuthMethod::Approle);
        assert_eq!(default_config.vault.addr, "http://localhost:8200");
        assert_eq!(default_config.vault.role_id, "");
        assert!(default_config.vault.secret_id.is_none());
        assert_eq!(default_config.vault.secret_id_path, None);
        assert_eq!(default_config.vault.auth_mount, "approle");
        assert_eq!(default_config.vault.k8s_role, None);
        assert_eq!(
            default_config.vault.k8s_token_path,
            PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
        );
        assert_eq!(default_config.vault.k8s_auth_mount, "kubernetes");
        assert_eq!(default_config.vault.mount, "secret");
        assert_eq!(default_config.vault.path_prefix, "");
        assert_eq!(default_config.vault.namespace, None);
        assert_eq!(default_config.vault.timeout_secs, 30);
        assert!(default_config.vault.resolve_secret_id().is_err());

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

        let k8s_config = Config::load_from_overrides(&[
            ("vault.auth_method", "kubernetes"),
            ("vault.k8s_role", "my-k8s-service-role"),
            ("vault.k8s_token_path", "/custom/token/path"),
            ("vault.k8s_auth_mount", "custom-k8s"),
        ])
        .expect("Failed to load k8s auth config");

        assert_eq!(k8s_config.vault.auth_method, VaultAuthMethod::Kubernetes);
        assert_eq!(
            k8s_config.vault.k8s_role,
            Some("my-k8s-service-role".to_string())
        );
        assert_eq!(
            k8s_config.vault.k8s_token_path,
            PathBuf::from("/custom/token/path")
        );
        assert_eq!(k8s_config.vault.k8s_auth_mount, "custom-k8s");
    }

    #[test]
    fn normalize_app_env_aliases_match_config() {
        for raw in ["production", "prod", "PRODUCTION", " Prod ", "  prod  "] {
            assert_eq!(
                classify_app_env(raw),
                TelemetryEnvironment::Production,
                "raw APP_ENV {raw:?} must be production"
            );
            assert!(classify_app_env(raw).is_production());
        }
        for raw in ["development", "dev", "", "staging", "development ", "PRODx"] {
            assert_eq!(
                classify_app_env(raw),
                TelemetryEnvironment::Development,
                "raw APP_ENV {raw:?} must be development"
            );
            assert!(!classify_app_env(raw).is_production());
        }
    }
}
