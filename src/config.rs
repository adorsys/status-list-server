use std::{collections::HashMap, fmt, marker::PhantomData};

use config::builder::DefaultState;
use config::{Config as ConfigLib, ConfigBuilder, ConfigError, Environment};
use ipnet::IpNet;
#[cfg(feature = "redis")]
use redis::{
    Client as RedisClient, ClientTlsConfig, RedisResult, TlsCertificates,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer};
use serde_aux::field_attributes::deserialize_vec_from_string_or_vec;
use std::net::IpAddr;
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
    pub cache: CacheConfig,
    pub status_list: StatusListConfig,
    pub rate_limit: RateLimitConfig,
    pub limits: LimitsConfig,
    pub telemetry: TelemetryConfig,
}

/// Where the server derives the client IP address from.
///
/// The correct choice depends entirely on the network topology the server is
/// deployed into, which the server cannot detect. There is deliberately **no
/// default**: guessing the topology is what allowed spoofed `X-Forwarded-For`
/// values to mint unlimited rate-limit buckets. An unset value refuses to
/// start rather than silently picking a source that may be forgeable.
///
/// The `trusted_hops` companion setting on [`RateLimitConfig`] only applies to
/// [`ClientIpSource::RightmostXForwardedFor`]. The variants are kept flat
/// (rather than carrying their own payload) so that every one of them is
/// expressible through the `APP_*` environment variables, which are the only
/// configuration source this server reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIpSource {
    /// The server is reached directly, with no proxy in front of it. The IP is
    /// taken from the accepted connection and cannot be forged.
    ConnectInfo,
    /// The server sits behind one or more reverse proxies that *append* to
    /// `X-Forwarded-For`. The IP is taken by counting `trusted_hops` entries in
    /// from the right, so client-supplied entries on the left are ignored.
    RightmostXForwardedFor,
    /// The server sits behind a proxy that unconditionally **overwrites**
    /// `X-Real-IP` (e.g. nginx `proxy_set_header X-Real-IP $remote_addr`).
    /// Only safe when the overwrite is guaranteed for every request path.
    XRealIp,
}

impl ClientIpSource {
    /// Every variant, so that error messages and documentation cannot drift
    /// from the enum.
    pub const ALL: [Self; 3] = [
        Self::ConnectInfo,
        Self::RightmostXForwardedFor,
        Self::XRealIp,
    ];

    /// The configuration spelling of this variant. Single source of truth for
    /// both `Display` and the accepted-values list.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConnectInfo => "connect_info",
            Self::RightmostXForwardedFor => "rightmost_x_forwarded_for",
            Self::XRealIp => "x_real_ip",
        }
    }

    /// Comma-separated list of accepted values, for error messages.
    pub fn accepted_values() -> String {
        Self::ALL
            .iter()
            .map(|source| source.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Whether this source reads a client-supplied header, and therefore
    /// depends on a proxy in front of the server to sanitise it.
    pub fn trusts_headers(self) -> bool {
        matches!(self, Self::RightmostXForwardedFor | Self::XRealIp)
    }
}

impl std::fmt::Display for ClientIpSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Rate-limit configuration.
///
/// One budget per tier, named after the tier it controls  -  see the rate-limiting
/// section of the README for how tiers map onto routes.
///
/// # Reading a budget
///
/// `*_burst_size` and `*_period_secs` are a token bucket, **not** a
/// requests-per-window quota. `burst_size` is the bucket's capacity, and one
/// token is replenished every `period_secs`. So `burst_size = 100`,
/// `period_secs = 60` means: up to 100 requests immediately, then a sustained
/// rate of **one request per minute**  -  not 100 per minute. Size
/// `period_secs` from the sustained rate you want (`period_secs = 60 /
/// requests_per_minute`) and `burst_size` from how much bunching you will
/// tolerate.
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Authenticated writes, keyed on the verified issuer.
    pub issuer_burst_size: u32,
    pub issuer_period_secs: u64,
    /// Public reads.
    pub reads_burst_size: u32,
    pub reads_period_secs: u64,
    /// Coarse IP-keyed gate that runs in front of authentication on the write
    /// routes.
    ///
    /// Separate from the read budget so that retuning public reads cannot
    /// silently retighten the write gate, and vice versa. Keep it comfortably
    /// above the issuer budget: every issuer sharing a source IP passes
    /// through it.
    pub write_gate_burst_size: u32,
    pub write_gate_period_secs: u64,
    /// Credential registration.
    ///
    /// Its own budget rather than sharing the issuer tier's: registration is
    /// unauthenticated and persists a row, so it warrants tuning independently
    /// of how fast an authenticated issuer may write.
    pub credentials_burst_size: u32,
    pub credentials_period_secs: u64,
    /// How the client IP is derived for the IP-keyed tiers.
    ///
    /// Has no default: when unset the server refuses to start (fail-closed).
    #[serde(default)]
    pub client_ip_source: Option<ClientIpSource>,
    /// How many `X-Forwarded-For` entries to skip, counting from the right,
    /// before reading the client IP.
    ///
    /// Only meaningful with [`ClientIpSource::RightmostXForwardedFor`].
    ///
    /// This is **not** the number of proxies in the chain. The innermost proxy
    /// writes the client's address into the header, so a single reverse proxy
    /// needs `0`. Each *additional* proxy in front of that one appends another
    /// entry to the right and therefore adds `1`:
    ///
    /// | Chain | `X-Forwarded-For` | `trusted_hops` |
    /// |---|---|---|
    /// | client -> ingress | `client` | `0` |
    /// | client -> CDN -> ingress | `client, cdn` | `1` |
    /// | client -> CDN -> LB -> ingress | `client, cdn, lb` | `2` |
    #[serde(default)]
    pub trusted_hops: usize,
    /// Comma-separated CIDR ranges of the proxies whose forwarding headers are
    /// honoured, e.g. `10.0.0.0/8,192.168.0.0/16`.
    ///
    /// **This is what makes a header source safe.** `X-Forwarded-For` and
    /// `X-Real-IP` are client-supplied: if the request did not arrive from a
    /// proxy, whatever they contain was chosen by the caller. Declaring which
    /// peers are proxies lets the server tell "my proxy told me the client
    /// address" from "the caller asserted an address", and ignore the latter.
    ///
    /// Required and non-empty for `rightmost_x_forwarded_for` and `x_real_ip`;
    /// rejected for `connect_info`, where it would have no meaning. A single
    /// host is expressed as a /32 or /128.
    ///
    /// Parsed as a plain string rather than a list so that it is expressible as
    /// one `APP_*` environment variable, which is the only configuration source
    /// this server reads.
    #[serde(default)]
    pub trusted_proxies: String,
    /// Soft ceiling on the number of live rate-limit buckets per tier.
    ///
    /// Exceeding it logs at `ERROR` after a sweep; nothing is rejected, because
    /// `governor` offers no admission control. Treat it as an alerting
    /// threshold, not a cap.
    pub max_buckets: usize,
    /// How often idle buckets are swept, in seconds.
    pub bucket_eviction_interval_secs: u64,
}

/// Upper bound accepted for `rate_limit.trusted_hops`.
///
/// Real proxy chains are short  -  CDN, load balancer, ingress, mesh sidecar is
/// already four. Anything beyond this is a typo, and accepting it would produce
/// a server that silently keys every request on the peer address.
const MAX_TRUSTED_HOPS: usize = 16;

impl RateLimitConfig {
    /// Validates the rate-limit configuration at startup.
    ///
    /// This is the fail-closed gate: a deployment that has not declared its
    /// network topology does not start, because every possible guess is wrong
    /// for some topology and a wrong guess is either a rate-limit bypass or a
    /// site-wide shared bucket.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let Some(source) = self.client_ip_source else {
            return Err(ConfigError::Message(format!(
                "rate_limit.client_ip_source must be set explicitly (one of: {}). \
                 The server refuses to start without it: the correct value depends on the \
                 network topology it is deployed into, and a wrong guess either lets clients \
                 forge the rate-limit key or collapses every client into one bucket. \
                 Set APP_RATE_LIMIT__CLIENT_IP_SOURCE. See the Rate Limiting section of the README.",
                ClientIpSource::accepted_values(),
            )));
        };

        if self.trusted_hops > 0 && source != ClientIpSource::RightmostXForwardedFor {
            return Err(ConfigError::Message(format!(
                "rate_limit.trusted_hops is set to {} but rate_limit.client_ip_source is \
                 `{source}`. trusted_hops only applies to `rightmost_x_forwarded_for`; leaving \
                 it set here would misrepresent the trust boundary.",
                self.trusted_hops,
            )));
        }

        if self.trusted_hops > MAX_TRUSTED_HOPS {
            return Err(ConfigError::Message(format!(
                "rate_limit.trusted_hops is {} but the maximum accepted is {MAX_TRUSTED_HOPS}. \
                 A hop count larger than any real proxy chain means the client IP can never be \
                 located, so every request would silently fall back to the peer address and share \
                 one bucket.",
                self.trusted_hops,
            )));
        }

        // The trust boundary itself. A header source without a declared set of
        // proxies is not "explicit configuration" at all: the header is
        // client-supplied, so with nothing to check the peer against, any
        // caller can assert any address. Refusing to start is the whole point
        // of #262 - the topology must be stated, not assumed.
        let proxies = self.parse_trusted_proxies()?;
        if source.trusts_headers() && proxies.is_empty() {
            return Err(ConfigError::Message(format!(
                "rate_limit.client_ip_source is `{source}`, which reads a client-supplied \
                 header, but rate_limit.trusted_proxies is empty. Set \
                 APP_RATE_LIMIT__TRUSTED_PROXIES to the CIDR ranges of the proxies in front of \
                 this server (e.g. `10.0.0.0/8`); a single host is a /32 or /128. Without it \
                 the header is only an assertion by the caller, and any client could choose \
                 its own rate-limit bucket."
            )));
        }
        if !source.trusts_headers() && !proxies.is_empty() {
            return Err(ConfigError::Message(format!(
                "rate_limit.trusted_proxies is set but rate_limit.client_ip_source is \
                 `{source}`, which never reads a forwarding header. Leaving it set would \
                 suggest a trust boundary that is not in effect."
            )));
        }

        if self.max_buckets == 0 {
            return Err(ConfigError::Message(
                "rate_limit.max_buckets must be greater than zero.".to_string(),
            ));
        }

        if self.bucket_eviction_interval_secs == 0 {
            return Err(ConfigError::Message(
                "rate_limit.bucket_eviction_interval_secs must be greater than zero.".to_string(),
            ));
        }

        // NOTE: nothing is logged here on purpose. `Config::load` runs before
        // the tracing subscriber is installed, so anything emitted from this
        // function goes nowhere. The header-trust warning is raised by
        // `HttpServer::new` instead  -  see `warn_about_header_trust`.
        Ok(())
    }

    /// Parses [`Self::trusted_proxies`] into CIDR ranges.
    ///
    /// Entries are comma-separated; a bare address is accepted and treated as a
    /// single host (`/32` or `/128`), because writing `10.1.2.3` and meaning
    /// "that one proxy" is the obvious thing to try.
    pub fn parse_trusted_proxies(&self) -> Result<Vec<IpNet>, ConfigError> {
        self.trusted_proxies
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                entry
                    .parse::<IpNet>()
                    .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| {
                        ConfigError::Message(format!(
                            "rate_limit.trusted_proxies entry `{entry}` is not a CIDR range or \
                             IP address (e.g. `10.0.0.0/8`, `2001:db8::/32`, `192.0.2.7`)."
                        ))
                    })
            })
            .collect()
    }

    /// Whether the derived client IP comes from a client-supplied header, and
    /// therefore depends on a proxy in front of this server to sanitise it.
    ///
    /// Reported at startup by `HttpServer::new`, not from [`Self::validate`],
    /// which runs before logging exists.
    pub fn trusts_client_headers(&self) -> bool {
        self.client_ip_source
            .is_some_and(ClientIpSource::trusts_headers)
    }

    /// A rate-limit configuration for tests.
    ///
    /// Shared by the config, runtime and router test modules so that a change
    /// to the shape of this struct does not have to be mirrored in three
    /// hand-written builders. `issuer_burst` sizes the per-issuer tier and
    /// `ip_burst` the three IP-keyed tiers; periods are long enough that no
    /// bucket refills mid-test.
    #[cfg(test)]
    pub(crate) fn for_test(
        source: ClientIpSource,
        trusted_hops: usize,
        issuer_burst: u32,
        ip_burst: u32,
    ) -> Self {
        Self {
            issuer_burst_size: issuer_burst,
            issuer_period_secs: 600,
            reads_burst_size: ip_burst,
            reads_period_secs: 600,
            write_gate_burst_size: ip_burst,
            write_gate_period_secs: 600,
            credentials_burst_size: ip_burst,
            credentials_period_secs: 600,
            client_ip_source: Some(source),
            trusted_hops,
            // Header sources require a declared trust boundary; `PROXY` in the
            // router tests sits in this range.
            trusted_proxies: if source.trusts_headers() {
                "10.0.0.0/8".to_string()
            } else {
                String::new()
            },
            max_buckets: 1_000,
            bucket_eviction_interval_secs: 60,
        }
    }
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
    /// Cache TTL for parsed certificate chains in seconds.
    /// A value of 0 keeps entries in memory indefinitely without expiration.
    pub chain_cache_ttl: u64,
    pub renewal_cron_schedule: String,
    #[serde(default)]
    pub dns_challenge_server_url: Option<String>,
    pub store: CertStoreConfig,
    #[serde(default)]
    pub dns: DnsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertStoreConfig {
    pub source: String,
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
    pub uri: SecretString,
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
    pub url: SecretString,
    /// Validated against the URL scheme at startup.
    #[serde(default)]
    pub backend: DatabaseBackend,
    pub pool: DatabasePoolConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    /// Cache TTL for AWS Secrets Manager entries in seconds.
    /// Setting this to 0 disables caching entirely.
    pub secrets_cache_ttl: u64,
    pub s3_bucket: String,
    pub s3_key_prefix: String,
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
    /// risks described in draft-21 Section 12.7. When disabled, historical resolution
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
        let client = if !self.require_client_auth {
            tracing::info!("Connecting to Redis (no client authentication)");
            RedisClient::open(self.uri.expose_secret())?
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
                self.uri.expose_secret(),
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

/// Environment variables renamed in this release, as `(deprecated, current)`.
///
/// The rate-limit budgets were renamed after the tiers they control, so that a
/// value's name says which route group it affects. The old spellings keep
/// working for one release cycle.
///
/// Deliberately handled here rather than with `#[serde(alias)]`: every budget
/// has a registered default, so an aliased field would be present twice in the
/// deserialized map and serde would reject it as a duplicate field.
pub const DEPRECATED_ENV_KEYS: &[(&str, &str)] = &[
    // `strict_*` previously drove BOTH the write tier and credential
    // registration, so it maps onto both replacements. Mapping it only onto
    // `issuer_*` would silently reset a deliberately-tightened registration
    // limit back to the 10/60s default - loosening an unauthenticated,
    // row-creating endpoint during what is meant to be a no-op rename.
    (
        "APP_RATE_LIMIT__STRICT_BURST_SIZE",
        "APP_RATE_LIMIT__ISSUER_BURST_SIZE",
    ),
    (
        "APP_RATE_LIMIT__STRICT_PERIOD_SECS",
        "APP_RATE_LIMIT__ISSUER_PERIOD_SECS",
    ),
    (
        "APP_RATE_LIMIT__STRICT_BURST_SIZE",
        "APP_RATE_LIMIT__CREDENTIALS_BURST_SIZE",
    ),
    (
        "APP_RATE_LIMIT__STRICT_PERIOD_SECS",
        "APP_RATE_LIMIT__CREDENTIALS_PERIOD_SECS",
    ),
    (
        "APP_RATE_LIMIT__PERMISSIVE_BURST_SIZE",
        "APP_RATE_LIMIT__READS_BURST_SIZE",
    ),
    (
        "APP_RATE_LIMIT__PERMISSIVE_PERIOD_SECS",
        "APP_RATE_LIMIT__READS_PERIOD_SECS",
    ),
    (
        "APP_RATE_LIMIT__UNAUTHENTICATED_BURST_SIZE",
        "APP_RATE_LIMIT__WRITE_GATE_BURST_SIZE",
    ),
    (
        "APP_RATE_LIMIT__UNAUTHENTICATED_PERIOD_SECS",
        "APP_RATE_LIMIT__WRITE_GATE_PERIOD_SECS",
    ),
];

/// Deprecated `APP_*` variables that are currently set in the environment.
///
/// Reported at startup by `HttpServer::new`; config loading itself happens
/// before the tracing subscriber exists, so it cannot warn.
pub fn deprecated_env_keys_in_use() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = DEPRECATED_ENV_KEYS
        .iter()
        .map(|(old, _)| *old)
        .filter(|old| std::env::var_os(old).is_some())
        .collect();
    // One deprecated key can map onto several current ones; report it once.
    names.dedup();
    names
}

/// The current keys a deprecated one now feeds.
pub fn replacements_for(deprecated: &str) -> Vec<&'static str> {
    DEPRECATED_ENV_KEYS
        .iter()
        .filter(|(old, _)| *old == deprecated)
        .map(|(_, new)| *new)
        .collect()
}

/// Maps `APP_SECTION__KEY` to the `section.key` path the config builder uses.
fn env_key_to_config_path(env_key: &str) -> String {
    env_key
        .strip_prefix("APP_")
        .unwrap_or(env_key)
        .replace("__", ".")
        .to_lowercase()
}

/// Copies any deprecated variable onto its current key, unless the current one
/// is also set  -  an operator who has migrated should not be overridden by a
/// stale variable left behind in the environment.
fn apply_deprecated_env_keys(
    mut builder: ConfigBuilder<DefaultState>,
) -> Result<ConfigBuilder<DefaultState>, ConfigError> {
    for (old, new) in DEPRECATED_ENV_KEYS {
        if std::env::var_os(new).is_some() {
            continue;
        }
        if let Some(value) = std::env::var_os(old).and_then(|v| v.into_string().ok()) {
            builder = builder.set_override(env_key_to_config_path(new), value)?;
        }
    }
    Ok(builder)
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

        builder = apply_deprecated_env_keys(builder)?;

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
        config.rate_limit.validate()?;
        Ok(config)
    }

    /// Test-only loader that supplies the one setting which has no default.
    ///
    /// `rate_limit.client_ip_source` is intentionally required in production
    /// (see [`RateLimitConfig::validate`]). Tests that are not about the rate
    /// limiter should not have to care, but they must not be able to paper over
    /// the requirement for production code either  -  hence a separate,
    /// test-only entry point rather than a default in `base_builder`.
    #[cfg(test)]
    pub(crate) fn load_for_test(overrides: &[(&str, &str)]) -> Result<Self, ConfigError> {
        let mut all: Vec<(&str, &str)> = vec![("rate_limit.client_ip_source", "connect_info")];
        all.extend_from_slice(overrides);
        Self::load_from_overrides(&all)
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

    #[cfg(feature = "acme")]
    let default_chain_cache_ttl = crate::utils::cert_manager::DEFAULT_CHAIN_CACHE_TTL.as_secs();
    #[cfg(not(feature = "acme"))]
    let default_chain_cache_ttl = 86400;

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
        .set_default("aws.secrets_cache_ttl", 300)?
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
        .set_default("server.cert.chain_cache_ttl", default_chain_cache_ttl)?
        .set_default("server.cert.renewal_cron_schedule", "0 0 0 * * *")?
        .set_default("server.cert.store.source", "filesystem")?
        .set_default("server.cert.store.certificate_path", default_cert_path)?
        .set_default("server.cert.store.signing_key_path", default_key_path)?
        .set_default("server.cert.store.certificate_key", Option::<String>::None)?
        .set_default("server.cert.store.signing_key_key", Option::<String>::None)?
        .set_default("aws.region", "us-east-1")?
        .set_default("cache.ttl", 5 * 60)?
        .set_default("cache.max_capacity", 100)?
        .set_default("status_list.token_exp_secs", 900)?
        .set_default("status_list.token_ttl_secs", 300)?
        .set_default("status_list.snapshot_retention_secs", 7776000)?
        // Token buckets: `burst_size` is capacity, one token returns every
        // `period_secs`. 10/60 is "10 at once, then one per minute".
        .set_default("rate_limit.issuer_burst_size", 10)?
        .set_default("rate_limit.issuer_period_secs", 60)?
        .set_default("rate_limit.reads_burst_size", 100)?
        .set_default("rate_limit.reads_period_secs", 60)?
        .set_default("rate_limit.write_gate_burst_size", 100)?
        .set_default("rate_limit.write_gate_period_secs", 60)?
        .set_default("rate_limit.credentials_burst_size", 10)?
        .set_default("rate_limit.credentials_period_secs", 60)?
        // NOTE: `rate_limit.client_ip_source` deliberately has no default  -
        // see `RateLimitConfig::validate`. Adding one here re-opens the bug
        // this setting exists to close.
        .set_default("rate_limit.trusted_hops", 0u64)?
        .set_default("rate_limit.max_buckets", 100_000u64)?
        .set_default("rate_limit.bucket_eviction_interval_secs", 60u64)?
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
    use sealed_test::prelude::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_config_loading() {
        // 1. Default configuration loading & helper methods
        let config = Config::load_for_test(&[]).expect("Failed to load default config");

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
        assert_eq!(config.server.cert.store.source, "filesystem");
        assert_eq!(
            config.server.cert.store.certificate_path,
            expected_cert_path
        );
        assert_eq!(config.server.cert.store.signing_key_path, expected_key_path);

        assert_eq!(config.rate_limit.issuer_burst_size, 10);
        assert_eq!(config.rate_limit.issuer_period_secs, 60);
        assert_eq!(config.rate_limit.reads_burst_size, 100);
        assert_eq!(config.rate_limit.reads_period_secs, 60);
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
        let overridden = Config::load_for_test(&[
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
            ("server.cert.store.certificate_path", "/certs/tls.crt"),
            ("server.cert.store.signing_key_path", "/certs/tls.key"),
            ("server.cert.renewal_cron_schedule", "0 0 12 * * *"),
            ("server.cert.dns_challenge_server_url", "http://pebble:8055"),
            ("aws.region", "us-west-2"),
            ("aws.secrets_cache_ttl", "600"),
            ("aws.s3_bucket", "my-custom-bucket"),
            ("aws.s3_key_prefix", "status-list/prod"),
            ("cache.ttl", "600"),
            ("cache.max_capacity", "2000"),
            ("status_list.token_exp_secs", "1800"),
            ("status_list.token_ttl_secs", "600"),
            ("rate_limit.issuer_burst_size", "3"),
            ("rate_limit.issuer_period_secs", "120"),
            ("rate_limit.reads_burst_size", "500"),
            ("rate_limit.reads_period_secs", "10"),
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
        assert_eq!(overridden.aws.secrets_cache_ttl, 600);
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
        assert_eq!(
            overridden.server.cert.store.certificate_path.as_deref(),
            Some("/certs/tls.crt")
        );
        assert_eq!(
            overridden.server.cert.store.signing_key_path.as_deref(),
            Some("/certs/tls.key")
        );
        assert_eq!(overridden.rate_limit.issuer_burst_size, 3);
        assert_eq!(overridden.rate_limit.issuer_period_secs, 120);
        assert_eq!(overridden.rate_limit.reads_burst_size, 500);
        assert_eq!(overridden.rate_limit.reads_period_secs, 10);
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

        // 3. Database backend overrides (MySQL & SQLite)
        let mysql_cfg = Config::load_for_test(&[
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

        let sqlite_cfg = Config::load_for_test(&[
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

        let env_override_cfg = Config::load_for_test(&[("server.cert.dns.provider", "route53")])
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
        let acme_json_cfg = Config::load_for_test(&[
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

        let empty_acme_json_cfg = Config::load_for_test(&[
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
        let invalid_db_res = Config::load_for_test(&[
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
            Config::load_for_test(&[
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
        let default_config = Config::load_for_test(&[]).expect("Failed to load default config");
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
    }

    // ---- rate limiting (#262) -----------------------------------------

    /// The fail-closed invariant: loading with *nothing* supplied for
    /// `client_ip_source` must fail. This deliberately uses
    /// `load_from_overrides` rather than `load_for_test`, because
    /// `load_for_test` is the thing that supplies the value.
    ///
    /// The assertion targets wording unique to `RateLimitConfig::validate`;
    /// asserting on the field name alone would also pass on a `config`-rs
    /// deserialization error and so would not prove the gate exists.
    ///
    /// Runs sealed so the variable can be cleared: `load_from_overrides` reads
    /// the real process environment, so a developer or CI job that exports
    /// `APP_RATE_LIMIT__CLIENT_IP_SOURCE` would otherwise turn this test green
    /// without the gate being present at all.
    #[sealed_test]
    fn test_client_ip_source_unset_refuses_to_start() {
        // SAFETY: `sealed_test` runs this in its own process, so mutating the
        // environment cannot race another test.
        unsafe { std::env::remove_var("APP_RATE_LIMIT__CLIENT_IP_SOURCE") };

        let err = Config::load_from_overrides(&[])
            .expect_err("config with no client_ip_source must fail closed")
            .to_string();
        assert!(
            err.contains("must be set explicitly"),
            "expected the fail-closed message from RateLimitConfig::validate, got: {err}"
        );
        assert!(
            err.contains("connect_info") && err.contains("rightmost_x_forwarded_for"),
            "error should list the accepted values, got: {err}"
        );
    }

    /// Renamed budgets keep working under their previous names for one release
    /// cycle.
    #[sealed_test(env = [
        ("APP_RATE_LIMIT__CLIENT_IP_SOURCE", "connect_info"),
        ("APP_RATE_LIMIT__STRICT_BURST_SIZE", "3"),
        ("APP_RATE_LIMIT__PERMISSIVE_PERIOD_SECS", "17"),
        ("APP_RATE_LIMIT__UNAUTHENTICATED_BURST_SIZE", "42")
    ])]
    fn test_deprecated_rate_limit_env_keys_still_apply() {
        let config = Config::load().expect("deprecated keys should still load");
        assert_eq!(config.rate_limit.issuer_burst_size, 3);
        assert_eq!(config.rate_limit.reads_period_secs, 17);
        assert_eq!(config.rate_limit.write_gate_burst_size, 42);

        // `strict_*` drove credential registration too, so a tightened value
        // must carry over there rather than silently reverting to the default.
        assert_eq!(
            config.rate_limit.credentials_burst_size, 3,
            "a tightened STRICT_BURST_SIZE must not loosen credential registration"
        );

        let in_use = deprecated_env_keys_in_use();
        assert_eq!(
            in_use.len(),
            3,
            "each deprecated key should be reported once, not once per replacement: {in_use:?}"
        );
        assert_eq!(
            replacements_for("APP_RATE_LIMIT__STRICT_BURST_SIZE"),
            vec![
                "APP_RATE_LIMIT__ISSUER_BURST_SIZE",
                "APP_RATE_LIMIT__CREDENTIALS_BURST_SIZE"
            ]
        );
    }

    /// An operator midway through migrating has both spellings exported. The
    /// current one must win, or migrating would appear to have no effect.
    #[sealed_test(env = [
        ("APP_RATE_LIMIT__CLIENT_IP_SOURCE", "connect_info"),
        ("APP_RATE_LIMIT__STRICT_BURST_SIZE", "3"),
        ("APP_RATE_LIMIT__ISSUER_BURST_SIZE", "9")
    ])]
    fn test_current_env_key_wins_over_its_deprecated_alias() {
        let config = Config::load().unwrap();
        assert_eq!(config.rate_limit.issuer_burst_size, 9);
    }

    #[sealed_test(env = [("APP_RATE_LIMIT__CLIENT_IP_SOURCE", "connect_info")])]
    fn test_no_deprecated_keys_reported_when_none_are_set() {
        for (old, _) in DEPRECATED_ENV_KEYS {
            // SAFETY: sealed process.
            unsafe { std::env::remove_var(old) };
        }
        assert!(deprecated_env_keys_in_use().is_empty());
    }

    /// Each tier is tunable on its own; sharing a budget between two tiers
    /// would mean retuning one silently retunes the other.
    #[test]
    fn test_every_tier_has_an_independent_budget() {
        let config = Config::load_for_test(&[
            ("rate_limit.issuer_burst_size", "1"),
            ("rate_limit.reads_burst_size", "2"),
            ("rate_limit.write_gate_burst_size", "3"),
            ("rate_limit.credentials_burst_size", "4"),
        ])
        .unwrap();
        assert_eq!(config.rate_limit.issuer_burst_size, 1);
        assert_eq!(config.rate_limit.reads_burst_size, 2);
        assert_eq!(config.rate_limit.write_gate_burst_size, 3);
        assert_eq!(config.rate_limit.credentials_burst_size, 4);
    }

    /// Every variant must be reachable through the `APP_*` environment
    /// variables, which are the only configuration source the server reads.
    #[test]
    fn test_client_ip_source_variants_round_trip() {
        for (raw, expected) in [
            ("connect_info", ClientIpSource::ConnectInfo),
            (
                "rightmost_x_forwarded_for",
                ClientIpSource::RightmostXForwardedFor,
            ),
            ("x_real_ip", ClientIpSource::XRealIp),
        ] {
            // Header sources additionally require a trust boundary; see
            // `test_header_source_requires_trusted_proxies`.
            let proxies = if expected.trusts_headers() {
                "10.0.0.0/8"
            } else {
                ""
            };
            let config = Config::load_from_overrides(&[
                ("rate_limit.client_ip_source", raw),
                ("rate_limit.trusted_proxies", proxies),
            ])
            .unwrap_or_else(|e| panic!("`{raw}` should be accepted: {e}"));
            assert_eq!(config.rate_limit.client_ip_source, Some(expected));
        }
    }

    #[test]
    fn test_trusted_hops_configurable_via_env_style_override() {
        let config = Config::load_from_overrides(&[
            (
                "APP_RATE_LIMIT__CLIENT_IP_SOURCE",
                "rightmost_x_forwarded_for",
            ),
            ("APP_RATE_LIMIT__TRUSTED_PROXIES", "10.0.0.0/8"),
            ("APP_RATE_LIMIT__TRUSTED_HOPS", "2"),
        ])
        .expect("trusted_hops must be expressible as a flat env var");
        assert_eq!(
            config.rate_limit.client_ip_source,
            Some(ClientIpSource::RightmostXForwardedFor)
        );
        assert_eq!(config.rate_limit.trusted_hops, 2);
    }

    #[test]
    fn test_unknown_client_ip_source_is_rejected() {
        let result =
            Config::load_from_overrides(&[("rate_limit.client_ip_source", "trust_me_bro")]);
        assert!(result.is_err(), "unknown variants must not load");
    }

    /// `trusted_hops` is only meaningful for the XFF source. Silently ignoring
    /// it elsewhere would let an operator believe they had configured a trust
    /// boundary that is not in effect.
    #[test]
    fn test_trusted_hops_rejected_for_non_xff_source() {
        let err = Config::load_from_overrides(&[
            ("rate_limit.client_ip_source", "connect_info"),
            ("rate_limit.trusted_hops", "1"),
        ])
        .expect_err("trusted_hops with connect_info must be rejected")
        .to_string();
        assert!(err.contains("trusted_hops"), "got: {err}");
    }

    /// A hop count larger than any real proxy chain means the client IP can
    /// never be located, so every request would quietly share the peer-address
    /// bucket. Rejecting is the only way an operator learns about the typo.
    #[test]
    fn test_trusted_hops_above_the_maximum_is_rejected() {
        let err = Config::load_from_overrides(&[
            ("rate_limit.client_ip_source", "rightmost_x_forwarded_for"),
            ("rate_limit.trusted_proxies", "10.0.0.0/8"),
            ("rate_limit.trusted_hops", "9999"),
        ])
        .expect_err("an implausible hop count must be rejected")
        .to_string();
        assert!(err.contains("trusted_hops"), "got: {err}");

        assert!(
            Config::load_from_overrides(&[
                ("rate_limit.client_ip_source", "rightmost_x_forwarded_for",),
                ("rate_limit.trusted_proxies", "10.0.0.0/8"),
                ("rate_limit.trusted_hops", &MAX_TRUSTED_HOPS.to_string()),
            ])
            .is_ok(),
            "the maximum itself must still be accepted"
        );
    }

    /// The trust boundary itself: a header source without declared proxies is
    /// not configuration, it is an invitation. Selecting one must fail closed.
    #[test]
    fn test_header_source_requires_trusted_proxies() {
        for source in ["rightmost_x_forwarded_for", "x_real_ip"] {
            let err = Config::load_from_overrides(&[("rate_limit.client_ip_source", source)])
                .expect_err("a header source without trusted_proxies must fail closed")
                .to_string();
            assert!(
                err.contains("trusted_proxies"),
                "`{source}` should name the missing setting, got: {err}"
            );
        }
    }

    /// The mirror: declaring proxies for a source that reads no header would
    /// suggest a boundary that is not in effect.
    #[test]
    fn test_connect_info_rejects_trusted_proxies() {
        let err = Config::load_from_overrides(&[
            ("rate_limit.client_ip_source", "connect_info"),
            ("rate_limit.trusted_proxies", "10.0.0.0/8"),
        ])
        .expect_err("trusted_proxies with connect_info must be rejected")
        .to_string();
        assert!(err.contains("trusted_proxies"), "got: {err}");
    }

    #[test]
    fn test_trusted_proxies_accepts_cidrs_and_bare_addresses() {
        let config = Config::load_from_overrides(&[
            ("rate_limit.client_ip_source", "x_real_ip"),
            (
                "rate_limit.trusted_proxies",
                " 10.0.0.0/8 , 192.0.2.7 , 2001:db8::/32 ",
            ),
        ])
        .expect("CIDRs, bare addresses and whitespace should all be accepted");
        let parsed = config.rate_limit.parse_trusted_proxies().unwrap();
        assert_eq!(parsed.len(), 3);
        assert!(parsed[1].contains(&"192.0.2.7".parse::<IpAddr>().unwrap()));
        assert!(!parsed[1].contains(&"192.0.2.8".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_malformed_trusted_proxy_is_rejected() {
        let err = Config::load_from_overrides(&[
            ("rate_limit.client_ip_source", "x_real_ip"),
            ("rate_limit.trusted_proxies", "10.0.0.0/8,not-an-address"),
        ])
        .expect_err("a malformed entry must be rejected")
        .to_string();
        assert!(err.contains("not-an-address"), "got: {err}");
    }

    /// The write gate must be tunable without touching the read tier, so that
    /// changing read throughput cannot silently retighten anonymous writes.
    #[test]
    fn test_unauthenticated_tier_is_tunable_independently_of_reads() {
        let config = Config::load_for_test(&[]).unwrap();
        assert_eq!(config.rate_limit.write_gate_burst_size, 100);
        assert_eq!(config.rate_limit.write_gate_period_secs, 60);
        assert_eq!(config.rate_limit.credentials_burst_size, 10);
        assert_eq!(config.rate_limit.credentials_period_secs, 60);
    }

    #[test]
    fn test_bucket_bounds_have_safe_defaults_and_reject_zero() {
        let config = Config::load_for_test(&[]).unwrap();
        assert_eq!(config.rate_limit.max_buckets, 100_000);
        assert_eq!(config.rate_limit.bucket_eviction_interval_secs, 60);

        assert!(
            Config::load_for_test(&[("rate_limit.max_buckets", "0")]).is_err(),
            "max_buckets=0 would disable the backstop entirely"
        );
        assert!(
            Config::load_for_test(&[("rate_limit.bucket_eviction_interval_secs", "0")]).is_err(),
            "a zero eviction interval would spin"
        );
    }
}
