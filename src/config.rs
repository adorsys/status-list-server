use std::{collections::HashMap, fmt, marker::PhantomData, time::Duration};

use config::{Config as ConfigLib, ConfigError, Environment};
use redis::{
    Client as RedisClient, ClientTlsConfig, RedisResult, TlsCertificates,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_aux::field_attributes::deserialize_vec_from_string_or_vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseBackend {
    #[default]
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

    /// Returns the lowercase name matching the config value (`"postgres"`,
    /// `"mysql"`, `"sqlite"`), useful for user-facing messages.
    pub fn as_str(&self) -> &'static str {
        match self {
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
    /// Resolve the DNS provider to use and validate that its settings are present.
    pub fn resolve(&self, app_env: &str) -> Result<DnsProviderKind, ConfigError> {
        let kind = self.provider.unwrap_or(if app_env == ENV_PRODUCTION {
            DnsProviderKind::Route53
        } else {
            DnsProviderKind::Pebble
        });

        let missing = match kind {
            DnsProviderKind::Cloudflare if self.cloudflare.is_none() => Some("dns.cloudflare"),
            DnsProviderKind::Gcloud
                if self.gcloud.as_ref().is_none_or(|g| {
                    g.service_account_key
                        .as_ref()
                        .is_none_or(|k| k.expose_secret().trim().is_empty())
                        && non_empty(&g.service_account_key_path).is_none()
                }) =>
            {
                Some("dns.gcloud")
            }
            DnsProviderKind::Azure if self.azure.is_none() => Some("dns.azure"),
            DnsProviderKind::Acmedns if self.acmedns.is_none() => Some("dns.acmedns"),
            _ => None,
        };
        if let Some(section) = missing {
            return Err(ConfigError::Message(format!(
                "DNS provider {kind:?} selected but the server.cert.{section} settings are missing"
            )));
        }
        match kind {
            DnsProviderKind::Cloudflare => {
                if let Some(cloudflare) = &self.cloudflare {
                    cloudflare.validate()?;
                }
            }
            DnsProviderKind::Azure => {
                if let Some(azure) = &self.azure {
                    azure.validate()?;
                }
            }
            DnsProviderKind::Acmedns => {
                if let Some(acmedns) = &self.acmedns {
                    acmedns.validate()?;
                }
            }
            _ => {}
        }
        Ok(kind)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub uri: SecretString,
    pub require_client_auth: bool,
    pub cert_cache_ttl: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: SecretString,
    /// Backend selection is used to validate the URL scheme at startup.
    #[serde(default)]
    pub backend: DatabaseBackend,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub secrets_cache_ttl: u64,
    pub s3_bucket: String,
    pub s3_key_prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    pub ttl: u64,
    pub max_capacity: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatusListConfig {
    pub token_exp_secs: u64,
    pub token_ttl_secs: u64,
    /// Retention period for historical status list snapshots in seconds.
    /// Snapshots older than this will be deleted by a scheduled cleanup task.
    /// Default is 90 days (7776000 seconds).
    ///
    /// **Privacy note:** Set to 0 to disable historical snapshots entirely.
    /// This prevents unbounded database growth and mitigates timing leak
    /// risks described in draft-21 §12.7. When disabled, historical resolution
    /// via `?time=` query parameter will not be available.
    pub history_retention_secs: u64,
}

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

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        // Build the config
        let config = ConfigLib::builder()
            // Set default values
            .set_default("server.host", "localhost")?
            .set_default("server.domain", "localhost")?
            .set_default("server.port", 8000)?
            .set_default("server.enable_metrics", false)?
            .set_default("server.aggregation_uri", Option::<String>::None)?
            .set_default(
                "database.url",
                "postgres://postgres:postgres@localhost:5432/status-list",
            )?
            .set_default("database.backend", "postgres")?
            .set_default("redis.uri", "redis://localhost:6379")?
            .set_default("redis.require_client_auth", false)?
            .set_default("redis.cert_cache_ttl", 3600)? // Default 1 hour
            .set_default("aws.secrets_cache_ttl", 300)? // Default 5 minutes
            .set_default("aws.s3_bucket", "status-list-adorsys")?
            .set_default("aws.s3_key_prefix", "")?
            .set_default("server.cert.provisioning_strategy", "acme")?
            .set_default("server.cert.email", "admin@example.com")?
            .set_default("server.cert.eku", vec![1, 3, 6, 1, 5, 5, 7, 3, 30])?
            .set_default("server.cert.organization", "adorsys GmbH & CO KG")?
            .set_default(
                "server.cert.acme_directory_url",
                "https://acme-v02.api.letsencrypt.org/directory",
            )?
            .set_default(
                "server.cert.chain_cache_ttl",
                crate::utils::cert_manager::DEFAULT_CHAIN_CACHE_TTL.as_secs(),
            )?
            .set_default("server.cert.renewal_cron_schedule", "0 0 0 * * *")?
            .set_default("server.cert.store.source", "filesystem")?
            .set_default("server.cert.store.certificate_path", Option::<String>::None)?
            .set_default("server.cert.store.signing_key_path", Option::<String>::None)?
            .set_default("server.cert.store.certificate_key", Option::<String>::None)?
            .set_default("server.cert.store.signing_key_key", Option::<String>::None)?
            .set_default("aws.region", "us-east-1")?
            .set_default("cache.ttl", 5 * 60)?
            .set_default("cache.max_capacity", 100)?
            .set_default("status_list.token_exp_secs", 900)? // 15 minutes
            .set_default("status_list.token_ttl_secs", 300)? // 5 minutes
            .set_default("status_list.history_retention_secs", 7776000)? // 90 days
            // Override config values via environment variables
            // The environment variables should be prefixed with 'APP_' and use '__' as a separator
            // Example: APP_REDIS__REQUIRE_CLIENT_AUTH=false
            .add_source(
                Environment::with_prefix("APP")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?;

        let config: Config = config.try_deserialize()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealed_test::prelude::*;
    use secrecy::ExposeSecret;

    #[sealed_test]
    fn test_default_config() {
        let config = Config::load().expect("Failed to load config");

        assert_eq!(config.server.host, "localhost");
        assert_eq!(config.server.port, 8000);
        assert_eq!(
            config.database.url.expose_secret(),
            "postgres://postgres:postgres@localhost:5432/status-list"
        );
        assert_eq!(config.database.backend, DatabaseBackend::Postgres);
        assert_eq!(config.redis.uri.expose_secret(), "redis://localhost:6379");
        assert!(!config.redis.require_client_auth);
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
        assert_eq!(config.server.cert.provisioning_strategy, "acme");
        assert_eq!(config.server.cert.store.source, "filesystem");
        assert_eq!(config.server.cert.store.certificate_path, None);
        assert_eq!(config.server.cert.store.signing_key_path, None);
        assert_eq!(config.server.aggregation_uri, None);
        assert_eq!(config.server.cert.dns.provider, None);
    }

    #[sealed_test(env = [
        ("APP_SERVER__AGGREGATION_URI", "https://example.com/aggregation"),
    ])]
    fn test_aggregation_uri_env_override() {
        let config = Config::load().expect("Failed to load config");

        assert_eq!(
            config.server.aggregation_uri.as_deref(),
            Some("https://example.com/aggregation")
        );
    }

    #[test]
    fn test_dns_provider_defaults_per_environment() {
        let dns = DnsConfig::default();

        assert_eq!(dns.resolve("production").unwrap(), DnsProviderKind::Route53);
        assert_eq!(dns.resolve("development").unwrap(), DnsProviderKind::Pebble);
    }

    #[test]
    fn test_dns_provider_explicit_selection_overrides_environment() {
        let dns = DnsConfig {
            provider: Some(DnsProviderKind::Pebble),
            ..Default::default()
        };

        assert_eq!(dns.resolve("production").unwrap(), DnsProviderKind::Pebble);
    }

    #[test]
    fn test_dns_provider_requires_its_settings() {
        let dns = DnsConfig {
            provider: Some(DnsProviderKind::Cloudflare),
            ..Default::default()
        };
        let err = dns.resolve("production").unwrap_err();
        assert!(err.to_string().contains("dns.cloudflare"));

        let dns = DnsConfig {
            provider: Some(DnsProviderKind::Cloudflare),
            cloudflare: Some(CloudflareDnsConfig {
                api_token: "token".into(),
            }),
            ..Default::default()
        };
        assert_eq!(
            dns.resolve("production").unwrap(),
            DnsProviderKind::Cloudflare
        );

        let dns = DnsConfig {
            provider: Some(DnsProviderKind::Acmedns),
            ..Default::default()
        };
        let err = dns.resolve("production").unwrap_err();
        assert!(err.to_string().contains("dns.acmedns"));

        // Legacy single-account config still resolves unchanged
        let acmedns = |cfg: AcmeDnsConfig| DnsConfig {
            provider: Some(DnsProviderKind::Acmedns),
            acmedns: Some(cfg),
            ..Default::default()
        };
        let dns = acmedns(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: Some("user".into()),
            password: Some("password".into()),
            subdomain: Some("subdomain".into()),
            accounts: Default::default(),
        });
        assert_eq!(dns.resolve("production").unwrap(), DnsProviderKind::Acmedns);

        // A per-domain accounts map alone is enough
        let account = AcmeDnsAccount {
            username: "user".into(),
            password: "password".into(),
            subdomain: "subdomain".into(),
        };
        let dns = acmedns(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: None,
            password: None,
            subdomain: None,
            accounts: [("status.example.com".to_string(), account)].into(),
        });
        assert_eq!(dns.resolve("production").unwrap(), DnsProviderKind::Acmedns);

        // A partial default account is rejected
        let dns = acmedns(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: Some("user".into()),
            password: None,
            subdomain: None,
            accounts: Default::default(),
        });
        let err = dns.resolve("production").unwrap_err();
        assert!(err.to_string().contains("must be set together"));

        // Neither a default account nor a map is rejected
        let dns = acmedns(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: None,
            password: None,
            subdomain: None,
            accounts: Default::default(),
        });
        let err = dns.resolve("production").unwrap_err();
        assert!(err.to_string().contains("default account"));

        // Gcloud needs the key inline or as a file path
        let dns = DnsConfig {
            provider: Some(DnsProviderKind::Gcloud),
            gcloud: Some(GcloudDnsConfig {
                service_account_key: None,
                service_account_key_path: None,
            }),
            ..Default::default()
        };
        let err = dns.resolve("production").unwrap_err();
        assert!(err.to_string().contains("dns.gcloud"));

        let dns = DnsConfig {
            provider: Some(DnsProviderKind::Gcloud),
            gcloud: Some(GcloudDnsConfig {
                service_account_key: None,
                service_account_key_path: Some("/etc/gcloud/key.json".into()),
            }),
            ..Default::default()
        };
        assert_eq!(dns.resolve("production").unwrap(), DnsProviderKind::Gcloud);
    }

    #[test]
    fn test_dns_provider_rejects_empty_required_fields() {
        // Azure names exactly the empty fields
        let azure = |tenant_id: &str, subscription_id: &str| DnsConfig {
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
        let err = azure("", " ")
            .resolve("production")
            .unwrap_err()
            .to_string();
        assert!(err.contains("tenant_id"));
        assert!(err.contains("subscription_id"));
        assert!(!err.contains("client_id"));
        assert_eq!(
            azure("tenant", "sub").resolve("production").unwrap(),
            DnsProviderKind::Azure
        );

        // Cloudflare rejects an empty api_token
        let dns = DnsConfig {
            provider: Some(DnsProviderKind::Cloudflare),
            cloudflare: Some(CloudflareDnsConfig {
                api_token: "".into(),
            }),
            ..Default::default()
        };
        let err = dns.resolve("production").unwrap_err();
        assert!(err.to_string().contains("api_token"));

        // ACME-DNS rejects an empty server_url
        let acmedns = |cfg: AcmeDnsConfig| DnsConfig {
            provider: Some(DnsProviderKind::Acmedns),
            acmedns: Some(cfg),
            ..Default::default()
        };
        let dns = acmedns(AcmeDnsConfig {
            server_url: " ".into(),
            username: Some("user".into()),
            password: Some("password".into()),
            subdomain: Some("subdomain".into()),
            accounts: Default::default(),
        });
        let err = dns.resolve("production").unwrap_err();
        assert!(err.to_string().contains("server_url"));

        // An empty default-account field counts as unset, so the account
        // is partial rather than silently unusable
        let dns = acmedns(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: Some("user".into()),
            password: Some("password".into()),
            subdomain: Some("".into()),
            accounts: Default::default(),
        });
        let err = dns.resolve("production").unwrap_err();
        assert!(err.to_string().contains("must be set together"));

        // Gcloud with both key sources empty counts as missing
        let dns = DnsConfig {
            provider: Some(DnsProviderKind::Gcloud),
            gcloud: Some(GcloudDnsConfig {
                service_account_key: Some("".into()),
                service_account_key_path: Some(" ".into()),
            }),
            ..Default::default()
        };
        let err = dns.resolve("production").unwrap_err();
        assert!(err.to_string().contains("dns.gcloud"));
    }

    #[test]
    fn test_acme_dns_rejects_unusable_account_entries() {
        let acmedns = |accounts: HashMap<String, AcmeDnsAccount>| DnsConfig {
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
        let account = |username: &str, subdomain: &str| AcmeDnsAccount {
            username: username.into(),
            password: "password".into(),
            subdomain: subdomain.into(),
        };

        // An entry with empty fields is rejected, naming the domain and fields
        let dns = acmedns([("status.example.com".to_string(), account("", " "))].into());
        let err = dns.resolve("production").unwrap_err().to_string();
        assert!(err.contains("status.example.com"));
        assert!(err.contains("username"));
        assert!(err.contains("subdomain"));
        assert!(!err.contains("password"));

        // A key that does not name a domain is rejected
        for key in ["", "  ", "*.", "."] {
            let dns = acmedns([(key.to_string(), account("user", "sub"))].into());
            let err = dns.resolve("production").unwrap_err().to_string();
            assert!(err.contains("does not name a domain"), "key {key:?}: {err}");
        }

        // A usable entry passes
        let dns = acmedns([("status.example.com".to_string(), account("user", "sub"))].into());
        assert_eq!(dns.resolve("production").unwrap(), DnsProviderKind::Acmedns);
    }

    #[sealed_test(env = [
        ("APP_SERVER__CERT__DNS__ACMEDNS__SERVER_URL", "https://auth.example.org"),
        ("APP_SERVER__CERT__DNS__ACMEDNS__ACCOUNTS", r#"{
            "a.example.com": {"username": "u1", "password": "p1", "subdomain": "s1"},
            "b.example.com": {"username": "u2", "password": "p2", "subdomain": "s2"}
        }"#),
    ])]
    fn test_acme_dns_accounts_parse_from_env_json() {
        let config = Config::load().expect("Failed to load config");

        let acmedns = config.server.cert.dns.acmedns.expect("acmedns settings");
        assert_eq!(acmedns.server_url, "https://auth.example.org");
        assert!(acmedns.default_account().is_none());
        assert_eq!(acmedns.accounts.len(), 2);
        let account = &acmedns.accounts["b.example.com"];
        assert_eq!(account.username, "u2");
        assert_eq!(account.password.expose_secret(), "p2");
        assert_eq!(account.subdomain, "s2");
    }

    #[sealed_test(env = [
        ("APP_SERVER__CERT__DNS__ACMEDNS__SERVER_URL", "https://auth.example.org"),
        ("APP_SERVER__CERT__DNS__ACMEDNS__ACCOUNTS", r#"{"a.example.com": not valid json"#),
    ])]
    fn test_acme_dns_accounts_reject_malformed_json() {
        Config::load().expect_err("malformed accounts JSON must fail config loading");
    }

    #[sealed_test(env = [
        ("APP_SERVER__CERT__DNS__ACMEDNS__SERVER_URL", "https://auth.example.org"),
        ("APP_SERVER__CERT__DNS__ACMEDNS__ACCOUNTS", ""),
    ])]
    fn test_acme_dns_accounts_empty_env_var_means_no_accounts() {
        let config = Config::load().expect("Failed to load config");

        let acmedns = config.server.cert.dns.acmedns.expect("acmedns settings");
        assert!(acmedns.accounts.is_empty());
    }

    #[sealed_test(env = [
        ("APP_SERVER__CERT__DNS__PROVIDER", "route53"),
    ])]
    fn test_dns_provider_env_override() {
        let config = Config::load().expect("Failed to load config");

        assert_eq!(
            config.server.cert.dns.provider,
            Some(DnsProviderKind::Route53)
        );
    }

    #[sealed_test(env = [
        ("APP_SERVER__HOST", "0.0.0.0"),
        ("APP_SERVER__PORT", "5002"),
        ("APP_DATABASE__URL", "postgres://user:password@localhost:5432/status-list"),
        ("APP_DATABASE__BACKEND", "postgres"),
        ("APP_REDIS__URI", "rediss://user:password@localhost:6379/redis"),
        ("APP_REDIS__REQUIRE_CLIENT_AUTH", "true"),
        ("APP_SERVER__CERT__EMAIL", "test@gmail.com"),
        ("APP_SERVER__CERT__ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"),
    ])]
    fn test_env_config() {
        // Test configuration overrides via environment variables
        let config = Config::load().expect("Failed to load config");

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 5002);
        assert_eq!(
            config.database.url.expose_secret(),
            "postgres://user:password@localhost:5432/status-list"
        );
        assert_eq!(
            config.redis.uri.expose_secret(),
            "rediss://user:password@localhost:6379/redis"
        );
        assert!(config.redis.require_client_auth);
        assert_eq!(config.server.cert.email, "test@gmail.com");
        assert_eq!(
            config.server.cert.acme_directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
    }

    #[sealed_test(env = [
        ("APP_REDIS__URI", "rediss://user:password@localhost:6379/redis"),
        ("APP_REDIS__REQUIRE_CLIENT_AUTH", "true"),
        ("APP_SERVER__CERT__EMAIL", "test@gmail.com"),
        ("APP_SERVER__CERT__ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"),
        ("APP_SERVER__CERT__ORGANIZATION", "Test Org"),
        ("APP_SERVER__CERT__EKU", "1,3,6,1,5,5,7,3,30"),
        ("APP_AWS__REGION", "us-west-2"),
        ("APP_AWS__SECRETS_CACHE_TTL", "600"),
        ("APP_AWS__S3_BUCKET", "my-custom-bucket"),
        ("APP_AWS__S3_KEY_PREFIX", "status-list/prod"),
        ("APP_CACHE__TTL", "600"),
        ("APP_CACHE__MAX_CAPACITY", "2000"),
    ])]
    fn test_env_config_with_tls() {
        let config = Config::load().expect("Failed to load config");

        assert_eq!(config.server.host, "localhost");
        assert_eq!(config.server.port, 8000);
        assert_eq!(
            config.database.url.expose_secret(),
            "postgres://postgres:postgres@localhost:5432/status-list"
        );
        assert_eq!(
            config.redis.uri.expose_secret(),
            "rediss://user:password@localhost:6379/redis"
        );
        assert!(config.redis.require_client_auth);
        assert_eq!(config.server.cert.email, "test@gmail.com");
        assert_eq!(
            config.server.cert.acme_directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(config.aws.region, "us-west-2");
        assert_eq!(config.aws.secrets_cache_ttl, 600);
        assert_eq!(config.aws.s3_bucket, "my-custom-bucket");
        assert_eq!(config.aws.s3_key_prefix, "status-list/prod");
        assert_eq!(config.cache.ttl, 600);
        assert_eq!(config.cache.max_capacity, 2000);
    }

    #[sealed_test(env = [
        ("APP_AWS__S3_BUCKET", "my-bucket"),
        ("APP_AWS__S3_KEY_PREFIX", "prefix"),
        ("APP_STATUS_LIST__TOKEN_EXP_SECS", "1800"),
        ("APP_STATUS_LIST__TOKEN_TTL_SECS", "600"),
        ("APP_SERVER__CERT__RENEWAL_CRON_SCHEDULE", "0 0 12 * * *"),
        ("APP_SERVER__CERT__DNS_CHALLENGE_SERVER_URL", "http://pebble:8055"),
        ("APP_SERVER__CERT__PROVISIONING_STRATEGY", "store"),
        ("APP_SERVER__CERT__STORE__CERTIFICATE_PATH", "/certs/tls.crt"),
        ("APP_SERVER__CERT__STORE__SIGNING_KEY_PATH", "/certs/tls.key"),
    ])]
    fn test_new_config_fields_env_override() {
        let config = Config::load().expect("Failed to load config");

        assert_eq!(config.aws.s3_bucket, "my-bucket");
        assert_eq!(config.aws.s3_key_prefix, "prefix");
        assert_eq!(config.status_list.token_exp_secs, 1800);
        assert_eq!(config.status_list.token_ttl_secs, 600);
        assert_eq!(config.server.cert.renewal_cron_schedule, "0 0 12 * * *");
        assert_eq!(
            config.server.cert.dns_challenge_server_url.as_deref(),
            Some("http://pebble:8055")
        );
        assert_eq!(config.server.cert.provisioning_strategy, "store");
        assert_eq!(
            config.server.cert.store.certificate_path.as_deref(),
            Some("/certs/tls.crt")
        );
        assert_eq!(
            config.server.cert.store.signing_key_path.as_deref(),
            Some("/certs/tls.key")
        );
    }

    #[sealed_test(env = [
        ("APP_DATABASE__BACKEND", "mysql"),
        ("APP_DATABASE__URL", "mysql://user:password@localhost:3306/status-list"),
    ])]
    fn test_mysql_backend_config() {
        let config = Config::load().expect("Failed to load config");
        assert_eq!(config.database.backend, DatabaseBackend::MySql);
        assert_eq!(
            config.database.url.expose_secret(),
            "mysql://user:password@localhost:3306/status-list"
        );
    }

    #[sealed_test(env = [
        ("APP_DATABASE__BACKEND", "sqlite"),
        ("APP_DATABASE__URL", "sqlite::memory:"),
    ])]
    fn test_sqlite_backend_config() {
        let config = Config::load().expect("Failed to load config");
        assert_eq!(config.database.backend, DatabaseBackend::Sqlite);
        assert_eq!(config.database.url.expose_secret(), "sqlite::memory:");
    }

    #[test]
    fn test_database_backend_validate_url_scheme() {
        assert!(
            DatabaseBackend::Postgres
                .validate_url_scheme("postgres://postgres:postgres@localhost:5432/status-list")
        );
        assert!(
            DatabaseBackend::Postgres
                .validate_url_scheme("postgresql://postgres:postgres@localhost:5432/status-list")
        );
        assert!(
            DatabaseBackend::MySql
                .validate_url_scheme("mysql://user:password@localhost:3306/status-list")
        );
        assert!(DatabaseBackend::Sqlite.validate_url_scheme("sqlite::memory:"));
        assert!(
            !DatabaseBackend::MySql
                .validate_url_scheme("postgres://postgres:postgres@localhost:5432/status-list")
        );
    }

    #[test]
    fn test_database_backend_default() {
        let backend = DatabaseBackend::default();
        assert_eq!(backend, DatabaseBackend::Postgres);
    }

    #[test]
    fn test_database_backend_as_str() {
        assert_eq!(DatabaseBackend::Postgres.as_str(), "postgres");
        assert_eq!(DatabaseBackend::MySql.as_str(), "mysql");
        assert_eq!(DatabaseBackend::Sqlite.as_str(), "sqlite");
    }

    #[sealed_test(env = [
        ("APP_DATABASE__BACKEND", "redis"),
        ("APP_DATABASE__URL", "postgres://user:password@localhost:5432/status-list"),
    ])]
    fn test_invalid_database_backend_config() {
        let result = Config::load();
        assert!(
            result.is_err(),
            "an unknown backend value should fail to load config"
        );
    }
}
