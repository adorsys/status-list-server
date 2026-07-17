use std::time::Duration;

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
    pub rate_limit: RateLimitConfig,
    pub limits: LimitsConfig,
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
    #[serde(default)]
    pub dns: DnsConfig,
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
    pub username: String,
    pub password: SecretString,
    /// Subdomain returned by the ACME-DNS registration
    pub subdomain: String,
}

/// Report the required fields whose value is empty, so misconfigurations
/// (e.g. an env var set to an empty string) fail at startup instead of
/// surfacing as opaque API errors at the first renewal
fn empty_fields(fields: &[(&'static str, bool)]) -> Option<String> {
    let empty: Vec<&str> = fields
        .iter()
        .filter_map(|&(name, is_empty)| is_empty.then_some(name))
        .collect();
    (!empty.is_empty()).then(|| empty.join(", "))
}

impl AzureDnsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(fields) = empty_fields(&[
            ("tenant_id", self.tenant_id.trim().is_empty()),
            ("client_id", self.client_id.trim().is_empty()),
            (
                "client_secret",
                self.client_secret.expose_secret().trim().is_empty(),
            ),
            ("subscription_id", self.subscription_id.trim().is_empty()),
            ("resource_group", self.resource_group.trim().is_empty()),
        ]) {
            return Err(ConfigError::Message(format!(
                "Azure DNS settings have empty required fields: {fields}"
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

impl AcmeDnsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(fields) = empty_fields(&[
            ("server_url", self.server_url.trim().is_empty()),
            ("username", self.username.trim().is_empty()),
            ("password", self.password.expose_secret().trim().is_empty()),
            ("subdomain", self.subdomain.trim().is_empty()),
        ]) {
            return Err(ConfigError::Message(format!(
                "ACME-DNS settings have empty required fields: {fields}"
            )));
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
            // Empty key sources count as unset
            DnsProviderKind::Gcloud
                if self.gcloud.as_ref().is_none_or(|g| {
                    g.service_account_key
                        .as_ref()
                        .is_none_or(|k| k.expose_secret().trim().is_empty())
                        && g.service_account_key_path
                            .as_ref()
                            .is_none_or(|p| p.trim().is_empty())
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
            .set_default("aws.region", "us-east-1")?
            .set_default("cache.ttl", 5 * 60)?
            .set_default("cache.max_capacity", 100)?
            .set_default("status_list.token_exp_secs", 900)? // 15 minutes
            .set_default("status_list.token_ttl_secs", 300)? // 5 minutes
            .set_default("rate_limit.strict_burst_size", 10)?
            .set_default("rate_limit.strict_period_secs", 60)?
            .set_default("rate_limit.permissive_burst_size", 100)?
            .set_default("rate_limit.permissive_period_secs", 60)?
            .set_default("limits.max_body_size_bytes", 2_097_152)? // 2 MiB
            .set_default("limits.max_status_index", 100_000)?
            .set_default("limits.max_statuses_per_request", 5_000)?
            .set_default("limits.max_serialized_list_size", 1_048_576)? // 1 MiB
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
        assert_eq!(config.server.aggregation_uri, None);
        assert_eq!(config.rate_limit.strict_burst_size, 10);
        assert_eq!(config.rate_limit.strict_period_secs, 60);
        assert_eq!(config.rate_limit.permissive_burst_size, 100);
        assert_eq!(config.rate_limit.permissive_period_secs, 60);
        assert_eq!(config.limits.max_body_size_bytes, 2_097_152);
        assert_eq!(config.limits.max_status_index, 100_000);
        assert_eq!(config.limits.max_statuses_per_request, 5_000);
        assert_eq!(config.limits.max_serialized_list_size, 1_048_576);
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

        // ACME-DNS names exactly the empty fields
        let dns = DnsConfig {
            provider: Some(DnsProviderKind::Acmedns),
            acmedns: Some(AcmeDnsConfig {
                server_url: " ".into(),
                username: "".into(),
                password: "password".into(),
                subdomain: "subdomain".into(),
            }),
            ..Default::default()
        };
        let err = dns.resolve("production").unwrap_err().to_string();
        assert!(err.contains("server_url"));
        assert!(err.contains("username"));
        assert!(!err.contains("subdomain"));

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
    }

    #[sealed_test]
    fn test_default_rate_limits_and_bounds() {
        unsafe { std::env::remove_var("APP_RATE_LIMIT__STRICT_BURST_SIZE") };
        unsafe { std::env::remove_var("APP_LIMITS__MAX_BODY_SIZE_BYTES") };
        let config = Config::load().expect("Failed to load config");

        assert_eq!(config.rate_limit.strict_burst_size, 10);
        assert_eq!(config.rate_limit.strict_period_secs, 60);
        assert_eq!(config.rate_limit.permissive_burst_size, 100);
        assert_eq!(config.rate_limit.permissive_period_secs, 60);
        assert_eq!(config.limits.max_body_size_bytes, 2_097_152);
        assert_eq!(config.limits.max_status_index, 100_000);
        assert_eq!(config.limits.max_statuses_per_request, 5_000);
        assert_eq!(config.limits.max_serialized_list_size, 1_048_576);
    }

    #[sealed_test(env = [
        ("APP_RATE_LIMIT__STRICT_BURST_SIZE", "3"),
        ("APP_RATE_LIMIT__STRICT_PERIOD_SECS", "120"),
        ("APP_RATE_LIMIT__PERMISSIVE_BURST_SIZE", "500"),
        ("APP_RATE_LIMIT__PERMISSIVE_PERIOD_SECS", "10"),
        ("APP_LIMITS__MAX_BODY_SIZE_BYTES", "65536"),
        ("APP_LIMITS__MAX_STATUS_INDEX", "4096"),
        ("APP_LIMITS__MAX_STATUSES_PER_REQUEST", "256"),
        ("APP_LIMITS__MAX_SERIALIZED_LIST_SIZE", "32768"),
    ])]
    fn test_rate_limits_and_bounds_env_override() {
        let config = Config::load().expect("Failed to load config");

        assert_eq!(config.rate_limit.strict_burst_size, 3);
        assert_eq!(config.rate_limit.strict_period_secs, 120);
        assert_eq!(config.rate_limit.permissive_burst_size, 500);
        assert_eq!(config.rate_limit.permissive_period_secs, 10);
        assert_eq!(config.limits.max_body_size_bytes, 65_536);
        assert_eq!(config.limits.max_status_index, 4_096);
        assert_eq!(config.limits.max_statuses_per_request, 256);
        assert_eq!(config.limits.max_serialized_list_size, 32_768);
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
