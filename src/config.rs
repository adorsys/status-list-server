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
    Mariadb,
}

impl DatabaseBackend {
    pub fn url_scheme(&self) -> &'static str {
        match self {
            DatabaseBackend::Postgres => "postgres",
            DatabaseBackend::MySql => "mysql",
            DatabaseBackend::Sqlite => "sqlite",
            DatabaseBackend::Mariadb => "mariadb",
        }
    }
}

impl std::str::FromStr for DatabaseBackend {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "postgres" => Ok(DatabaseBackend::Postgres),
            "mysql" => Ok(DatabaseBackend::MySql),
            "sqlite" => Ok(DatabaseBackend::Sqlite),
            "mariadb" => Ok(DatabaseBackend::Mariadb),
            _ => Err(format!("Unknown database backend: {s}")),
        }
    }
}

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
    pub renewal_cron_schedule: String,
    #[serde(default)]
    pub dns_challenge_server_url: Option<String>,
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
            .set_default("server.cert.renewal_cron_schedule", "0 0 0 * * *")?
            .set_default("aws.region", "us-east-1")?
            .set_default("cache.ttl", 5 * 60)?
            .set_default("cache.max_capacity", 100)?
            .set_default("status_list.token_exp_secs", 900)? // 15 minutes
            .set_default("status_list.token_ttl_secs", 300)? // 5 minutes
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
        ("APP_DATABASE__URL", "sqlite:./test.db"),
    ])]
    fn test_sqlite_backend_config() {
        let config = Config::load().expect("Failed to load config");
        assert_eq!(config.database.backend, DatabaseBackend::Sqlite);
        assert_eq!(config.database.url.expose_secret(), "sqlite:./test.db");
    }

    #[sealed_test(env = [
        ("APP_DATABASE__BACKEND", "mariadb"),
        ("APP_DATABASE__URL", "mariadb://user:password@localhost:3306/status-list"),
    ])]
    fn test_mariadb_backend_config() {
        let config = Config::load().expect("Failed to load config");
        assert_eq!(config.database.backend, DatabaseBackend::Mariadb);
        assert_eq!(
            config.database.url.expose_secret(),
            "mariadb://user:password@localhost:3306/status-list"
        );
    }

    #[test]
    fn test_database_backend_from_str() {
        assert_eq!(
            "postgres".parse::<DatabaseBackend>().unwrap(),
            DatabaseBackend::Postgres
        );
        assert_eq!(
            "mysql".parse::<DatabaseBackend>().unwrap(),
            DatabaseBackend::MySql
        );
        assert_eq!(
            "sqlite".parse::<DatabaseBackend>().unwrap(),
            DatabaseBackend::Sqlite
        );
        assert_eq!(
            "mariadb".parse::<DatabaseBackend>().unwrap(),
            DatabaseBackend::Mariadb
        );
        assert_eq!(
            "PostgreS".parse::<DatabaseBackend>().unwrap(),
            DatabaseBackend::Postgres
        );
        assert!("unknown".parse::<DatabaseBackend>().is_err());
    }

    #[test]
    fn test_database_backend_url_scheme() {
        assert_eq!(DatabaseBackend::Postgres.url_scheme(), "postgres");
        assert_eq!(DatabaseBackend::MySql.url_scheme(), "mysql");
        assert_eq!(DatabaseBackend::Sqlite.url_scheme(), "sqlite");
        assert_eq!(DatabaseBackend::Mariadb.url_scheme(), "mariadb");
    }

    #[test]
    fn test_database_backend_default() {
        let backend = DatabaseBackend::default();
        assert_eq!(backend, DatabaseBackend::Postgres);
    }
}
}
