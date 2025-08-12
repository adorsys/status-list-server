use std::time::Duration;

use config::{Config as ConfigLib, ConfigError, Environment};
use redis::{
    aio::{ConnectionManager, ConnectionManagerConfig},
    Client as RedisClient, ClientTlsConfig, RedisResult, TlsCertificates,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_aux::field_attributes::deserialize_vec_from_string_or_vec;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub aws: AwsConfig,
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub domain: String,
    pub port: u16,
    pub cert: CertConfig,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub uri: SecretString,
    pub require_client_auth: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsConfig {
    pub region: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    pub ttl: u64,
    pub max_capacity: u64,
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
                        redis::ErrorKind::IoError,
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

        let config = ConnectionManagerConfig::new().set_connection_timeout(Duration::from_secs(60));
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
            .set_default(
                "database.url",
                "postgres://postgres:postgres@localhost:5432/status-list",
            )?
            .set_default("redis.uri", "redis://localhost:6379")?
            .set_default("redis.require_client_auth", false)?
            .set_default("server.cert.email", "admin@example.com")?
            .set_default("server.cert.eku", vec![1, 3, 6, 1, 5, 5, 7, 3, 30])?
            .set_default("server.cert.organization", "adorsys GmbH & CO KG")?
            .set_default(
                "server.cert.acme_directory_url",
                "https://acme-v02.api.letsencrypt.org/directory",
            )?
            .set_default("aws.region", "us-east-1")?
            .set_default("cache.ttl", 5 * 60)?
            .set_default("cache.max_capacity", 100)?
            // Override config values via environment variables
            // The environment variables should be prefixed with 'APP_' and use '__' as a separator
            // Example: APP_REDIS__REQUIRE_CLIENT_AUTH=false
            .add_source(
                Environment::with_prefix("APP")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?;

        config.try_deserialize()
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
        assert_eq!(config.redis.uri.expose_secret(), "redis://localhost:6379");
        assert!(!config.redis.require_client_auth);
        assert_eq!(config.server.cert.email, "admin@example.com");
        assert_eq!(
            config.server.cert.acme_directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(config.aws.region, "us-east-1");
    }

    #[sealed_test(env = [
        ("APP_SERVER__HOST", "0.0.0.0"),
        ("APP_SERVER__PORT", "5002"),
        ("APP_DATABASE__URL", "postgres://user:password@localhost:5432/status-list"),
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
        assert_eq!(config.cache.ttl, 600);
        assert_eq!(config.cache.max_capacity, 2000);
    }
}
