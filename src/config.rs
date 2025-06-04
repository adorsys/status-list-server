use config::{Config as ConfigLib, ConfigError, Environment};
use redis::{
    aio::ConnectionManager, Client as RedisClient, ClientTlsConfig, RedisResult, TlsCertificates,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub aws: AwsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub cert: CertConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertConfig {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eku: Option<Vec<u64>>,
    pub acme_directory_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub uri: SecretString,
    pub require_tls: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsConfig {
    pub region: String,
}

impl RedisConfig {
    /// Establishes a new Redis connection based on the configuration.
    ///
    /// If [`RedisConfig::require_tls`] is `false`, a plain-text connection is used.
    /// If it is `true`, the connection will use TLS, and the URI **must** use the `rediss://` scheme.
    ///
    /// To enable mutual TLS (mTLS), both `cert_pem` and `key_pem` must be provided.
    /// If one is missing, the client-side authentication will not be effective.
    ///
    /// The optional `root_cert` parameter allows specifying a custom root certificate (in PEM format).
    /// If omitted, system root certificates will be used.
    ///
    /// # Parameters
    /// - `cert_pem`: The client certificate in PEM format (required for mTLS).
    /// - `key_pem`: The client private key in PEM format (required for mTLS).
    /// - `root_cert`: An optional custom root certificate in PEM format.
    ///
    /// # Errors
    /// Returns an error if the connection cannot be established.
    pub async fn start(
        &self,
        cert_pem: Option<&str>,
        key_pem: Option<&str>,
        root_cert: Option<&str>,
    ) -> RedisResult<ConnectionManager> {
        let client = if !self.require_tls {
            RedisClient::open(self.uri.expose_secret())?
        } else {
            let client_tls = match (cert_pem, key_pem) {
                (Some(cert), Some(key)) => Some(ClientTlsConfig {
                    client_cert: cert.as_bytes().to_vec(),
                    client_key: key.as_bytes().to_vec(),
                }),
                _ => None,
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

        client.get_connection_manager().await
    }
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        // Build the config
        let config = ConfigLib::builder()
            // Set default values
            .set_default("server.host", "localhost")?
            .set_default("server.port", 3000)?
            .set_default(
                "database.url",
                "postgres://postgres:postgres@localhost:5432/status-list",
            )?
            .set_default("redis.uri", "redis://localhost:6379")?
            .set_default("redis.require_tls", false)?
            .set_default("server.cert.email", "admin@example.com")?
            .set_default("server.cert.organization", "Adorsys GmbH & CO KG")?
            .set_default(
                "server.cert.acme_directory_url",
                "https://acme-v02.api.letsencrypt.org/directory",
            )?
            .set_default("aws.region", "us-east-1")?
            // Override config values via environment variables
            // The environment variables should be prefixed with 'APP_' and use '__' as a separator
            // Example: APP_REDIS__REQUIRE_TLS=true
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
        assert_eq!(config.server.port, 3000);
        assert_eq!(
            config.database.url.expose_secret(),
            "postgres://postgres:postgres@localhost:5432/status-list"
        );
        assert_eq!(config.redis.uri.expose_secret(), "redis://localhost:6379");
        assert_eq!(config.redis.require_tls, false);
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
        ("APP_REDIS__REQUIRE_TLS", "true"),
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
        assert_eq!(config.redis.require_tls, true);
        assert_eq!(config.server.cert.email, "test@gmail.com");
        assert_eq!(
            config.server.cert.acme_directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
    }
}
