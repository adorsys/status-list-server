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
    pub development_dns_challenge_url: String,
    pub dns_propagation_timeout_secs: u64,
    pub dns_propagation_initial_delay_secs: u64,
    pub signing_key_max_retries: u32,
    pub signing_key_retry_delay_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub uri: SecretString,
    pub require_client_auth: bool,
    pub cert_cache_ttl: u64,
    pub connection_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub secrets_cache_ttl: u64,
    pub secrets_cache_max_capacity: usize,
    pub s3_bucket: String,
    pub s3_key_prefix: String,
    pub s3_bucket_max_retries: u32,
    pub s3_bucket_retry_delay_ms: u64,
    pub route53_txt_ttl: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    pub ttl: u64,
    pub max_capacity: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatusListConfig {
    pub token_exp_secs: i64,
    pub token_ttl_secs: i64,
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

        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_secs(self.connection_timeout_secs)));
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
            .set_default("redis.uri", "redis://localhost:6379")?
            .set_default("redis.require_client_auth", false)?
            .set_default("redis.cert_cache_ttl", 3600)? // Default 1 hour
            .set_default("redis.connection_timeout_secs", 60)?
            .set_default("aws.secrets_cache_ttl", 300)? // Default 5 minutes
            .set_default("aws.secrets_cache_max_capacity", 100)?
            .set_default("aws.s3_bucket", "status-list-adorsys")?
            .set_default("aws.s3_key_prefix", "")?
            .set_default("aws.s3_bucket_max_retries", 3)?
            .set_default("aws.s3_bucket_retry_delay_ms", 500)?
            .set_default("aws.route53_txt_ttl", 60)?
            .set_default("server.cert.email", "admin@example.com")?
            .set_default("server.cert.eku", vec![1, 3, 6, 1, 5, 5, 7, 3, 30])?
            .set_default("server.cert.organization", "adorsys GmbH & CO KG")?
            .set_default(
                "server.cert.acme_directory_url",
                "https://acme-v02.api.letsencrypt.org/directory",
            )?
            .set_default("server.cert.renewal_cron_schedule", "0 0 0 * * *")?
            .set_default("server.cert.development_dns_challenge_url", "http://challtestsrv:8055")?
            .set_default("server.cert.dns_propagation_timeout_secs", 300)?
            .set_default("server.cert.dns_propagation_initial_delay_secs", 2)?
            .set_default("server.cert.signing_key_max_retries", 3)?
            .set_default("server.cert.signing_key_retry_delay_ms", 500)?
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
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.port == 0 {
            return Err(ConfigError::Message(
                "server.port must be between 1 and 65535".into(),
            ));
        }

        if self.redis.connection_timeout_secs == 0 {
            return Err(ConfigError::Message(
                "redis.connection_timeout_secs must be greater than 0".into(),
            ));
        }

        if self.aws.s3_bucket.is_empty() {
            return Err(ConfigError::Message(
                "aws.s3_bucket must not be empty".into(),
            ));
        }

        if self.aws.s3_bucket_max_retries == 0 {
            return Err(ConfigError::Message(
                "aws.s3_bucket_max_retries must be greater than 0".into(),
            ));
        }

        if self.aws.secrets_cache_max_capacity == 0 {
            return Err(ConfigError::Message(
                "aws.secrets_cache_max_capacity must be greater than 0".into(),
            ));
        }

        if self.server.cert.dns_propagation_timeout_secs == 0 {
            return Err(ConfigError::Message(
                "server.cert.dns_propagation_timeout_secs must be greater than 0".into(),
            ));
        }

        if self.server.cert.signing_key_max_retries == 0 {
            return Err(ConfigError::Message(
                "server.cert.signing_key_max_retries must be greater than 0".into(),
            ));
        }

        if self.status_list.token_exp_secs <= 0 {
            return Err(ConfigError::Message(
                "status_list.token_exp_secs must be greater than 0".into(),
            ));
        }

        if self.status_list.token_ttl_secs < 0 {
            return Err(ConfigError::Message(
                "status_list.token_ttl_secs must not be negative".into(),
            ));
        }

        Ok(())
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
        assert_eq!(config.aws.s3_bucket, "status-list-adorsys");
        assert_eq!(config.aws.s3_key_prefix, "");
        assert_eq!(config.aws.secrets_cache_max_capacity, 100);
        assert_eq!(config.aws.route53_txt_ttl, 60);
        assert_eq!(config.redis.connection_timeout_secs, 60);
        assert_eq!(config.status_list.token_exp_secs, 900);
        assert_eq!(config.status_list.token_ttl_secs, 300);
        assert_eq!(config.server.cert.renewal_cron_schedule, "0 0 0 * * *");
        assert_eq!(
            config.server.cert.development_dns_challenge_url,
            "http://challtestsrv:8055"
        );
        assert_eq!(config.server.cert.dns_propagation_timeout_secs, 300);
        assert_eq!(config.server.cert.dns_propagation_initial_delay_secs, 2);
        assert_eq!(config.server.cert.signing_key_max_retries, 3);
        assert_eq!(config.server.cert.signing_key_retry_delay_ms, 500);
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
        ("APP_AWS__SECRETS_CACHE_TTL", "600"),
        ("APP_AWS__S3_BUCKET", "my-custom-bucket"),
        ("APP_AWS__S3_KEY_PREFIX", "status-list/prod"),
        ("APP_AWS__SECRETS_CACHE_MAX_CAPACITY", "500"),
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
        assert_eq!(config.aws.secrets_cache_max_capacity, 500);
        assert_eq!(config.cache.ttl, 600);
        assert_eq!(config.cache.max_capacity, 2000);
    }

    #[sealed_test(env = [
        ("APP_AWS__S3_BUCKET", "my-bucket"),
        ("APP_AWS__S3_KEY_PREFIX", "prefix"),
        ("APP_AWS__SECRETS_CACHE_MAX_CAPACITY", "50"),
        ("APP_AWS__ROUTE53_TXT_TTL", "120"),
        ("APP_REDIS__CONNECTION_TIMEOUT_SECS", "30"),
        ("APP_STATUS_LIST__TOKEN_EXP_SECS", "1800"),
        ("APP_STATUS_LIST__TOKEN_TTL_SECS", "600"),
        ("APP_SERVER__CERT__RENEWAL_CRON_SCHEDULE", "0 0 12 * * *"),
        ("APP_SERVER__CERT__DEVELOPMENT_DNS_CHALLENGE_URL", "http://pebble:8055"),
        ("APP_SERVER__CERT__DNS_PROPAGATION_TIMEOUT_SECS", "600"),
        ("APP_SERVER__CERT__DNS_PROPAGATION_INITIAL_DELAY_SECS", "5"),
        ("APP_SERVER__CERT__SIGNING_KEY_MAX_RETRIES", "5"),
        ("APP_SERVER__CERT__SIGNING_KEY_RETRY_DELAY_MS", "1000"),
    ])]
    fn test_new_config_fields_env_override() {
        let config = Config::load().expect("Failed to load config");

        assert_eq!(config.aws.s3_bucket, "my-bucket");
        assert_eq!(config.aws.s3_key_prefix, "prefix");
        assert_eq!(config.aws.secrets_cache_max_capacity, 50);
        assert_eq!(config.aws.route53_txt_ttl, 120);
        assert_eq!(config.redis.connection_timeout_secs, 30);
        assert_eq!(config.status_list.token_exp_secs, 1800);
        assert_eq!(config.status_list.token_ttl_secs, 600);
        assert_eq!(config.server.cert.renewal_cron_schedule, "0 0 12 * * *");
        assert_eq!(
            config.server.cert.development_dns_challenge_url,
            "http://pebble:8055"
        );
        assert_eq!(config.server.cert.dns_propagation_timeout_secs, 600);
        assert_eq!(config.server.cert.dns_propagation_initial_delay_secs, 5);
        assert_eq!(config.server.cert.signing_key_max_retries, 5);
        assert_eq!(config.server.cert.signing_key_retry_delay_ms, 1000);
    }

    #[sealed_test(env = [
        ("APP_AWS__S3_BUCKET", ""),
    ])]
    fn test_validation_empty_s3_bucket() {
        let result = Config::load();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("s3_bucket"),
            "Expected error about s3_bucket, got: {err}"
        );
    }

    #[sealed_test(env = [
        ("APP_STATUS_LIST__TOKEN_EXP_SECS", "0"),
    ])]
    fn test_validation_zero_token_exp() {
        let result = Config::load();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("token_exp_secs"),
            "Expected error about token_exp_secs, got: {err}"
        );
    }

    #[sealed_test(env = [
        ("APP_AWS__SECRETS_CACHE_MAX_CAPACITY", "0"),
    ])]
    fn test_validation_zero_secrets_cache_capacity() {
        let result = Config::load();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("secrets_cache_max_capacity"),
            "Expected error about secrets_cache_max_capacity, got: {err}"
        );
    }

    #[sealed_test(env = [
        ("APP_REDIS__CONNECTION_TIMEOUT_SECS", "0"),
    ])]
    fn test_validation_zero_redis_connection_timeout() {
        let result = Config::load();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("connection_timeout_secs"),
            "Expected error about connection_timeout_secs, got: {err}"
        );
    }
}