#[cfg(feature = "dns-route53")]
use crate::cert_manager::challenge::AwsRoute53DnsUpdater;
#[cfg(feature = "redis")]
use crate::cert_manager::storage::Redis;
#[cfg(all(feature = "aws-s3", feature = "aws-secrets"))]
use crate::cert_manager::storage::{AwsS3, AwsSecretsManager};
#[cfg(feature = "postgres")]
use crate::database::{Migrator, queries::SeaOrmStore};
#[cfg(feature = "postgres")]
use crate::models::{Credentials, StatusListRecord};
use crate::{
    cert_manager::{
        CertManager,
        challenge::{Dns01Handler, PebbleDnsUpdater},
        storage::MemoryStorage,
    },
    config::Config as AppConfig,
    database::queries::{
        CredentialRepository, MemoryCredentialRepository, MemoryStatusListRepository,
        StatusListRepository,
    },
};
#[cfg(any(feature = "aws-s3", feature = "aws-secrets"))]
use aws_config::{BehaviorVersion, Region};
#[cfg(feature = "postgres")]
use color_eyre::eyre::Context;
use color_eyre::eyre::Result as EyeResult;
#[cfg(feature = "postgres")]
use sea_orm::Database;
#[cfg(feature = "postgres")]
use sea_orm_migration::MigratorTrait;
#[cfg(feature = "postgres")]
use secrecy::ExposeSecret;
use std::sync::Arc;
#[cfg(all(
    not(feature = "memory"),
    feature = "postgres",
    feature = "aws-s3",
    feature = "aws-secrets",
    feature = "redis"
))]
use std::time::Duration;

use super::cache::Cache;
#[cfg(all(
    not(feature = "memory"),
    feature = "postgres",
    feature = "aws-s3",
    feature = "aws-secrets",
    feature = "redis"
))]
use super::cert_manager::http_client::DefaultHttpClient;

#[cfg(all(
    not(feature = "memory"),
    feature = "postgres",
    feature = "aws-s3",
    feature = "aws-secrets",
    feature = "redis"
))]
const ENV_PRODUCTION: &str = "production";
#[cfg(all(
    not(feature = "memory"),
    feature = "postgres",
    feature = "aws-s3",
    feature = "aws-secrets",
    feature = "redis"
))]
const ENV_DEVELOPMENT: &str = "development";

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) credential_repo: Arc<dyn CredentialRepository>,
    pub(crate) status_list_repo: Arc<dyn StatusListRepository>,
    pub(crate) server_domain: String,
    pub cert_manager: Arc<CertManager>,
    pub(crate) cache: Cache,
    pub(crate) aggregation_uri: Option<String>,
    pub(crate) token_exp_secs: u64,
    pub(crate) token_ttl_secs: u64,
}

pub async fn build_state(config: &AppConfig) -> EyeResult<AppState> {
    #[cfg(feature = "memory")]
    {
        return build_memory_state(config).await;
    }

    #[cfg(all(
        not(feature = "memory"),
        feature = "postgres",
        feature = "aws-s3",
        feature = "aws-secrets",
        feature = "redis"
    ))]
    {
        return build_production_state(config).await;
    }

    #[cfg(not(any(
        feature = "memory",
        all(
            feature = "postgres",
            feature = "aws-s3",
            feature = "aws-secrets",
            feature = "redis"
        )
    )))]
    {
        color_eyre::eyre::bail!(
            "No complete backend feature set selected. Use `--features memory` for local in-memory backends or enable `postgres,aws-s3,aws-secrets,redis` for production storage."
        );
    }
}

#[cfg(all(
    not(feature = "memory"),
    feature = "postgres",
    feature = "aws-s3",
    feature = "aws-secrets",
    feature = "redis"
))]
async fn build_production_state(config: &AppConfig) -> EyeResult<AppState> {
    let db = Database::connect(config.database.url.expose_secret())
        .await
        .wrap_err("Failed to connect to database")?;

    Migrator::up(&db, None)
        .await
        .wrap_err("Failed to run database migrations")?;

    let aws_config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(config.aws.region.clone()))
        .load()
        .await;

    let redis_conn = config
        .redis
        .start(None, None, None)
        .await
        .wrap_err("Failed to connect to Redis")?;

    // Initialize the challenge handler based on the environment.
    // Use a fake DNS server to validate the challenge in development.
    let app_env = std::env::var("APP_ENV").unwrap_or(ENV_DEVELOPMENT.to_string());
    let challenge_handler = if app_env == ENV_PRODUCTION {
        #[cfg(feature = "dns-route53")]
        {
            let updater = AwsRoute53DnsUpdater::new(&aws_config);
            Dns01Handler::new(updater)
        }
        #[cfg(not(feature = "dns-route53"))]
        {
            color_eyre::eyre::bail!(
                "Production certificate provisioning requires the `dns-route53` backend feature"
            );
        }
    } else {
        // Use pebble as the DNS server in development.
        // The DNS channel server URL is optional and only used in dev mode;
        // it falls back to the well-known Pebble challenge test server when unset.
        let dns_url = config
            .server
            .cert
            .dns_challenge_server_url
            .as_deref()
            .unwrap_or("http://challtestsrv:8055");
        let updater = PebbleDnsUpdater::new(dns_url);
        Dns01Handler::new(updater)
    };

    // Initialize the storage backends for the certificate manager
    let cache = Redis::new(redis_conn.clone()).with_ttl(config.redis.cert_cache_ttl);
    let cert_storage = AwsS3::new(
        &aws_config,
        &config.aws.s3_bucket,
        &config.aws.region,
        &config.aws.s3_key_prefix,
    )
    .with_cache(cache);
    let secrets_storage = AwsSecretsManager::new(
        &aws_config,
        Duration::from_secs(config.aws.secrets_cache_ttl),
    )
    .await?;

    let mut certificate_manager = CertManager::new(
        [&config.server.domain],
        &config.server.cert.email,
        config.server.cert.organization.as_deref(),
        &config.server.cert.acme_directory_url,
    )?
    .with_cert_storage(cert_storage)
    .with_secrets_storage(secrets_storage)
    .with_challenge_handler(challenge_handler)
    .with_eku(&config.server.cert.eku);

    if app_env == ENV_DEVELOPMENT {
        // Override the default HTTP client to use the pebble root certificate
        // It is necessary to avoid https errors since pebble uses localhost over https
        // with a self-signed root certificate
        let root_cert = include_bytes!("../../test_data/pebble.pem");
        let http_client = DefaultHttpClient::new(Some(root_cert))?;
        certificate_manager = certificate_manager.with_acme_http_client(http_client);
    }

    let db_clone = Arc::new(db);
    Ok(AppState {
        credential_repo: Arc::new(SeaOrmStore::<Credentials>::new(db_clone.clone())),
        status_list_repo: Arc::new(SeaOrmStore::<StatusListRecord>::new(db_clone)),
        server_domain: config.server.domain.clone(),
        cert_manager: Arc::new(certificate_manager),
        cache: Cache::new(config.cache.ttl, config.cache.max_capacity),
        aggregation_uri: empty_to_none(config.server.aggregation_uri.clone()),
        token_exp_secs: config.status_list.token_exp_secs,
        token_ttl_secs: config.status_list.token_ttl_secs,
    })
}

#[cfg(feature = "memory")]
async fn build_memory_state(config: &AppConfig) -> EyeResult<AppState> {
    let cert_storage = MemoryStorage::new();
    let secrets_storage = MemoryStorage::new();
    let challenge_storage = MemoryStorage::new();
    let challenge_handler = Dns01Handler::new(PebbleDnsUpdater::new(
        config
            .server
            .cert
            .dns_challenge_server_url
            .as_deref()
            .unwrap_or("http://localhost:8055"),
    ));

    let certificate_manager = CertManager::new(
        [&config.server.domain],
        &config.server.cert.email,
        config.server.cert.organization.as_deref(),
        &config.server.cert.acme_directory_url,
    )?
    .with_cert_storage(cert_storage)
    .with_secrets_storage(secrets_storage)
    .with_challenge_handler(challenge_handler)
    .with_eku(&config.server.cert.eku);

    let _ = challenge_storage;

    Ok(AppState {
        credential_repo: Arc::new(MemoryCredentialRepository::new()),
        status_list_repo: Arc::new(MemoryStatusListRepository::new()),
        server_domain: config.server.domain.clone(),
        cert_manager: Arc::new(certificate_manager),
        cache: Cache::new(config.cache.ttl, config.cache.max_capacity),
        aggregation_uri: empty_to_none(config.server.aggregation_uri.clone()),
        token_exp_secs: config.status_list.token_exp_secs,
        token_ttl_secs: config.status_list.token_ttl_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::empty_to_none;

    #[test]
    fn test_empty_to_none() {
        assert_eq!(empty_to_none(None), None);
        assert_eq!(empty_to_none(Some("".to_string())), None);
        assert_eq!(empty_to_none(Some("  ".to_string())), None);
        assert_eq!(
            empty_to_none(Some("https://x".to_string())),
            Some("https://x".to_string())
        );
    }
}
