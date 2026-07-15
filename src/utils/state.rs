use crate::{
    adapters::{
        aws::{AwsS3, AwsSecretsManager},
        cache::MokaStatusListCache,
        certificate::AcmeCertificateProvider,
        dns::{AwsRoute53DnsUpdater, DnsUpdaterProvider, PebbleDnsUpdater},
        metrics::NoopMetricsCollector,
        postgres::{PostgresCredentialRepository, PostgresStatusListRepository},
        redis::Redis,
        secret::StorageSecretStore,
    },
    cert_manager::{CertManager, challenge::Dns01Handler},
    config::Config as AppConfig,
    database::{Migrator, queries::SeaOrmStore},
    ports::{
        CertificateProvider, CredentialRepository, DnsProvider, MetricsCollector, SecretStore,
        StatusListCache, StatusListRepository,
    },
};
use aws_config::{BehaviorVersion, Region};
use color_eyre::eyre::{Context, Result as EyeResult};
use sea_orm::Database;
use sea_orm_migration::MigratorTrait;
use secrecy::ExposeSecret;
use std::{sync::Arc, time::Duration};

use super::cert_manager::http_client::DefaultHttpClient;

const ENV_PRODUCTION: &str = "production";
const ENV_DEVELOPMENT: &str = "development";

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

#[derive(Clone)]
pub struct AppState {
    pub status_lists: Arc<dyn StatusListRepository>,
    pub credentials: Arc<dyn CredentialRepository>,
    pub status_list_cache: Arc<dyn StatusListCache>,
    pub certificate_provider: Arc<dyn CertificateProvider>,
    pub secret_store: Arc<dyn SecretStore>,
    pub dns_provider: Arc<dyn DnsProvider>,
    pub metrics_collector: Arc<dyn MetricsCollector>,
    pub server_domain: String,
    pub aggregation_uri: Option<String>,
    pub token_exp_secs: u64,
    pub token_ttl_secs: u64,
}

pub async fn build_state(config: &AppConfig) -> EyeResult<AppState> {
    build_state_with_cert_manager(config)
        .await
        .map(|(state, _cert_manager)| state)
}

pub async fn build_state_with_cert_manager(
    config: &AppConfig,
) -> EyeResult<(AppState, Arc<CertManager>)> {
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
    let (challenge_handler, dns_provider): (Dns01Handler, Arc<dyn DnsProvider>) =
        if app_env == ENV_PRODUCTION {
            let updater = AwsRoute53DnsUpdater::new(&aws_config);
            let dns_provider = Arc::new(DnsUpdaterProvider::new(Arc::new(
                AwsRoute53DnsUpdater::new(&aws_config),
            )));
            (Dns01Handler::new(updater), dns_provider)
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
            let dns_provider = Arc::new(DnsUpdaterProvider::new(Arc::new(PebbleDnsUpdater::new(
                dns_url,
            ))));
            (Dns01Handler::new(updater), dns_provider)
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
    let secret_store = Arc::new(StorageSecretStore::new(Arc::new(
        AwsSecretsManager::new(
            &aws_config,
            Duration::from_secs(config.aws.secrets_cache_ttl),
        )
        .await?,
    )));

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
    let status_list_repo = SeaOrmStore::new(db_clone.clone());
    let credential_repo = SeaOrmStore::new(db_clone.clone());
    let cache = MokaStatusListCache::new(config.cache.ttl, config.cache.max_capacity);
    let cert_manager = Arc::new(certificate_manager);
    Ok((
        AppState {
            status_lists: Arc::new(PostgresStatusListRepository::new(status_list_repo)),
            credentials: Arc::new(PostgresCredentialRepository::new(credential_repo)),
            status_list_cache: Arc::new(cache),
            certificate_provider: Arc::new(AcmeCertificateProvider::new(cert_manager.clone())),
            secret_store,
            dns_provider,
            metrics_collector: Arc::new(NoopMetricsCollector),
            server_domain: config.server.domain.clone(),
            aggregation_uri: empty_to_none(config.server.aggregation_uri.clone()),
            token_exp_secs: config.status_list.token_exp_secs,
            token_ttl_secs: config.status_list.token_ttl_secs,
        },
        cert_manager,
    ))
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
