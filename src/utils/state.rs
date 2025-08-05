use crate::{
    cert_manager::{
        challenge::{AwsRoute53DnsUpdater, Dns01Handler},
        storage::{AwsS3, AwsSecretsManager, Redis},
        CertManager,
    },
    config::Config as AppConfig,
    database::{queries::SeaOrmStore, Migrator},
    models::{Credentials, StatusListRecord},
};
use aws_config::{BehaviorVersion, Region};
use color_eyre::eyre::{Context, Result as EyeResult};
use sea_orm::Database;
use sea_orm_migration::MigratorTrait;
use secrecy::ExposeSecret;
use std::sync::Arc;

use super::{
    cache::Cache,
    cert_manager::{challenge::PebbleDnsUpdater, http_client::DefaultHttpClient},
};

// Could also be passed at runtime through environment variable
const BUCKET_NAME: &str = "status-list-adorsys";
const ENV_PRODUCTION: &str = "production";
const ENV_DEVELOPMENT: &str = "development";

#[derive(Clone)]
pub struct AppState {
    pub credential_repo: SeaOrmStore<Credentials>,
    pub status_list_repo: SeaOrmStore<StatusListRecord>,
    pub server_domain: String,
    pub cert_manager: Arc<CertManager>,
    pub cache: Cache,
}

pub async fn build_state(config: &AppConfig) -> EyeResult<AppState> {
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

    // Read Redis root certificate if available
    let redis_root_cert = {
        // Try configuration first, then environment variable, then fallback paths
        let cert_path = config
            .redis
            .root_cert_path
            .clone()
            .or_else(|| std::env::var("APP_REDIS__ROOT_CERT_PATH").ok());

        cert_path
            .and_then(|path| {
                // Validate that the path exists and is readable
                if !std::path::Path::new(&path).exists() {
                    tracing::warn!("Redis CA certificate path does not exist: {}", path);
                    return None;
                }

                // Try to read the certificate file
                match std::fs::read_to_string(&path) {
                    Ok(cert) => {
                        tracing::info!("Successfully loaded Redis CA certificate from: {}", path);
                        Some(cert)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to read Redis CA certificate from {}: {}", path, e);
                        None
                    }
                }
            })
            .or_else(|| {
                // Fallback to alternative certificate paths
                let alternative_paths = [
                    "/etc/ssl/certs/redis-ca.crt",
                    "/etc/redis/ca.crt",
                    "/etc/certs/redis-ca.crt",
                    "/etc/redis-certs/ca.crt", // Default Kubernetes mount path
                ];

                for path in &alternative_paths {
                    if std::path::Path::new(path).exists() {
                        match std::fs::read_to_string(path) {
                            Ok(cert) => {
                                tracing::info!("Successfully loaded Redis CA certificate from fallback path: {}", path);
                                return Some(cert);
                            }
                            Err(e) => {
                                tracing::debug!("Failed to read Redis CA certificate from fallback path {}: {}", path, e);
                                continue;
                            }
                        }
                    }
                }

                tracing::warn!("No Redis CA certificate found in any of the expected locations");
                None
            })
    };

    let redis_conn = config
        .redis
        .start(None, None, redis_root_cert.as_deref())
        .await
        .map_err(|e| {
            let error_msg = if config.redis.require_tls {
                format!(
                    "Failed to connect to Redis with TLS. URI: {}, Error: {}. {}",
                    config.redis.uri.expose_secret(),
                    e,
                    if redis_root_cert.is_some() {
                        "Certificate was provided but connection failed."
                    } else {
                        "No certificate provided - this may cause TLS validation to fail."
                    }
                )
            } else {
                format!(
                    "Failed to connect to Redis without TLS. URI: {}, Error: {}",
                    config.redis.uri.expose_secret(),
                    e
                )
            };
            color_eyre::eyre::eyre!(error_msg)
        })?;

    // Initialize the challenge handler based on the environment.
    // Use a fake DNS server to validate the challenge in development.
    let app_env = std::env::var("APP_ENV").unwrap_or(ENV_DEVELOPMENT.to_string());
    let challenge_handler = if app_env == ENV_PRODUCTION {
        let updater = AwsRoute53DnsUpdater::new(&aws_config);
        Dns01Handler::new(updater)
    } else {
        // Use pebble as the DNS server in development
        let updater = PebbleDnsUpdater::new("http://challtestsrv:8055");
        Dns01Handler::new(updater)
    };

    // Initialize the storage backends for the certificate manager
    let cache = Redis::new(redis_conn.clone());
    let cert_storage =
        AwsS3::new(&aws_config, BUCKET_NAME, config.aws.region.clone()).with_cache(cache);
    let secrets_storage = AwsSecretsManager::new(&aws_config).await?;
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
        let root_cert = include_bytes!("../test_resources/pebble.pem");
        let http_client = DefaultHttpClient::new(Some(root_cert))?;
        certificate_manager = certificate_manager.with_acme_http_client(http_client);
    }

    let db_clone = Arc::new(db);
    Ok(AppState {
        credential_repo: SeaOrmStore::new(db_clone.clone()),
        status_list_repo: SeaOrmStore::new(db_clone),
        server_domain: config.server.domain.clone(),
        cert_manager: Arc::new(certificate_manager),
        cache: Cache::new(config.cache.ttl, config.cache.max_capacity),
    })
}
