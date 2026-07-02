use std::path::PathBuf;

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
use std::{sync::Arc, time::Duration};

use super::{
    cache::Cache,
    cert_manager::{challenge::PebbleDnsUpdater, http_client::DefaultHttpClient},
};

const BUCKET_NAME: &str = "status-list-adorsys";
const ENV_PRODUCTION: &str = "production";
const ENV_DEVELOPMENT: &str = "development";

/// File paths for externally managed signing key and certificate chain.
///
/// Files are re-read on each request so that certificate rotation
/// (e.g. by Kubernetes cert-manager updating a mounted Secret) is
/// picked up without a pod restart.
#[derive(Clone, Debug)]
pub struct SigningFiles {
    pub key_file: PathBuf,
    pub cert_file: PathBuf,
}

#[derive(Clone)]
pub struct AppState {
    pub credential_repo: SeaOrmStore<Credentials>,
    pub status_list_repo: SeaOrmStore<StatusListRecord>,
    pub server_domain: String,
    pub cert_manager: Option<Arc<CertManager>>,
    pub signing_files: Option<SigningFiles>,
    pub cache: Cache,
}

pub async fn build_state(config: &AppConfig) -> EyeResult<AppState> {
    let db = Database::connect(config.database.url.expose_secret())
        .await
        .wrap_err("Failed to connect to database")?;

    Migrator::up(&db, None)
        .await
        .wrap_err("Failed to run database migrations")?;

    let redis_conn = config
        .redis
        .start(None, None, None)
        .await
        .wrap_err("Failed to connect to Redis")?;

    let signing_files = config.server.signing.as_ref().map(|s| {
        tracing::info!(
            key_file = %s.key_file,
            cert_file = %s.cert_file,
            "Static signing files configured — bypassing built-in ACME certificate management"
        );
        SigningFiles {
            key_file: PathBuf::from(&s.key_file),
            cert_file: PathBuf::from(&s.cert_file),
        }
    });

    let cert_manager = if signing_files.is_some() {
        None
    } else {
        build_cert_manager(config, &redis_conn).await?
    };

    let db_clone = Arc::new(db);
    Ok(AppState {
        credential_repo: SeaOrmStore::new(db_clone.clone()),
        status_list_repo: SeaOrmStore::new(db_clone),
        server_domain: config.server.domain.clone(),
        cert_manager,
        signing_files,
        cache: Cache::new(config.cache.ttl, config.cache.max_capacity),
    })
}

/// Build the certificate manager based on the storage backend configuration.
///
/// Returns `None` when certificate management is disabled (no `server.cert`
/// or no storage backend configured).
async fn build_cert_manager(
    config: &AppConfig,
    redis_conn: &redis::aio::ConnectionManager,
) -> EyeResult<Option<Arc<CertManager>>> {
    let cert_config = match &config.server.cert {
        Some(c) => c,
        None => {
            tracing::info!("Certificate management is disabled (no server.cert configuration)");
            return Ok(None);
        }
    };

    let app_env = std::env::var("APP_ENV").unwrap_or(ENV_DEVELOPMENT.to_string());

    if let Some(aws_config_values) = &config.aws {
        return build_aws_cert_manager(
            config,
            cert_config,
            aws_config_values,
            redis_conn,
            &app_env,
        )
        .await
        .map(Some);
    }

    tracing::info!("Certificate management is disabled (no aws configuration provided)");
    Ok(None)
}

/// Build a certificate manager backed by AWS S3 and Secrets Manager.
async fn build_aws_cert_manager(
    config: &AppConfig,
    cert_config: &crate::config::CertConfig,
    aws_config_values: &crate::config::AwsConfig,
    redis_conn: &redis::aio::ConnectionManager,
    app_env: &str,
) -> EyeResult<Arc<CertManager>> {
    let aws_config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(aws_config_values.region.clone()))
        .load()
        .await;

    let challenge_handler = if app_env == ENV_PRODUCTION {
        let updater = AwsRoute53DnsUpdater::new(&aws_config);
        Dns01Handler::new(updater)
    } else {
        let updater = PebbleDnsUpdater::new("http://challtestsrv:8055");
        Dns01Handler::new(updater)
    };

    let cache = Redis::new(redis_conn.clone()).with_ttl(config.redis.cert_cache_ttl);
    let cert_storage =
        AwsS3::new(&aws_config, BUCKET_NAME, aws_config_values.region.clone()).with_cache(cache);
    let secrets_storage = AwsSecretsManager::new(
        &aws_config,
        Duration::from_secs(aws_config_values.secrets_cache_ttl),
    )
    .await?;

    let mut certificate_manager = CertManager::new(
        [&config.server.domain],
        &cert_config.email,
        cert_config.organization.as_deref(),
        &cert_config.acme_directory_url,
    )?
    .with_cert_storage(cert_storage)
    .with_secrets_storage(secrets_storage)
    .with_challenge_handler(challenge_handler)
    .with_eku(&cert_config.eku);

    if app_env == ENV_DEVELOPMENT {
        let root_cert = include_bytes!("../test_resources/pebble.pem");
        let http_client = DefaultHttpClient::new(Some(root_cert))?;
        certificate_manager = certificate_manager.with_acme_http_client(http_client);
    }

    Ok(Arc::new(certificate_manager))
}
