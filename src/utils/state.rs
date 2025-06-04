use crate::{
    cert_manager::{
        challenge::{AwsRoute53DnsUpdater, Dns01Handler},
        storage::{AwsS3, AwsSecretsManager, Redis},
        CertManager,
    },
    config::Config as AppConfig,
    database::{queries::SeaOrmStore, Migrator},
    models::{Credentials, StatusListToken},
};
use aws_config::{BehaviorVersion, Region};
use color_eyre::eyre::{eyre, Ok, Result as EyeResult};
use sea_orm::Database;
use sea_orm_migration::MigratorTrait;
use secrecy::ExposeSecret;
use std::sync::Arc;

// Could also be passed at runtime through environment variable
const BUCKET_NAME: &str = "status-list-adorsys";

#[derive(Clone)]
pub struct AppState {
    pub credential_repo: SeaOrmStore<Credentials>,
    pub status_list_token_repo: SeaOrmStore<StatusListToken>,
    pub server_domain: String,
    pub cert_manager: Arc<CertManager>,
}

pub async fn build_state(config: &AppConfig) -> EyeResult<AppState> {
    let db = Database::connect(config.database.url.expose_secret())
        .await
        .map_err(|e| eyre!("Failed to connect to database: {e:?}"))?;

    Migrator::up(&db, None)
        .await
        .map_err(|e| eyre!("Failed to run database migrations: {e:?}"))?;

    let aws_config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(config.aws.region.clone()))
        .load()
        .await;

    let redis_conn = config
        .redis
        .start(None, None, None)
        .await
        .map_err(|e| eyre!("Failed to connect to Redis: {e:?}"))?;

    // Initialize the storage backends for the certificate manager
    let cache = Redis::new(redis_conn.clone());
    let cert_storage = AwsS3::new(&aws_config, BUCKET_NAME).with_cache(cache.clone());
    let secrets_storage = AwsSecretsManager::new(&aws_config).await?;
    // Initialize the challenge handler
    let updater = AwsRoute53DnsUpdater::new(&aws_config);
    let challenge_handler = Dns01Handler::new(updater);

    let mut certificate_manager = CertManager::new(
        [&config.server.host],
        &config.server.cert.email,
        config.server.cert.organization.as_deref(),
        &config.server.cert.acme_directory_url,
    )?
    .with_cert_storage(cert_storage)
    .with_secrets_storage(secrets_storage)
    .with_challenge_handler(challenge_handler);

    if let Some(eku) = &config.server.cert.eku {
        certificate_manager = certificate_manager.with_eku(eku);
    }

    let db_clone = Arc::new(db);
    Ok(AppState {
        credential_repo: SeaOrmStore::new(db_clone.clone()),
        status_list_token_repo: SeaOrmStore::new(db_clone),
        server_domain: config.server.host.clone(),
        cert_manager: Arc::new(certificate_manager),
    })
}
