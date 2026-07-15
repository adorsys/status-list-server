use crate::{
    cert_manager::{
        CertManager, StoreProvisioningStrategy,
        challenge::{AwsRoute53DnsUpdater, Dns01Handler},
        storage::{AwsS3, AwsSecretsManager, Redis},
    },
    config::Config as AppConfig,
    database::{Migrator, queries::SeaOrmStore},
    models::{Credentials, StatusListRecord},
};
use aws_config::{BehaviorVersion, Region};
use color_eyre::eyre::{Context, Result as EyeResult, eyre};
use sea_orm::Database;
use sea_orm_migration::MigratorTrait;
use secrecy::ExposeSecret;
use std::{sync::Arc, time::Duration};

use super::{
    cache::Cache,
    cert_manager::{challenge::PebbleDnsUpdater, http_client::DefaultHttpClient},
};

const ENV_PRODUCTION: &str = "production";
const ENV_DEVELOPMENT: &str = "development";

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

#[derive(Clone)]
pub struct AppState {
    pub credential_repo: SeaOrmStore<Credentials>,
    pub status_list_repo: SeaOrmStore<StatusListRecord>,
    pub server_domain: String,
    pub cert_manager: Arc<CertManager>,
    pub cache: Cache,
    pub aggregation_uri: Option<String>,
    pub token_exp_secs: u64,
    pub token_ttl_secs: u64,
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

    let redis_conn = config
        .redis
        .start(None, None, None)
        .await
        .wrap_err("Failed to connect to Redis")?;

    // Initialize the challenge handler based on the environment.
    // Use a fake DNS server to validate the challenge in development.
    let app_env = std::env::var("APP_ENV").unwrap_or(ENV_DEVELOPMENT.to_string());
    let challenge_handler = if app_env == ENV_PRODUCTION {
        let updater = AwsRoute53DnsUpdater::new(&aws_config);
        Dns01Handler::new(updater)
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

    let cert_strategy = store_certificate_strategy(config)?;
    let uses_acme_strategy = config
        .server
        .cert
        .provisioning_strategy
        .eq_ignore_ascii_case("acme");

    let mut cert_manager_builder = CertManager::builder()
        .domains([config.server.domain.as_str()])
        .email(&config.server.cert.email)
        .organization(config.server.cert.organization.as_deref())
        .acme_directory_url(&config.server.cert.acme_directory_url)
        .cert_storage(cert_storage)
        .secrets_storage(secrets_storage)
        .eku(&config.server.cert.eku);

    cert_manager_builder = if uses_acme_strategy {
        cert_manager_builder
            .challenge_handler(challenge_handler)
            .acme_strategy()
    } else if let Some(cert_strategy) = cert_strategy {
        cert_manager_builder.store_strategy(cert_strategy)
    } else {
        return Err(eyre!(
            "store certificate provisioning strategy is missing after validation"
        ));
    };

    if app_env == ENV_DEVELOPMENT {
        // Override the default HTTP client to use the pebble root certificate
        // It is necessary to avoid https errors since pebble uses localhost over https
        // with a self-signed root certificate
        let root_cert = include_bytes!("../../test_data/pebble.pem");
        let http_client = DefaultHttpClient::new(Some(root_cert))?;
        cert_manager_builder = cert_manager_builder.acme_http_client(http_client);
    }

    let certificate_manager = cert_manager_builder.build()?;

    let db_clone = Arc::new(db);
    Ok(AppState {
        credential_repo: SeaOrmStore::new(db_clone.clone()),
        status_list_repo: SeaOrmStore::new(db_clone),
        server_domain: config.server.domain.clone(),
        cert_manager: Arc::new(certificate_manager),
        cache: Cache::new(config.cache.ttl, config.cache.max_capacity),
        aggregation_uri: empty_to_none(config.server.aggregation_uri.clone()),
        token_exp_secs: config.status_list.token_exp_secs,
        token_ttl_secs: config.status_list.token_ttl_secs,
    })
}

fn store_certificate_strategy(config: &AppConfig) -> EyeResult<Option<StoreProvisioningStrategy>> {
    let cert_config = &config.server.cert;
    if cert_config
        .provisioning_strategy
        .eq_ignore_ascii_case("acme")
    {
        return Ok(None);
    }

    if !cert_config
        .provisioning_strategy
        .eq_ignore_ascii_case("store")
    {
        return Err(eyre!(
            "unsupported certificate provisioning strategy '{}'; expected 'acme' or 'store'",
            cert_config.provisioning_strategy
        ));
    }

    match cert_config.store.source.as_str() {
        source if source.eq_ignore_ascii_case("filesystem") => {
            let certificate_path = cert_config
                .store
                .certificate_path
                .as_deref()
                .ok_or_else(|| {
                    eyre!(
                        "server.cert.store.certificate_path is required for filesystem store provisioning"
                    )
                })?;
            let signing_key_path = cert_config
                .store
                .signing_key_path
                .as_deref()
                .ok_or_else(|| {
                    eyre!(
                        "server.cert.store.signing_key_path is required for filesystem store provisioning"
                    )
                })?;
            Ok(Some(StoreProvisioningStrategy::filesystem(
                certificate_path,
                signing_key_path,
            )))
        }
        source if source.eq_ignore_ascii_case("storage") => {
            let certificate_key = cert_config.store.certificate_key.as_deref().ok_or_else(|| {
                eyre!("server.cert.store.certificate_key is required for storage store provisioning")
            })?;
            let signing_key_key = cert_config.store.signing_key_key.as_deref().ok_or_else(|| {
                eyre!("server.cert.store.signing_key_key is required for storage store provisioning")
            })?;
            Ok(Some(StoreProvisioningStrategy::storage(
                certificate_key,
                signing_key_key,
            )))
        }
        source
            if source.eq_ignore_ascii_case("secrets")
                || source.eq_ignore_ascii_case("secrets_manager")
                || source.eq_ignore_ascii_case("aws_secrets_manager") =>
        {
            let certificate_key = cert_config.store.certificate_key.as_deref().ok_or_else(|| {
                eyre!(
                    "server.cert.store.certificate_key is required for secrets store provisioning"
                )
            })?;
            let signing_key_key = cert_config.store.signing_key_key.as_deref().ok_or_else(|| {
                eyre!(
                    "server.cert.store.signing_key_key is required for secrets store provisioning"
                )
            })?;
            Ok(Some(StoreProvisioningStrategy::secrets_storage(
                certificate_key,
                signing_key_key,
            )))
        }
        other => Err(eyre!(
            "unsupported certificate store source '{other}'; expected 'filesystem', 'storage', or 'secrets'"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{empty_to_none, store_certificate_strategy};
    use crate::config::{
        AwsConfig, CacheConfig, CertConfig, CertStoreConfig, Config, DatabaseConfig, RedisConfig,
        ServerConfig, StatusListConfig,
    };
    use secrecy::SecretString;

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

    fn base_config() -> Config {
        Config {
            server: ServerConfig {
                host: "localhost".to_string(),
                domain: "example.com".to_string(),
                port: 8000,
                cert: CertConfig {
                    provisioning_strategy: "store".to_string(),
                    email: "admin@example.com".to_string(),
                    organization: None,
                    eku: vec![],
                    acme_directory_url: "https://example.com/dir".to_string(),
                    renewal_cron_schedule: "0 0 0 * * *".to_string(),
                    dns_challenge_server_url: None,
                    store: CertStoreConfig {
                        source: "filesystem".to_string(),
                        certificate_path: Some("/certs/tls.crt".to_string()),
                        signing_key_path: Some("/certs/tls.key".to_string()),
                        certificate_key: None,
                        signing_key_key: None,
                    },
                },
                enable_metrics: false,
                aggregation_uri: None,
            },
            database: DatabaseConfig {
                url: SecretString::from("postgres://postgres:postgres@localhost/status-list"),
            },
            redis: RedisConfig {
                uri: SecretString::from("redis://localhost:6379"),
                require_client_auth: false,
                cert_cache_ttl: 300,
            },
            aws: AwsConfig {
                region: "us-east-1".to_string(),
                secrets_cache_ttl: 300,
                s3_bucket: "bucket".to_string(),
                s3_key_prefix: String::new(),
            },
            cache: CacheConfig {
                ttl: 300,
                max_capacity: 100,
            },
            status_list: StatusListConfig {
                token_exp_secs: 900,
                token_ttl_secs: 300,
            },
        }
    }

    #[test]
    fn test_store_filesystem_strategy_requires_paths() {
        let mut config = base_config();
        config.server.cert.store.signing_key_path = None;

        let err = store_certificate_strategy(&config).unwrap_err();
        assert!(
            err.to_string()
                .contains("server.cert.store.signing_key_path")
        );
    }

    #[test]
    fn test_store_secrets_strategy_requires_keys() {
        let mut config = base_config();
        config.server.cert.store.source = "aws_secrets_manager".to_string();
        config.server.cert.store.certificate_path = None;
        config.server.cert.store.signing_key_path = None;
        config.server.cert.store.certificate_key = Some("cert-secret".to_string());
        config.server.cert.store.signing_key_key = None;

        let err = store_certificate_strategy(&config).unwrap_err();
        assert!(
            err.to_string()
                .contains("server.cert.store.signing_key_key")
        );
    }
}
