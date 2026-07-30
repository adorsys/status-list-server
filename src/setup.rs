//! Composition root assembling outbound infrastructure adapters and creating the AppState container.

#[cfg(feature = "aws")]
use aws_config::{BehaviorVersion, Region};
#[cfg(any(
    feature = "acme",
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql"
))]
use color_eyre::eyre::Context;
use color_eyre::eyre::Result as EyeResult;
#[cfg(any(
    feature = "acme",
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql"
))]
use color_eyre::eyre::eyre;
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use sea_orm::ConnectOptions;
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use sea_orm_migration::MigratorTrait;
#[cfg(any(
    feature = "acme",
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql"
))]
use secrecy::ExposeSecret;
use std::sync::Arc;
#[cfg(any(
    feature = "acme",
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql"
))]
use std::time::Duration;
#[cfg(feature = "acme")]
use tracing::warn;

#[cfg(feature = "aws")]
use crate::cert_manager::challenge::AwsRoute53DnsProvider;
#[cfg(feature = "acme")]
use crate::cert_manager::challenge::{
    AcmeDnsCredentials, AcmeDnsProvider, AzureDnsProvider, CloudflareDnsProvider, Dns01Handler,
    GoogleCloudDnsProvider, PebbleDnsProvider, ServicePrincipal,
};
#[cfg(feature = "acme")]
use crate::cert_manager::http_client::DefaultHttpClient;
#[cfg(feature = "acme")]
use crate::cert_manager::{
    CertManager, StoreProvisioningStrategy, storage::MemoryStorage, storage::Storage,
};
use crate::config::{Config as AppConfig, DatabaseBackend};
#[cfg(feature = "acme")]
use crate::config::{
    DnsProviderKind, ENV_DEVELOPMENT, ENV_PRODUCTION, GcloudKeySource, ResolvedDnsProvider,
};
use crate::domain::{
    ports::{CertificateProvider, CredentialRepo, StatusListHistoryRepo, StatusListRepo},
    service::Service,
};
#[cfg(feature = "aws")]
use crate::outbound::aws::{AwsS3, AwsSecretsManager};
use crate::outbound::cache::MokaStatusListCache;
#[cfg(feature = "acme")]
use crate::outbound::cert::AcmeCertificateProvider;
#[cfg(feature = "memory")]
use crate::outbound::memory::{MemoryCredentials, MemoryStatusListHistory, MemoryStatusLists};
#[cfg(feature = "redis")]
use crate::outbound::redis::Redis;
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use crate::outbound::sql::{
    Migrator, SeaOrmStore, SqlCredentialRepo, SqlStatusListHistoryRepo, SqlStatusListRepo,
};
use crate::server::AppState;

/// Assembles application configuration, connects outbound repositories, and builds `AppState`.
#[cfg(feature = "acme")]
pub async fn build_state(config: &AppConfig) -> EyeResult<AppState> {
    build_state_with_cert_manager(config)
        .await
        .map(|(state, _cert_manager)| state)
}

#[cfg(not(feature = "acme"))]
pub async fn build_state(config: &AppConfig) -> EyeResult<AppState> {
    build_state_internal(config).await
}

#[cfg(feature = "acme")]
pub async fn build_state_with_cert_manager(
    config: &AppConfig,
) -> EyeResult<(AppState, Arc<CertManager>)> {
    build_state_internal(config).await
}

#[cfg(feature = "acme")]
async fn build_state_internal(config: &AppConfig) -> EyeResult<(AppState, Arc<CertManager>)> {
    build_state_impl(config).await
}

#[cfg(not(feature = "acme"))]
async fn build_state_internal(config: &AppConfig) -> EyeResult<AppState> {
    let (state,) = build_state_impl(config).await?;
    Ok(state)
}

#[cfg(feature = "acme")]
type BuildStateResult = (AppState, Arc<CertManager>);

#[cfg(not(feature = "acme"))]
type BuildStateResult = (AppState,);

async fn build_state_impl(config: &AppConfig) -> EyeResult<BuildStateResult> {
    let (status_list_repo, credential_repo, status_list_history): (
        Arc<dyn StatusListRepo>,
        Arc<dyn CredentialRepo>,
        Arc<dyn StatusListHistoryRepo>,
    ) = match config.database.backend {
        #[cfg(feature = "memory")]
        DatabaseBackend::Memory => {
            let memory_history = MemoryStatusListHistory::default();
            let memory_lists = MemoryStatusLists::default().with_history(&memory_history);
            (
                Arc::new(memory_lists),
                Arc::new(MemoryCredentials::default()),
                Arc::new(memory_history),
            )
        }
        #[cfg(not(feature = "memory"))]
        DatabaseBackend::Memory => {
            return Err(color_eyre::eyre::eyre!(
                "Database backend 'memory' configured, but 'memory' feature flag was not compiled in."
            ));
        }
        #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
        db_backend => {
            let db_url = config.database.url.expose_secret();
            if !db_backend.validate_url_scheme(db_url) {
                return Err(color_eyre::eyre::eyre!(
                    "URL scheme does not match configured backend '{}'. Expected URL starting with {}",
                    db_backend.as_str(),
                    db_backend.expected_scheme_description()
                ));
            }

            #[cfg(feature = "sqlite")]
            let mut opt = ConnectOptions::new(db_url.to_string());
            #[cfg(not(feature = "sqlite"))]
            let opt = ConnectOptions::new(db_url.to_string());
            #[cfg(feature = "sqlite")]
            if db_backend == crate::config::DatabaseBackend::Sqlite {
                opt.max_connections(1);
                opt.map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
            }
            let db = sea_orm::Database::connect(opt)
                .await
                .wrap_err("Failed to connect to database")?;

            Migrator::up(&db, None)
                .await
                .wrap_err("Failed to run database migrations")?;

            let db_clone = Arc::new(db);
            (
                Arc::new(SqlStatusListRepo::new(SeaOrmStore::new(db_clone.clone()))),
                Arc::new(SqlCredentialRepo::new(SeaOrmStore::new(db_clone.clone()))),
                Arc::new(SqlStatusListHistoryRepo::new(SeaOrmStore::new(
                    db_clone.clone(),
                ))),
            )
        }
        #[cfg(not(any(feature = "sqlite", feature = "postgres", feature = "mysql")))]
        other => {
            return Err(color_eyre::eyre::eyre!(
                "Database backend '{}' configured, but feature flag for it was not compiled in.",
                other.as_str()
            ));
        }
    };

    #[cfg(feature = "acme")]
    let (cert_provider, cert_manager_opt): (
        Arc<dyn CertificateProvider>,
        Option<Arc<CertManager>>,
    ) = {
        let app_env = std::env::var("APP_ENV").unwrap_or(ENV_DEVELOPMENT.to_string());
        let cert_domains = [config.server.domain.as_str()];
        let (cert_storage, secrets_storage): (Box<dyn Storage>, Box<dyn Storage>) = {
            #[cfg(feature = "aws")]
            {
                if config
                    .server
                    .cert
                    .store
                    .source
                    .eq_ignore_ascii_case("aws_secrets_manager")
                    || !config.aws.s3_bucket.is_empty()
                {
                    let aws_config = aws_config::defaults(BehaviorVersion::latest())
                        .region(Region::new(config.aws.region.clone()))
                        .load()
                        .await;

                    #[cfg(feature = "redis")]
                    let cache_opt = if !config.redis.uri.expose_secret().is_empty() {
                        if let Ok(redis_conn) = config.redis.start(None, None, None).await {
                            Some(Redis::new(redis_conn).with_ttl(config.redis.cert_cache_ttl))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    #[cfg(not(feature = "redis"))]
                    let cache_opt = None;

                    let s3 = AwsS3::new(
                        &aws_config,
                        &config.aws.s3_bucket,
                        &config.aws.region,
                        &config.aws.s3_key_prefix,
                    );
                    let cert_st: Box<dyn Storage> = match cache_opt {
                        Some(c) => Box::new(s3.with_cache(c)),
                        None => Box::new(s3),
                    };

                    let secrets_st: Box<dyn Storage> = Box::new(
                        AwsSecretsManager::new(
                            &aws_config,
                            Duration::from_secs(config.aws.secrets_cache_ttl),
                        )
                        .await?,
                    );
                    (cert_st, secrets_st)
                } else {
                    (
                        Box::new(MemoryStorage::default()),
                        Box::new(MemoryStorage::default()),
                    )
                }
            }
            #[cfg(not(feature = "aws"))]
            {
                (
                    Box::new(MemoryStorage::default()),
                    Box::new(MemoryStorage::default()),
                )
            }
        };

        let cert_strategy = store_certificate_strategy(config)?;
        let uses_acme_strategy = config
            .server
            .cert
            .provisioning_strategy
            .eq_ignore_ascii_case("acme");

        let mut cert_manager_builder = CertManager::builder()
            .domains(cert_domains)
            .email(&config.server.cert.email)
            .organization(config.server.cert.organization.as_deref())
            .acme_directory_url(&config.server.cert.acme_directory_url)
            .cert_storage(cert_storage)
            .secrets_storage(secrets_storage)
            .chain_cache_ttl(Duration::from_secs(config.server.cert.chain_cache_ttl))
            .eku(&config.server.cert.eku);

        cert_manager_builder = if uses_acme_strategy {
            let dns_provider = config
                .server
                .cert
                .dns
                .resolve(&app_env)
                .wrap_err("Invalid DNS provider configuration")?;
            if dns_provider.kind() == DnsProviderKind::Pebble && app_env == ENV_PRODUCTION {
                warn!(
                    "The 'pebble' DNS provider is a development-only fake DNS server \
                     but APP_ENV=production; ACME challenges will not succeed against a real CA"
                );
            }
            let challenge_handler =
                build_dns_challenge_handler(dns_provider, config, &cert_domains).await?;
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
            let root_cert = include_bytes!("../test_data/pebble.pem");
            let http_client = DefaultHttpClient::new(Some(root_cert))?;
            cert_manager_builder = cert_manager_builder.acme_http_client(http_client);
        }

        let certificate_manager = cert_manager_builder.build()?;
        let cert_manager = Arc::new(certificate_manager);
        (
            Arc::new(AcmeCertificateProvider::new(cert_manager.clone())),
            Some(cert_manager),
        )
    };

    #[cfg(not(feature = "acme"))]
    let (cert_provider, _cert_manager_opt): (Arc<dyn CertificateProvider>, Option<()>) = (
        Arc::new(crate::outbound::cert::StoreCertificateProvider::new(
            config.server.cert.store.certificate_path.clone(),
            config.server.cert.store.signing_key_path.clone(),
        )),
        None,
    );

    let status_list_cache = MokaStatusListCache::new(config.cache.ttl, config.cache.max_capacity);

    let history_option = if config.status_list.history_retention_secs == 0 {
        None
    } else {
        Some(status_list_history)
    };

    let service = Arc::new(Service::from_arcs(
        status_list_repo,
        credential_repo,
        Arc::new(status_list_cache),
        history_option,
        cert_provider,
    ));

    let state = AppState {
        service,
        server_domain: config.server.domain.clone(),
        aggregation_uri: empty_to_none(config.server.aggregation_uri.clone()),
        token_exp_secs: config.status_list.token_exp_secs,
        token_ttl_secs: config.status_list.token_ttl_secs,
        max_status_index: config.limits.max_status_index,
        max_statuses_per_request: config.limits.max_statuses_per_request,
        max_serialized_list_size: config.limits.max_serialized_list_size,
        history_retention_secs: config.status_list.history_retention_secs,
    };

    #[cfg(feature = "acme")]
    {
        Ok((state, cert_manager_opt.unwrap()))
    }
    #[cfg(not(feature = "acme"))]
    {
        Ok((state,))
    }
}

pub async fn setup_history_cleanup_scheduler(
    app_state: AppState,
    cron_schedule: &str,
) -> color_eyre::Result<()> {
    use tokio_cron_scheduler::{Job, JobScheduler};
    use tracing::{error, info};

    if app_state.history_retention_secs == 0 {
        info!(
            "Historical snapshots are disabled (history_retention_secs=0), skipping cleanup scheduler"
        );
        return Ok(());
    }

    let scheduler = JobScheduler::new().await?;

    scheduler
        .add(Job::new_async(cron_schedule, move |_, _| {
            let app_state = app_state.clone();
            Box::pin(async move {
                let now = time::OffsetDateTime::now_utc().unix_timestamp();
                let cutoff = now - app_state.history_retention_secs as i64;

                match app_state
                    .service
                    .cleanup_historical_snapshots(cutoff)
                    .await
                {
                    Ok(deleted) => {
                        info!("Cleaned up {deleted} historical status list snapshots older than {cutoff}");
                    }
                    Err(e) => {
                        error!("Failed to clean up historical snapshots: {e:?}");
                    }
                }
            })
        })?)
        .await?;

    scheduler.start().await?;
    info!("Historical snapshot cleanup scheduler started with schedule: {cron_schedule}");
    Ok(())
}

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

#[cfg(feature = "acme")]
fn acme_dns_credentials(account: &crate::config::AcmeDnsAccount) -> AcmeDnsCredentials {
    AcmeDnsCredentials {
        username: account.username.clone(),
        password: account.password.clone(),
        subdomain: account.subdomain.clone(),
    }
}

#[cfg(feature = "acme")]
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
        source if source.eq_ignore_ascii_case("aws_secrets_manager") => {
            let certificate_key = cert_config
                .store
                .certificate_key
                .as_deref()
                .ok_or_else(|| {
                    eyre!(
                        "server.cert.store.certificate_key is required for aws_secrets_manager store provisioning"
                    )
                })?;
            let signing_key_key = cert_config
                .store
                .signing_key_key
                .as_deref()
                .ok_or_else(|| {
                    eyre!(
                        "server.cert.store.signing_key_key is required for aws_secrets_manager store provisioning"
                    )
                })?;
            Ok(Some(StoreProvisioningStrategy::secrets_storage(
                certificate_key,
                signing_key_key,
            )))
        }
        unsupported => Err(eyre!(
            "unsupported certificate store source '{unsupported}'; expected 'filesystem' or 'aws_secrets_manager'"
        )),
    }
}

#[cfg(feature = "acme")]
async fn build_dns_challenge_handler(
    provider: ResolvedDnsProvider<'_>,
    config: &AppConfig,
    cert_domains: &[&str],
) -> EyeResult<Dns01Handler> {
    let handler = match provider {
        #[cfg(feature = "aws")]
        ResolvedDnsProvider::Route53 => {
            let aws_config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(config.aws.region.clone()))
                .load()
                .await;
            Dns01Handler::new(AwsRoute53DnsProvider::new(&aws_config))
        }
        #[cfg(not(feature = "aws"))]
        ResolvedDnsProvider::Route53 => {
            return Err(eyre!(
                "Route53 DNS provider requested, but 'aws' feature is disabled at compile time."
            ));
        }
        ResolvedDnsProvider::Cloudflare(cfg) => {
            Dns01Handler::new(CloudflareDnsProvider::new(cfg.api_token.clone()))
        }
        ResolvedDnsProvider::Gcloud(key) => {
            let key_json = match key {
                GcloudKeySource::Inline(key) => key.expose_secret().to_string(),
                GcloudKeySource::Path(path) => tokio::fs::read_to_string(path)
                    .await
                    .wrap_err_with(|| format!("Failed to read service account key at {path}"))?,
            };
            Dns01Handler::new(GoogleCloudDnsProvider::new(&key_json)?)
        }
        ResolvedDnsProvider::Azure(cfg) => Dns01Handler::new(AzureDnsProvider::new(
            ServicePrincipal {
                tenant_id: cfg.tenant_id.clone(),
                client_id: cfg.client_id.clone(),
                client_secret: cfg.client_secret.clone(),
            },
            &cfg.subscription_id,
            &cfg.resource_group,
        )),
        ResolvedDnsProvider::Acmedns(cfg) => {
            let accounts = cfg
                .accounts
                .iter()
                .map(|(domain, account)| (domain.clone(), acme_dns_credentials(account)))
                .collect();
            let provider = AcmeDnsProvider::new(
                &cfg.server_url,
                cfg.default_account().as_ref().map(acme_dns_credentials),
                accounts,
            )?;
            provider.check_order_domains(cert_domains)?;
            Dns01Handler::new(provider)
        }
        ResolvedDnsProvider::Pebble => {
            let dns_url = config
                .server
                .cert
                .dns_challenge_server_url
                .as_deref()
                .unwrap_or("http://challtestsrv:8055");
            Dns01Handler::new(PebbleDnsProvider::new(dns_url))
        }
    };
    Ok(handler)
}

#[cfg(all(test, feature = "acme"))]
mod tests {
    use super::*;
    use crate::cert_manager::challenge::Dns01Handler;
    use crate::config::{
        AcmeDnsConfig, AzureDnsConfig, CloudflareDnsConfig, DnsProviderKind, ENV_PRODUCTION,
        GcloudDnsConfig,
    };
    use sealed_test::prelude::*;

    fn build_dns_challenge_handler(
        provider: DnsProviderKind,
        config: &mut AppConfig,
        cert_domains: &[&str],
    ) -> EyeResult<Dns01Handler> {
        config.server.cert.dns.provider = Some(provider);
        let resolved = config.server.cert.dns.resolve(ENV_PRODUCTION)?;
        tokio::runtime::Runtime::new()
            .expect("failed to build test runtime")
            .block_on(super::build_dns_challenge_handler(
                resolved,
                config,
                cert_domains,
            ))
    }

    #[sealed_test]
    fn builds_handler_for_each_configured_provider() {
        let mut config = AppConfig::load().expect("Failed to load config");
        let domain = config.server.domain.clone();
        let domains = [domain.as_str()];

        #[cfg(feature = "aws")]
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Route53, &mut config, &domains).is_ok()
        );
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Pebble, &mut config, &domains).is_ok()
        );

        config.server.cert.dns.cloudflare = Some(CloudflareDnsConfig {
            api_token: "token".into(),
        });
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Cloudflare, &mut config, &domains).is_ok()
        );

        config.server.cert.dns.azure = Some(AzureDnsConfig {
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            subscription_id: "sub".into(),
            resource_group: "rg".into(),
        });
        assert!(build_dns_challenge_handler(DnsProviderKind::Azure, &mut config, &domains).is_ok());

        config.server.cert.dns.acmedns = Some(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: Some("user".into()),
            password: Some("password".into()),
            subdomain: Some("subdomain".into()),
            accounts: Default::default(),
        });
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Acmedns, &mut config, &domains).is_ok()
        );

        let key_json = serde_json::json!({
            "client_email": "acme@test-project.iam.gserviceaccount.com",
            "private_key": include_str!("../test_data/gcloud_test_key.dummy.pem"),
            "token_uri": "https://oauth2.googleapis.com/token",
            "project_id": "test-project",
        });
        config.server.cert.dns.gcloud = Some(GcloudDnsConfig {
            service_account_key: Some(key_json.to_string().into()),
            service_account_key_path: None,
        });
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Gcloud, &mut config, &domains).is_ok()
        );
    }
}

#[cfg(test)]
mod general_tests {
    use super::*;
    use sealed_test::prelude::*;

    /// Verifies that build_state succeeds with AppConfig::load() defaults under
    /// the default feature set, catching missing test_data/ or config mismatch issues.
    #[sealed_test(env = [("APP_ENV", "development")])]
    fn build_state_succeeds_under_default_config() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = AppConfig::load().expect("Failed to load config");
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            if let Err(ref e) = build_state(&config).await {
                panic!("build_state failed under default configuration: {e:?}");
            }
        });
    }
}
