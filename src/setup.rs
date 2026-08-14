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
#[cfg(feature = "acme")]
use color_eyre::eyre::eyre;
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use sea_orm::ConnectOptions;
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use sea_orm_migration::MigratorTrait;
#[cfg(any(
    feature = "acme",
    feature = "vault",
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql"
))]
use secrecy::ExposeSecret;
use std::sync::Arc;
#[cfg(any(
    feature = "acme",
    feature = "vault",
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
    CertManager, StoreProvisioningStrategy,
    storage::{CryptoMaterialCachePolicy, MemoryStorage, Storage},
};
use crate::config::{Config as AppConfig, DatabaseBackend};
#[cfg(feature = "acme")]
use crate::config::{
    DnsProviderKind, ENV_DEVELOPMENT, ENV_PRODUCTION, GcloudKeySource, ResolvedDnsProvider,
};
use crate::domain::{
    ports::{CertificateProvider, CredentialRepo, StatusListRepo, StatusListSnapshotRepo},
    service::Service,
};
#[cfg(feature = "aws")]
use crate::outbound::aws::AwsSecretsManager;
use crate::outbound::cache::MokaStatusListCache;
#[cfg(feature = "acme")]
use crate::outbound::cert::AcmeCertificateProvider;
#[cfg(feature = "memory")]
use crate::outbound::memory::{MemoryCredentials, MemoryStatusListSnapshotRepo, MemoryStatusLists};
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use crate::outbound::sql::{
    Migrator, SeaOrmStore, SqlCredentialRepo, SqlStatusListRepo, SqlStatusListSnapshotRepo,
    verify_binlog_format, verify_innodb_engines,
};
#[cfg(feature = "vault")]
use crate::outbound::vault::VaultClient;
use crate::server::AppState;
use crate::server::health::{AlwaysReady, Readiness};

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
    // Hoisted DB handle captured from the backend branches below so the
    // readiness probe can reach the real adapter (the domain ports only expose
    // the higher-level repositories).
    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    let mut db_arc: Option<Arc<sea_orm::DatabaseConnection>> = None;

    let (status_list_repo, credential_repo, status_list_snapshot): (
        Arc<dyn StatusListRepo>,
        Arc<dyn CredentialRepo>,
        Arc<dyn StatusListSnapshotRepo>,
    ) = match config.database.backend {
        #[cfg(feature = "memory")]
        DatabaseBackend::Memory => {
            let memory_snapshot = MemoryStatusListSnapshotRepo::default();
            let memory_lists = MemoryStatusLists::default().with_snapshot(&memory_snapshot);
            (
                Arc::new(memory_lists),
                Arc::new(MemoryCredentials::default()),
                Arc::new(memory_snapshot),
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

            let mut opt = ConnectOptions::new(db_url.to_string());

            if db_backend == DatabaseBackend::Sqlite || db_backend == DatabaseBackend::Memory {
                opt.max_connections(1);
                #[cfg(feature = "sqlite")]
                opt.map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
            } else {
                let pool = &config.database.pool;
                opt.max_connections(pool.max_connections)
                    .min_connections(pool.min_connections)
                    .acquire_timeout(Duration::from_secs(pool.acquire_timeout_secs))
                    .connect_timeout(Duration::from_secs(pool.connect_timeout_secs))
                    .idle_timeout(Duration::from_secs(pool.idle_timeout_secs))
                    .max_lifetime(Duration::from_secs(pool.max_lifetime_secs))
                    .sqlx_logging(false);
            }

            let db = sea_orm::Database::connect(opt)
                .await
                .wrap_err("Failed to connect to database")?;

            Migrator::up(&db, None)
                .await
                .wrap_err("Failed to run database migrations")?;

            verify_innodb_engines(&db).await.wrap_err(
                "Startup aborted: one or more tables are not using the InnoDB storage engine. \
                     See the logged error(s) above for the table name(s) and the ALTER TABLE \
                     runbook command to fix the issue.",
            )?;

            verify_binlog_format(&db).await.wrap_err(
                "Startup aborted: MySQL binary logging is incompatible with the READ COMMITTED \
                     isolation level this server pins on every write. See the logged error \
                     above for the fix.",
            )?;

            let db_clone = Arc::new(db);
            db_arc = Some(db_clone.clone());
            (
                Arc::new(SqlStatusListRepo::new(SeaOrmStore::new(db_clone.clone()))),
                Arc::new(SqlCredentialRepo::new(SeaOrmStore::new(db_clone.clone()))),
                Arc::new(SqlStatusListSnapshotRepo::new(SeaOrmStore::new(
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
        let material_storage = build_crypto_material_storage(config).await?;

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
            .crypto_material_cache_policy(CryptoMaterialCachePolicy::new(
                Duration::from_secs(config.server.cert.material_cache_ttl),
                Duration::from_secs(config.server.cert.signing_key_cache_ttl),
            ))
            .crypto_material_storage(material_storage)
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

    let snapshot_option = if config.status_list.snapshot_retention_secs == 0 {
        None
    } else {
        Some(status_list_snapshot)
    };

    let service = Arc::new(Service::from_arcs(
        status_list_repo,
        credential_repo,
        Arc::new(status_list_cache),
        snapshot_option,
        cert_provider,
    ));

    // Assemble the readiness probes from the real adapters captured above.
    let mut readiness = Readiness::default();

    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    {
        match db_arc {
            Some(db) => readiness = readiness.with_check(crate::server::health::DbCheck::new(db)),
            None => readiness = readiness.with_check(AlwaysReady::new("database")),
        }
    }
    #[cfg(not(any(feature = "sqlite", feature = "postgres", feature = "mysql")))]
    {
        readiness = readiness.with_check(AlwaysReady::new("database"));
    }

    // Redis is an optional certificate-cache accelerator in this setup. Startup
    // falls back to direct certificate storage when Redis cannot connect, so it
    // is intentionally omitted from readiness gating.

    #[cfg(feature = "acme")]
    {
        if let Some(manager) = &cert_manager_opt {
            readiness =
                readiness.with_check(crate::server::health::CertStoreCheck::new(manager.clone()));
        }
    }
    #[cfg(not(feature = "acme"))]
    {
        readiness = readiness.with_check(crate::server::health::FilesystemCertCheck::new(
            config.server.cert.store.certificate_path.clone(),
            config.server.cert.store.signing_key_path.clone(),
        ));
    }

    let state = AppState {
        service,
        server_domain: config.server.domain.clone(),
        aggregation_uri: empty_to_none(config.server.aggregation_uri.clone()),
        token_exp_secs: config.status_list.token_exp_secs,
        token_ttl_secs: config.status_list.token_ttl_secs,
        max_status_index: config.limits.max_status_index,
        max_statuses_per_request: config.limits.max_statuses_per_request,
        max_serialized_list_size: config.limits.max_serialized_list_size,
        snapshot_retention_secs: config.status_list.snapshot_retention_secs,
        readiness,
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

pub async fn setup_snapshot_cleanup_scheduler(
    app_state: AppState,
    cron_schedule: &str,
) -> color_eyre::Result<()> {
    use tokio_cron_scheduler::{Job, JobScheduler};
    use tracing::{error, info, warn};

    if app_state.snapshot_retention_secs == 0 {
        info!(
            "Historical snapshots are disabled (snapshot_retention_secs=0), skipping cleanup scheduler"
        );
        return Ok(());
    }

    let scheduler = JobScheduler::new().await?;

    scheduler
        .add(Job::new_async(cron_schedule, move |_, _| {
            let app_state = app_state.clone();
            Box::pin(async move {
                let now = time::OffsetDateTime::now_utc().unix_timestamp();
                let cutoff = now - app_state.snapshot_retention_secs as i64;

                match app_state
                    .service
                    .cleanup_snapshots(cutoff)
                    .await
                {
                    Ok(deleted) => {
                        info!("Cleaned up {deleted} historical status list snapshots older than {cutoff}");
                    }
                    // Expected, not exceptional: the sweep scans a range of
                    // `idx_status_list_history_exp` while snapshot inserts write
                    // into the top of it. The next run retries the lost batch, so
                    // this must not page.
                    Err(crate::domain::models::status_list::StatusListError::Contention {
                        code,
                    }) => {
                        warn!(
                            db.contention_code = code,
                            "Historical snapshot cleanup lost a lock race; \
                             the next scheduled run will retry the remaining rows"
                        );
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
async fn build_crypto_material_storage(config: &AppConfig) -> EyeResult<Box<dyn Storage>> {
    let backend = config.server.cert.material_backend.as_str();
    if backend.eq_ignore_ascii_case("memory") {
        tracing::info!("Using in-memory cryptographic-material backend");
        return Ok(Box::new(MemoryStorage::default()));
    }

    if backend.eq_ignore_ascii_case("vault") {
        #[cfg(feature = "vault")]
        {
            tracing::info!("Using Vault KV v2 as cryptographic-material backend");
            return Ok(Box::new(
                VaultClient::builder(&config.vault.addr, config.vault.token.clone())
                    .mount(&config.vault.mount)
                    .path_prefix(&config.vault.path_prefix)
                    .namespace(config.vault.namespace.as_deref())
                    .secrets_cache_ttl(Duration::ZERO)
                    .timeout(Duration::from_secs(config.vault.timeout_secs))
                    .build()?,
            ));
        }
        #[cfg(not(feature = "vault"))]
        {
            return Err(eyre!(
                "cryptographic-material backend 'vault' configured, but 'vault' feature is disabled"
            ));
        }
    }

    if backend.eq_ignore_ascii_case("aws_secrets_manager") {
        #[cfg(feature = "aws")]
        {
            tracing::info!("Using AWS Secrets Manager as cryptographic-material backend");
            let aws_config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(config.aws.region.clone()))
                .load()
                .await;
            return Ok(Box::new(
                AwsSecretsManager::new(&aws_config, Duration::ZERO).await?,
            ));
        }
        #[cfg(not(feature = "aws"))]
        {
            return Err(eyre!(
                "cryptographic-material backend 'aws_secrets_manager' configured, but 'aws' feature is disabled"
            ));
        }
    }

    Err(eyre!(
        "unsupported cryptographic-material backend '{backend}'; expected 'memory', 'aws_secrets_manager', or 'vault'"
    ))
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

    #[test]
    fn builds_handler_for_each_configured_provider() {
        let mut config = AppConfig::load_from_overrides(&[]).expect("Failed to load config");
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

    /// Verifies that build_state succeeds with AppConfig::load_from_overrides defaults under
    /// the default feature set, catching missing test_data/ or config mismatch issues.
    /// When SQL features are enabled, uses memory backend to avoid requiring a real database.
    #[test]
    fn build_state_succeeds_under_default_config() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = AppConfig::load_from_overrides(&[
            ("APP_DATABASE__BACKEND", "memory"),
            ("APP_DATABASE__URL", "memory:"),
            #[cfg(feature = "vault")]
            ("APP_VAULT__TOKEN", "root"),
        ])
        .expect("Failed to load config");
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            if let Err(ref e) = build_state(&config).await {
                panic!("build_state failed under default configuration: {e:?}");
            }
        });
    }

    /// Verifies that a saturated pool returns an error within `acquire_timeout`
    /// rather than queuing indefinitely.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn test_pool_acquire_timeout_fires() {
        use sea_orm::{ConnectOptions, Database};
        use std::time::Instant;
        use testcontainers_modules::{
            postgres::Postgres as PostgresImage, testcontainers::runners::AsyncRunner,
        };

        let (_container, db_url) = if let Ok(url) = std::env::var("APP_DATABASE__URL") {
            (None, url)
        } else {
            let node = PostgresImage::default()
                .start()
                .await
                .expect("Failed to start Postgres container for pool test");
            let host = node
                .get_host()
                .await
                .expect("Failed to resolve Postgres host for pool test");
            let port = node
                .get_host_port_ipv4(5432)
                .await
                .expect("Failed to resolve Postgres port for pool test");
            (
                Some(node),
                format!("postgres://postgres:postgres@{host}:{port}/postgres"),
            )
        };

        // sea-orm folds `connect_timeout` and `acquire_timeout` onto sqlx's
        // single `PoolOptions::acquire_timeout`, and pool construction opens a
        // connection eagerly under it — so this bound also caps the initial
        // handshake, which exceeds a second on some hosts (Docker Desktop on
        // Windows). Sized to clear that while staying under the holder's 10s.
        const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

        let mut opt = ConnectOptions::new(db_url);
        opt.max_connections(1)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .sqlx_logging(false);

        let db = std::sync::Arc::new(
            Database::connect(opt)
                .await
                .expect("Failed to connect for pool test"),
        );

        // Hold the single connection with a long-running query
        let db_clone = db.clone();
        let _holder = tokio::spawn(async move {
            let _ = sea_orm::ConnectionTrait::execute_unprepared(
                db_clone.as_ref(),
                "SELECT pg_sleep(10)",
            )
            .await;
        });

        // Give the holder time to acquire the connection
        tokio::time::sleep(Duration::from_millis(100)).await;

        let start = Instant::now();
        let result = sea_orm::ConnectionTrait::execute_unprepared(db.as_ref(), "SELECT 1").await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "Expected pool-exhaustion error, got Ok");
        // Lower bound: the failure came from the acquire timeout, not an
        // unrelated early error.
        assert!(
            elapsed >= ACQUIRE_TIMEOUT,
            "failed before acquire_timeout could fire, so the error was not \
             pool exhaustion: {elapsed:?}"
        );
        // Upper bound: it gave up instead of queueing behind the holder's 10s
        // query. Sized against that 10s, leaving headroom for jitter.
        const UPPER_BOUND: Duration = Duration::from_secs(8);
        assert!(
            elapsed < UPPER_BOUND,
            "acquire_timeout did not fire quickly enough, so the acquire queued \
             behind the holder rather than giving up: {elapsed:?}"
        );
    }
}
