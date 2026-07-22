use crate::{
    adapters::{
        aws::{AwsS3, AwsSecretsManager},
        cache::MokaStatusListCache,
        certificate::AcmeCertificateProvider,
        redis::Redis,
        sea_orm::{
            Migrator, SeaOrmCredentialRepository, SeaOrmStatusListHistoryRepository,
            SeaOrmStatusListRepository, store::SeaOrmStore,
        },
    },
    application::{
        CredentialApplicationService, CredentialService, StatusListApplicationServiceWithHistory,
        StatusListService,
    },
    cert_manager::{
        CertManager, StoreProvisioningStrategy,
        challenge::{
            AcmeDnsCredentials, AcmeDnsProvider, AwsRoute53DnsProvider, AzureDnsProvider,
            CloudflareDnsProvider, Dns01Handler, GoogleCloudDnsProvider, PebbleDnsProvider,
            ServicePrincipal,
        },
    },
    config::{
        Config as AppConfig, DnsProviderKind, ENV_DEVELOPMENT, ENV_PRODUCTION, GcloudKeySource,
        ResolvedDnsProvider,
    },
    ports::{
        CertificateProvider, CredentialRepository, StatusListCache, StatusListHistoryRepository,
        StatusListRepository,
    },
};
use aws_config::{BehaviorVersion, Region, SdkConfig};
use color_eyre::eyre::{Context, Result as EyeResult, eyre};
use sea_orm::{ConnectOptions, Database};
use sea_orm_migration::MigratorTrait;
use secrecy::ExposeSecret;
use std::{sync::Arc, time::Duration};
use tracing::warn;

use crate::cert_manager::http_client::DefaultHttpClient;

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

/// Map an ACME-DNS account from the config layer to provider credentials
fn acme_dns_credentials(account: &crate::config::AcmeDnsAccount) -> AcmeDnsCredentials {
    AcmeDnsCredentials {
        username: account.username.clone(),
        password: account.password.clone(),
        subdomain: account.subdomain.clone(),
    }
}

#[derive(Clone)]
pub struct AppState {
    pub status_lists: Arc<dyn StatusListService>,
    pub credentials: Arc<dyn CredentialService>,
    pub certificate_provider: Arc<dyn CertificateProvider>,
    pub server_domain: String,
    pub aggregation_uri: Option<String>,
    pub token_exp_secs: u64,
    pub token_ttl_secs: u64,
    pub max_status_index: i32,
    pub max_statuses_per_request: usize,
    /// Retention period for historical status list snapshots in seconds.
    /// Set to 0 to disable historical snapshots entirely.
    pub history_retention_secs: u64,
}

pub async fn build_state(config: &AppConfig) -> EyeResult<AppState> {
    build_state_with_cert_manager(config)
        .await
        .map(|(state, _cert_manager)| state)
}

pub async fn build_state_with_cert_manager(
    config: &AppConfig,
) -> EyeResult<(AppState, Arc<CertManager>)> {
    let db_url = config.database.url.expose_secret();
    let db_backend = config.database.backend;

    // Validate URL scheme matches the configured backend
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
    let db = Database::connect(opt)
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

    // Domains certificates are ordered for; the single source for both the
    // ACME order and the challenge handler's startup coverage checks.
    let cert_domains = [config.server.domain.as_str()];

    // Read APP_ENV once — needed for DNS provider defaulting (ACME path) and
    // for the development HTTP-client override below.
    let app_env = std::env::var("APP_ENV").unwrap_or(ENV_DEVELOPMENT.to_string());

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
            build_dns_challenge_handler(dns_provider, config, &aws_config, &cert_domains).await?;
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
        let root_cert = include_bytes!("../test_data/pebble.pem");
        let http_client = DefaultHttpClient::new(Some(root_cert))?;
        cert_manager_builder = cert_manager_builder.acme_http_client(http_client);
    }

    let certificate_manager = cert_manager_builder.build()?;

    let db_clone = Arc::new(db);
    let status_list_repo = SeaOrmStore::new(db_clone.clone());
    let credential_repo = SeaOrmStore::new(db_clone.clone());
    let status_list_history_repo = SeaOrmStore::new(db_clone.clone());
    let cache = MokaStatusListCache::new(config.cache.ttl, config.cache.max_capacity);
    let status_lists: Arc<dyn StatusListRepository> =
        Arc::new(SeaOrmStatusListRepository::new(status_list_repo));
    let credentials: Arc<dyn CredentialRepository> =
        Arc::new(SeaOrmCredentialRepository::new(credential_repo));
    let status_list_history: Arc<dyn StatusListHistoryRepository> = Arc::new(
        SeaOrmStatusListHistoryRepository::new(status_list_history_repo),
    );
    let status_list_cache: Arc<dyn StatusListCache> = Arc::new(cache);
    let cert_manager = Arc::new(certificate_manager);
    let token_exp_secs = config.status_list.token_exp_secs;
    let status_list_service: Arc<dyn StatusListService> =
        if config.status_list.history_retention_secs == 0 {
            Arc::new(
                StatusListApplicationServiceWithHistory::<
                    dyn StatusListRepository,
                    dyn StatusListCache,
                    dyn StatusListHistoryRepository,
                >::without_history(status_lists, status_list_cache, token_exp_secs)
                .with_max_serialized_list_size(config.limits.max_serialized_list_size),
            )
        } else {
            Arc::new(
                StatusListApplicationServiceWithHistory::new(
                    status_lists,
                    status_list_cache,
                    status_list_history,
                    token_exp_secs,
                )
                .with_max_serialized_list_size(config.limits.max_serialized_list_size),
            )
        };
    Ok((
        AppState {
            status_lists: status_list_service,
            credentials: Arc::new(CredentialApplicationService::new(credentials)),
            certificate_provider: Arc::new(AcmeCertificateProvider::new(cert_manager.clone())),
            server_domain: config.server.domain.clone(),
            aggregation_uri: empty_to_none(config.server.aggregation_uri.clone()),
            token_exp_secs: config.status_list.token_exp_secs,
            token_ttl_secs: config.status_list.token_ttl_secs,
            max_status_index: config.limits.max_status_index,
            max_statuses_per_request: config.limits.max_statuses_per_request,
            history_retention_secs: config.status_list.history_retention_secs,
        },
        cert_manager,
    ))
}

/// Setup the scheduled task to clean up old status list history snapshots.
/// This runs daily at midnight UTC by default.
pub async fn setup_history_cleanup_scheduler(
    app_state: AppState,
    cron_schedule: &str,
) -> color_eyre::Result<()> {
    use tokio_cron_scheduler::{Job, JobScheduler};
    use tracing::{error, info};

    // Skip scheduling if historical snapshots are disabled
    if app_state.history_retention_secs == 0 {
        info!(
            "Historical snapshots are disabled (history_retention_secs=0), skipping cleanup scheduler"
        );
        return Ok(());
    }

    let scheduler = JobScheduler::new().await?;

    // Schedule the cleanup task
    scheduler
        .add(Job::new_async(cron_schedule, move |_, _| {
            let app_state = app_state.clone();
            Box::pin(async move {
                let now = time::OffsetDateTime::now_utc().unix_timestamp();
                let cutoff = now - app_state.history_retention_secs as i64;

                match app_state.status_lists.cleanup_history(cutoff).await {
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

/// Build the DNS-01 challenge handler for the resolved DNS provider.
///
/// `cert_domains` are the domains certificates will be ordered for, used to
/// validate at startup that the provider can serve challenges for them.
async fn build_dns_challenge_handler(
    provider: ResolvedDnsProvider<'_>,
    config: &AppConfig,
    aws_config: &SdkConfig,
    cert_domains: &[&str],
) -> EyeResult<Dns01Handler> {
    let handler = match provider {
        ResolvedDnsProvider::Route53 => Dns01Handler::new(AwsRoute53DnsProvider::new(aws_config)),
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
            // Catch a credentials gap or an overloaded two-value TXT window
            // for the ordered domains at startup instead of at the first renewal
            provider.check_order_domains(cert_domains)?;
            Dns01Handler::new(provider)
        }
        ResolvedDnsProvider::Pebble => {
            // The DNS challenge server URL is optional and only used in dev mode;
            // it falls back to the well-known Pebble challenge test server when unset.
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::{empty_to_none, store_certificate_strategy};
    use crate::config::{
        AcmeDnsConfig, AwsConfig, AzureDnsConfig, CacheConfig, CertConfig, CertStoreConfig,
        CloudflareDnsConfig, Config, DatabaseConfig, DnsConfig, GcloudDnsConfig, LimitsConfig,
        RateLimitConfig, RedisConfig, ServerConfig, StatusListConfig,
    };
    use sealed_test::prelude::*;
    use secrecy::SecretString;

    fn test_sdk_config() -> SdkConfig {
        SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .build()
    }

    // Sync wrapper shadowing the async builder: sealed tests fork the
    // process and run without an async runtime
    // and resolves the given provider first, exactly as the boot path does
    fn build_dns_challenge_handler(
        provider: DnsProviderKind,
        config: &mut AppConfig,
        aws_config: &SdkConfig,
        cert_domains: &[&str],
    ) -> EyeResult<Dns01Handler> {
        config.server.cert.dns.provider = Some(provider);
        let resolved = config.server.cert.dns.resolve(ENV_PRODUCTION)?;
        tokio::runtime::Runtime::new()
            .expect("failed to build test runtime")
            .block_on(super::build_dns_challenge_handler(
                resolved,
                config,
                aws_config,
                cert_domains,
            ))
    }

    #[sealed_test]
    fn builds_handler_for_each_configured_provider() {
        let sdk = test_sdk_config();
        let mut config = AppConfig::load().expect("Failed to load config");
        let domain = config.server.domain.clone();
        let domains = [domain.as_str()];

        // Route53 and Pebble need no provider-specific settings
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Route53, &mut config, &sdk, &domains)
                .is_ok()
        );
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Pebble, &mut config, &sdk, &domains)
                .is_ok()
        );

        config.server.cert.dns.cloudflare = Some(CloudflareDnsConfig {
            api_token: "token".into(),
        });
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Cloudflare, &mut config, &sdk, &domains)
                .is_ok()
        );

        config.server.cert.dns.azure = Some(AzureDnsConfig {
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            subscription_id: "sub".into(),
            resource_group: "rg".into(),
        });
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Azure, &mut config, &sdk, &domains)
                .is_ok()
        );

        config.server.cert.dns.acmedns = Some(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: Some("user".into()),
            password: Some("password".into()),
            subdomain: Some("subdomain".into()),
            accounts: Default::default(),
        });
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Acmedns, &mut config, &sdk, &domains)
                .is_ok()
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
            build_dns_challenge_handler(DnsProviderKind::Gcloud, &mut config, &sdk, &domains)
                .is_ok()
        );
    }

    // Boot cannot proceed on missing provider settings; since the builder
    // takes a resolved provider, the rejection now comes from resolve()
    #[sealed_test]
    fn fails_when_provider_settings_are_missing() {
        let sdk = test_sdk_config();
        let mut config = AppConfig::load().expect("Failed to load config");
        let domain = config.server.domain.clone();
        let domains = [domain.as_str()];

        for kind in [
            DnsProviderKind::Cloudflare,
            DnsProviderKind::Gcloud,
            DnsProviderKind::Azure,
            DnsProviderKind::Acmedns,
        ] {
            assert!(build_dns_challenge_handler(kind, &mut config, &sdk, &domains).is_err());
        }
    }

    #[sealed_test]
    fn acme_dns_must_cover_the_server_domain_at_startup() {
        let sdk = test_sdk_config();
        let mut config = AppConfig::load().expect("Failed to load config");
        let domain = config.server.domain.clone();
        let domains = [domain.as_str()];

        let account = crate::config::AcmeDnsAccount {
            username: "user".into(),
            password: "password".into(),
            subdomain: "subdomain".into(),
        };
        let mut acmedns = AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: None,
            password: None,
            subdomain: None,
            accounts: [("other.example.com".to_string(), account.clone())].into(),
        };

        // Map-only config not covering the server domain fails at startup
        config.server.cert.dns.acmedns = Some(acmedns.clone());
        let err =
            build_dns_challenge_handler(DnsProviderKind::Acmedns, &mut config, &sdk, &domains)
                .err()
                .expect("startup must fail without an account for the server domain");
        assert!(err.to_string().contains(&domain));

        // An entry for the server domain (any cosmetic form) makes it build
        acmedns.accounts.insert(domain.to_uppercase(), account);
        config.server.cert.dns.acmedns = Some(acmedns);
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Acmedns, &mut config, &sdk, &domains)
                .is_ok()
        );
    }

    #[sealed_test]
    fn acme_dns_account_conflicts_fail_at_boot() {
        let sdk = test_sdk_config();
        let mut config = AppConfig::load().expect("Failed to load config");
        let domain = config.server.domain.clone();
        let domains = [domain.as_str()];

        // Two entries normalizing to the server domain, different credentials:
        // the provider is built eagerly at boot, so this must fail here
        let account = |subdomain: &str| crate::config::AcmeDnsAccount {
            username: "user".into(),
            password: "password".into(),
            subdomain: subdomain.into(),
        };
        config.server.cert.dns.acmedns = Some(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: None,
            password: None,
            subdomain: None,
            accounts: [
                (domain.clone(), account("first")),
                (domain.to_uppercase(), account("second")),
            ]
            .into(),
        });

        let err =
            build_dns_challenge_handler(DnsProviderKind::Acmedns, &mut config, &sdk, &domains)
                .err()
                .expect("conflicting account entries must fail the boot-path builder");
        assert!(err.to_string().contains("Conflicting ACME-DNS accounts"));
    }

    #[sealed_test]
    fn acme_dns_rejects_three_cert_domains_on_one_account() {
        let sdk = test_sdk_config();
        let mut config = AppConfig::load().expect("Failed to load config");
        let domains = ["a.example.com", "b.example.com", "c.example.com"];

        // All three fall back to the default account, whose two-value TXT
        // window cannot hold three digests at once
        config.server.cert.dns.acmedns = Some(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: Some("user".into()),
            password: Some("password".into()),
            subdomain: Some("subdomain".into()),
            accounts: Default::default(),
        });

        let err =
            build_dns_challenge_handler(DnsProviderKind::Acmedns, &mut config, &sdk, &domains)
                .err()
                .expect("three identifiers on one account must fail the boot-path builder");
        assert!(err.to_string().contains("two most recent TXT values"));

        // Mapping one of them to its own account restores a valid setup
        if let Some(acmedns) = &mut config.server.cert.dns.acmedns {
            acmedns.accounts.insert(
                "c.example.com".to_string(),
                crate::config::AcmeDnsAccount {
                    username: "user-c".into(),
                    password: "password-c".into(),
                    subdomain: "subdomain-c".into(),
                },
            );
        }
        assert!(
            build_dns_challenge_handler(DnsProviderKind::Acmedns, &mut config, &sdk, &domains)
                .is_ok()
        );
    }

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
                    chain_cache_ttl: 3600,
                    renewal_cron_schedule: "0 0 0 * * *".to_string(),
                    dns_challenge_server_url: None,
                    store: CertStoreConfig {
                        source: "filesystem".to_string(),
                        certificate_path: Some("/certs/tls.crt".to_string()),
                        signing_key_path: Some("/certs/tls.key".to_string()),
                        certificate_key: None,
                        signing_key_key: None,
                    },
                    dns: DnsConfig::default(),
                },
                enable_metrics: false,
                aggregation_uri: None,
            },
            database: DatabaseConfig {
                url: SecretString::from("postgres://postgres:postgres@localhost/status-list"),
                backend: crate::config::DatabaseBackend::Postgres,
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
                history_retention_secs: 7776000, // 90 days
            },
            rate_limit: RateLimitConfig {
                strict_burst_size: 10,
                strict_period_secs: 60,
                permissive_burst_size: 100,
                permissive_period_secs: 60,
            },
            limits: LimitsConfig {
                max_body_size_bytes: 2_097_152,
                max_status_index: 100_000,
                max_statuses_per_request: 5_000,
                max_serialized_list_size: 1_048_576,
            },
        }
    }

    #[test]
    fn store_strategy_ignores_dns_config() {
        // Case 1: no DNS section at all (default DnsConfig)
        let config = base_config(); // provisioning_strategy = "store"
        let result = store_certificate_strategy(&config);
        assert!(
            result.is_ok(),
            "store strategy must not touch DNS config: {result:?}"
        );

        // Case 2: a broken DNS section (provider selected but credentials absent)
        let mut config = base_config();
        config.server.cert.dns.provider = Some(DnsProviderKind::Cloudflare);
        // cloudflare credentials intentionally absent
        let result = store_certificate_strategy(&config);
        assert!(
            result.is_ok(),
            "store strategy must not call resolve() even with a bad DNS section: {result:?}"
        );
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
