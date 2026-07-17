use crate::{
    cert_manager::{
        CertManager,
        challenge::Dns01Handler,
    },
    config::{Config as AppConfig, DnsProviderKind, ENV_DEVELOPMENT, ENV_PRODUCTION},
    database::{Migrator, queries::SeaOrmStore},
    models::{Credentials, StatusListRecord},
};
use color_eyre::eyre::{Context, Result as EyeResult};
use sea_orm::{ConnectOptions, Database};
use sea_orm_migration::MigratorTrait;
use secrecy::ExposeSecret;
use std::{sync::Arc, time::Duration};
use tracing::warn;

use super::{cache::StatusListCache, cert_manager::http_client::DefaultHttpClient};

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

#[derive(Clone)]
pub struct AppState {
    pub credential_repo: SeaOrmStore<Credentials>,
    pub status_list_repo: SeaOrmStore<StatusListRecord>,
    pub server_domain: String,
    pub cert_manager: Arc<CertManager>,
    pub cache: StatusListCache,
    pub aggregation_uri: Option<String>,
    pub token_exp_secs: u64,
    pub token_ttl_secs: u64,
}

pub async fn build_state(config: &AppConfig) -> EyeResult<AppState> {
    let db_url = config.database.url.expose_secret();

    #[cfg(feature = "sqlite")]
    let mut opt = ConnectOptions::new(db_url.to_string());
    #[cfg(not(feature = "sqlite"))]
    let opt = ConnectOptions::new(db_url.to_string());
    #[cfg(feature = "sqlite")]
    {
        opt.max_connections(1);
        opt.map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
    }
    
    let db = Database::connect(opt)
        .await
        .wrap_err("Failed to connect to database")?;

    Migrator::up(&db, None)
        .await
        .wrap_err("Failed to run database migrations")?;

    // Initialize the challenge handler with the configured DNS provider.
    // When no provider is configured, the environment decides: Route53 in
    // production, Pebble (fake DNS server) in development.
    let app_env = std::env::var("APP_ENV").unwrap_or(ENV_DEVELOPMENT.to_string());
    let dns_provider = config
        .server
        .cert
        .dns
        .resolve(&app_env)
        .wrap_err("Invalid DNS provider configuration")?;
    if dns_provider == DnsProviderKind::Pebble && app_env == ENV_PRODUCTION {
        warn!(
            "The 'pebble' DNS provider is a development-only fake DNS server \
             but APP_ENV=production; ACME challenges will not succeed against a real CA"
        );
    }
    let challenge_handler = build_dns_challenge_handler(dns_provider, config).await?;

    // Initialize the storage backends for the certificate manager
    // These are feature-gated and will use memory implementations when
    // the corresponding feature is not enabled
    let cert_storage = build_cert_storage(config).await?;
    let secrets_storage = build_secrets_storage(config).await?;

    let mut certificate_manager = CertManager::new(
        [&config.server.domain],
        &config.server.cert.email,
        config.server.cert.organization.as_deref(),
        &config.server.cert.acme_directory_url,
    )?
    .with_cert_storage(cert_storage)
    .with_secrets_storage(secrets_storage)
    .with_challenge_handler(challenge_handler)
    .with_cert_chain_cache_ttl(Duration::from_secs(config.server.cert.chain_cache_ttl))
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
        credential_repo: SeaOrmStore::new(db_clone.clone()),
        status_list_repo: SeaOrmStore::new(db_clone),
        server_domain: config.server.domain.clone(),
        cert_manager: Arc::new(certificate_manager),
        cache: StatusListCache::new(config.cache.ttl, config.cache.max_capacity),
        aggregation_uri: empty_to_none(config.server.aggregation_uri.clone()),
        token_exp_secs: config.status_list.token_exp_secs,
        token_ttl_secs: config.status_list.token_ttl_secs,
    })
}

/// Build the certificate storage backend based on enabled features.
///
/// Priority:
/// 1. AWS S3 (if aws-s3 feature is enabled)
/// 2. Memory storage (fallback for local development)
async fn build_cert_storage(_config: &AppConfig) -> EyeResult<Box<dyn crate::cert_manager::storage::Storage>> {
    #[cfg(feature = "aws-s3")]
    {
        use crate::cert_manager::storage::AwsS3;

        let aws_config = ::aws_config::defaults(::aws_config::BehaviorVersion::latest())
            .region(::aws_config::Region::new(_config.aws.region.clone()))
            .load()
            .await;

        let cache = build_cert_chain_cache(_config).await?;

        let storage = AwsS3::new(
            &aws_config,
            &_config.aws.s3_bucket,
            &_config.aws.region,
            &_config.aws.s3_key_prefix,
        )
        .with_cache(cache);

        return Ok(Box::new(storage));
    }

    #[cfg(not(feature = "aws-s3"))]
    {
        use crate::cert_manager::storage::MemoryStorage;

        tracing::info!("Using in-memory certificate storage (aws-s3 feature not enabled)");
        Ok(Box::new(MemoryStorage::cert_storage()))
    }
}

/// Build the secrets storage backend based on enabled features.
///
/// Priority:
/// 1. AWS Secrets Manager (if aws-secrets-manager feature is enabled)
/// 2. Memory storage (fallback for local development)
async fn build_secrets_storage(_config: &AppConfig) -> EyeResult<Box<dyn crate::cert_manager::storage::Storage>> {
    #[cfg(feature = "aws-secrets-manager")]
    {
        use crate::cert_manager::storage::AwsSecretsManager;

        let aws_config = ::aws_config::defaults(::aws_config::BehaviorVersion::latest())
            .region(::aws_config::Region::new(_config.aws.region.clone()))
            .load()
            .await;

        let storage = AwsSecretsManager::new(
            &aws_config,
            Duration::from_secs(_config.aws.secrets_cache_ttl),
        )
        .await?;

        return Ok(Box::new(storage));
    }

    #[cfg(not(feature = "aws-secrets-manager"))]
    {
        use crate::cert_manager::storage::MemoryStorage;

        tracing::info!("Using in-memory secrets storage (aws-secrets-manager feature not enabled)");
        Ok(Box::new(MemoryStorage::secrets_storage()))
    }
}

/// Build the certificate chain cache backend based on enabled features.
/// 
/// Priority:
/// 1. Redis (if redis-cache feature is enabled)
/// 2. Memory cache (fallback - uses moka, which is always in-memory)
#[cfg(feature = "aws-s3")]
async fn build_cert_chain_cache(config: &AppConfig) -> EyeResult<Box<dyn crate::cert_manager::storage::Storage>> {
    #[cfg(feature = "redis-cache")]
    {
        use crate::cert_manager::storage::Redis;
        
        let redis_conn = config
            .redis
            .start(None, None, None)
            .await
            .wrap_err("Failed to connect to Redis")?;
        
        return Ok(Box::new(Redis::new(redis_conn).with_ttl(config.redis.cert_cache_ttl)));
    }
    
    #[cfg(not(feature = "redis-cache"))]
    {
        use crate::cert_manager::storage::MemoryStorage;
        
        tracing::info!("Using in-memory certificate chain cache (redis-cache feature not enabled)");
        Ok(Box::new(MemoryStorage::new("cert_chain_cache")))
    }
}

/// Build the DNS-01 challenge handler for the resolved DNS provider
async fn build_dns_challenge_handler(
    provider: DnsProviderKind,
    config: &AppConfig,
) -> EyeResult<Dns01Handler> {
    match provider {
        #[cfg(feature = "dns-route53")]
        DnsProviderKind::Route53 => {
            use crate::cert_manager::challenge::AwsRoute53DnsProvider;
            
            let aws_config = ::aws_config::defaults(::aws_config::BehaviorVersion::latest())
                .region(::aws_config::Region::new(config.aws.region.clone()))
                .load()
                .await;
            
            Ok(Dns01Handler::new(AwsRoute53DnsProvider::new(&aws_config)))
        }
        
        #[cfg(feature = "dns-cloudflare")]
        DnsProviderKind::Cloudflare => {
            use crate::cert_manager::challenge::CloudflareDnsProvider;

            let cfg = config.server.cert.dns
                .cloudflare
                .as_ref()
                .ok_or_else(|| color_eyre::eyre::eyre!("Missing Cloudflare DNS settings"))?;
            Ok(Dns01Handler::new(CloudflareDnsProvider::new(cfg.api_token.clone())))
        }

        #[cfg(feature = "dns-gcloud")]
        DnsProviderKind::Gcloud => {
            use crate::cert_manager::challenge::GoogleCloudDnsProvider;

            let cfg = config.server.cert.dns
                .gcloud
                .as_ref()
                .ok_or_else(|| color_eyre::eyre::eyre!("Missing Google Cloud DNS settings"))?;
            // Empty values count as unset, matching DnsConfig::resolve
            let inline = cfg
                .service_account_key
                .as_ref()
                .filter(|k| !k.expose_secret().trim().is_empty());
            let path = cfg
                .service_account_key_path
                .as_deref()
                .filter(|p| !p.trim().is_empty());
            let key_json = match (inline, path) {
                (Some(key), _) => key.expose_secret().to_string(),
                (None, Some(path)) => tokio::fs::read_to_string(path)
                    .await
                    .wrap_err_with(|| format!("Failed to read service account key at {path}"))?,
                (None, None) => return Err(color_eyre::eyre::eyre!("Missing Google Cloud service account key")),
            };
            Ok(Dns01Handler::new(GoogleCloudDnsProvider::new(&key_json)?))
        }

        #[cfg(feature = "dns-azure")]
        DnsProviderKind::Azure => {
            use crate::cert_manager::challenge::{AzureDnsProvider, ServicePrincipal};

            let cfg = config.server.cert.dns
                .azure
                .as_ref()
                .ok_or_else(|| color_eyre::eyre::eyre!("Missing Azure DNS settings"))?;
            Ok(Dns01Handler::new(AzureDnsProvider::new(
                ServicePrincipal {
                    tenant_id: cfg.tenant_id.clone(),
                    client_id: cfg.client_id.clone(),
                    client_secret: cfg.client_secret.clone(),
                },
                &cfg.subscription_id,
                &cfg.resource_group,
            )))
        }

        #[cfg(feature = "dns-acmedns")]
        DnsProviderKind::Acmedns => {
            use crate::cert_manager::challenge::AcmeDnsProvider;

            let cfg = config.server.cert.dns
                .acmedns
                .as_ref()
                .ok_or_else(|| color_eyre::eyre::eyre!("Missing ACME-DNS settings"))?;
            Ok(Dns01Handler::new(AcmeDnsProvider::new(
                &cfg.server_url,
                &cfg.username,
                cfg.password.clone(),
                &cfg.subdomain,
            )))
        }
        
        #[cfg(feature = "dns-pebble")]
        DnsProviderKind::Pebble => {
            use crate::cert_manager::challenge::PebbleDnsProvider;
            
            // The DNS challenge server URL is optional and only used in dev mode;
            // it falls back to the well-known Pebble challenge test server when unset.
            let dns_url = config
                .server
                .cert
                .dns_challenge_server_url
                .as_deref()
                .unwrap_or("http://challtestsrv:8055");
            Ok(Dns01Handler::new(PebbleDnsProvider::new(dns_url)))
        }
        
        // Fallback for when a DNS provider is requested but its feature is not enabled
        #[allow(unreachable_patterns)]
        _ => {
            return Err(color_eyre::eyre::eyre!(
                "DNS provider {:?} is not available. Make sure the corresponding feature is enabled (e.g., 'dns-route53', 'dns-cloudflare', etc.)",
                provider
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(
        feature = "dns-route53",
        feature = "dns-pebble",
        feature = "dns-cloudflare",
        feature = "dns-azure",
        feature = "dns-acmedns",
        feature = "dns-gcloud"
    ))]
    use crate::config::{AcmeDnsConfig, AzureDnsConfig, CloudflareDnsConfig, GcloudDnsConfig};

    #[cfg(all(
        feature = "dns-route53",
        feature = "dns-pebble",
        feature = "dns-cloudflare",
        feature = "dns-azure",
        feature = "dns-acmedns",
        feature = "dns-gcloud"
    ))]
    use sealed_test::prelude::*;

    // Sync wrapper shadowing the async builder: sealed tests fork the
    // process and run without an async runtime
    fn build_dns_challenge_handler(
        provider: DnsProviderKind,
        config: &AppConfig,
    ) -> EyeResult<Dns01Handler> {
        tokio::runtime::Runtime::new()
            .expect("failed to build test runtime")
            .block_on(super::build_dns_challenge_handler(provider, config))
    }

    #[sealed_test]
    #[cfg(all(
        feature = "dns-route53",
        feature = "dns-pebble",
        feature = "dns-cloudflare",
        feature = "dns-azure",
        feature = "dns-acmedns",
        feature = "dns-gcloud"
    ))]
    fn builds_handler_for_each_configured_provider() {
        let mut config = AppConfig::load().expect("Failed to load config");

        // Route53 and Pebble need no provider-specific settings
        assert!(build_dns_challenge_handler(DnsProviderKind::Route53, &config).is_ok());
        assert!(build_dns_challenge_handler(DnsProviderKind::Pebble, &config).is_ok());

        config.server.cert.dns.cloudflare = Some(CloudflareDnsConfig {
            api_token: "token".into(),
        });
        assert!(build_dns_challenge_handler(DnsProviderKind::Cloudflare, &config).is_ok());

        config.server.cert.dns.azure = Some(AzureDnsConfig {
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            subscription_id: "sub".into(),
            resource_group: "rg".into(),
        });
        assert!(build_dns_challenge_handler(DnsProviderKind::Azure, &config).is_ok());

        config.server.cert.dns.acmedns = Some(AcmeDnsConfig {
            server_url: "https://auth.example.org".into(),
            username: "user".into(),
            password: "password".into(),
            subdomain: "subdomain".into(),
        });
        assert!(build_dns_challenge_handler(DnsProviderKind::Acmedns, &config).is_ok());

        let key_json = serde_json::json!({
            "client_email": "acme@test-project.iam.gserviceaccount.com",
            "private_key": include_str!("../../test_data/gcloud_test_key.dummy.pem"),
            "token_uri": "https://oauth2.googleapis.com/token",
            "project_id": "test-project",
        });
        config.server.cert.dns.gcloud = Some(GcloudDnsConfig {
            service_account_key: Some(key_json.to_string().into()),
            service_account_key_path: None,
        });
        assert!(build_dns_challenge_handler(DnsProviderKind::Gcloud, &config).is_ok());
    }

    #[sealed_test]
    #[cfg(all(
        feature = "dns-cloudflare",
        feature = "dns-azure",
        feature = "dns-acmedns",
        feature = "dns-gcloud"
    ))]
    fn fails_when_provider_settings_are_missing() {
        let config = AppConfig::load().expect("Failed to load config");

        assert!(build_dns_challenge_handler(DnsProviderKind::Cloudflare, &config).is_err());
        assert!(build_dns_challenge_handler(DnsProviderKind::Gcloud, &config).is_err());
        assert!(build_dns_challenge_handler(DnsProviderKind::Azure, &config).is_err());
        assert!(build_dns_challenge_handler(DnsProviderKind::Acmedns, &config).is_err());
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
}
