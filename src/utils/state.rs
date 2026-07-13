use crate::{
    cert_manager::{
        CertManager,
        challenge::{
            AcmeDnsProvider, AwsRoute53DnsUpdater, AzureDnsProvider, CloudflareDnsProvider,
            Dns01Handler, GoogleCloudDnsProvider, ServicePrincipal,
        },
        storage::{AwsS3, AwsSecretsManager, Redis},
    },
    config::{Config as AppConfig, DnsProviderKind},
    database::{Migrator, queries::SeaOrmStore},
    models::{Credentials, StatusListRecord},
};
use aws_config::{BehaviorVersion, Region, SdkConfig};
use color_eyre::eyre::{Context, Result as EyeResult, eyre};
use sea_orm::Database;
use sea_orm_migration::MigratorTrait;
use secrecy::ExposeSecret;
use std::{sync::Arc, time::Duration};

use super::{
    cache::Cache,
    cert_manager::{challenge::PebbleDnsUpdater, http_client::DefaultHttpClient},
};

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
    let challenge_handler = build_dns_challenge_handler(dns_provider, config, &aws_config)?;

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

/// Build the DNS-01 challenge handler for the resolved DNS provider
fn build_dns_challenge_handler(
    provider: DnsProviderKind,
    config: &AppConfig,
    aws_config: &SdkConfig,
) -> EyeResult<Dns01Handler> {
    let dns = &config.server.cert.dns;
    let handler = match provider {
        DnsProviderKind::Route53 => Dns01Handler::new(AwsRoute53DnsUpdater::new(aws_config)),
        DnsProviderKind::Cloudflare => {
            let cfg = dns
                .cloudflare
                .as_ref()
                .ok_or_else(|| eyre!("Missing Cloudflare DNS settings"))?;
            Dns01Handler::new(CloudflareDnsProvider::new(cfg.api_token.clone()))
        }
        DnsProviderKind::Gcloud => {
            let cfg = dns
                .gcloud
                .as_ref()
                .ok_or_else(|| eyre!("Missing Google Cloud DNS settings"))?;
            let key_json = match (&cfg.service_account_key, &cfg.service_account_key_path) {
                (Some(key), _) => key.expose_secret().to_string(),
                (None, Some(path)) => std::fs::read_to_string(path)
                    .wrap_err_with(|| format!("Failed to read service account key at {path}"))?,
                (None, None) => return Err(eyre!("Missing Google Cloud service account key")),
            };
            Dns01Handler::new(GoogleCloudDnsProvider::new(&key_json)?)
        }
        DnsProviderKind::Azure => {
            let cfg = dns
                .azure
                .as_ref()
                .ok_or_else(|| eyre!("Missing Azure DNS settings"))?;
            Dns01Handler::new(AzureDnsProvider::new(
                ServicePrincipal {
                    tenant_id: cfg.tenant_id.clone(),
                    client_id: cfg.client_id.clone(),
                    client_secret: cfg.client_secret.clone(),
                },
                &cfg.subscription_id,
                &cfg.resource_group,
            ))
        }
        DnsProviderKind::Acmedns => {
            let cfg = dns
                .acmedns
                .as_ref()
                .ok_or_else(|| eyre!("Missing ACME-DNS settings"))?;
            Dns01Handler::new(AcmeDnsProvider::new(
                &cfg.server_url,
                &cfg.username,
                cfg.password.clone(),
                &cfg.subdomain,
            ))
        }
        DnsProviderKind::Pebble => {
            // The DNS challenge server URL is optional and only used in dev mode;
            // it falls back to the well-known Pebble challenge test server when unset.
            let dns_url = config
                .server
                .cert
                .dns_challenge_server_url
                .as_deref()
                .unwrap_or("http://challtestsrv:8055");
            Dns01Handler::new(PebbleDnsUpdater::new(dns_url))
        }
    };
    Ok(handler)
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
