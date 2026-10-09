use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use serde_json::json;
use status_list_server::{
    config::Config,
    crypto::SigningKey,
    domain::{
        models::status_list::StatusListError,
        ports::{CertificateProvider, SigningMaterial},
        service::Service,
    },
    outbound::{
        cache::MokaStatusListCache,
        memory::{MemoryCredentials, MemoryStatusListSnapshotRepo, MemoryStatusLists},
    },
    server::{AppState, cache::TokenBytesCache, health::Readiness},
    startup::HttpServer,
};
use tokio::net::TcpListener;

pub(super) const KEY: &str = include_str!("../../test_data/ec-private.pem");
// Generate once per test process from the existing fixture key. Both the server
// and the independent signature assertions use this exact certificate.
pub(super) fn certificate() -> &'static str {
    static CERT: OnceLock<String> = OnceLock::new();
    CERT.get_or_init(|| {
        let key = rcgen::KeyPair::from_pem(KEY).unwrap();
        rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem()
    })
}

struct FixtureCertificate(Arc<SigningMaterial>);

#[async_trait::async_trait]
impl CertificateProvider for FixtureCertificate {
    async fn signing_material(&self) -> Result<Arc<SigningMaterial>, StatusListError> {
        Ok(self.0.clone())
    }
}

// Deserialize an explicit fixture through Config's existing public surface.
// No ambient APP_* values are read and no process-wide environment is mutated.
fn fixture_config() -> Config {
    serde_json::from_value(json!({
        "server": {"host": "127.0.0.1", "port": 0, "domain": "localhost",
            "enable_metrics": false, "cert": {"email": "test@example.com",
                "acme_directory_url": "https://acme.invalid/directory",
                "signing_key_cache_ttl": 0, "renewal_cron_schedule": "0 0 0 * * *", "store": {}}},
        "database": {"backend": "memory", "pool": {"max_connections": 1,
            "min_connections": 0, "acquire_timeout_secs": 5, "connect_timeout_secs": 5,
            "idle_timeout_secs": 60, "max_lifetime_secs": 60}},
        "aws": {"region": "us-east-1"},
        "vault": {"addr": "http://localhost:8200", "role_id": "", "auth_mount": "approle",
            "k8s_token_path": "", "k8s_auth_mount": "kubernetes", "mount": "secret",
            "path_prefix": "", "timeout_secs": 5},
        "gcp_secret_manager": {"project_id": "", "secrets_cache_ttl": 0},
        "azure_keyvault": {"secrets_cache_ttl": 0},
        "cache": {"backend": "memory", "ttl": 300, "max_capacity": 100},
        "token_bytes_cache": {"max_capacity": 1048576},
        "status_list": {"token_exp_secs": 900, "token_ttl_secs": 300, "snapshot_retention_secs": 3600},
        "management_auth": {"leeway_secs": 60, "max_token_lifetime_secs": 3600, "audiences": []},
        "rate_limit": {"strict_burst_size": 100, "strict_period_secs": 60,
            "permissive_burst_size": 100, "permissive_period_secs": 60},
        "limits": {"max_body_size_bytes": 2097152, "max_status_index": 100000,
            "max_statuses_per_request": 5000, "max_serialized_list_size": 1048576,
            "max_lists_per_issuer": 1000, "list_quota_transition": false},
        "telemetry": {"environment": "development", "enabled": false,
            "otlp_endpoint": "http://localhost:4317", "sampler_ratio": 1.0},
        "watcher": {"poll_interval_secs": 30}
    })).unwrap()
}

fn fixture_state(config: &Config) -> AppState {
    use base64::prelude::BASE64_STANDARD;
    let snapshots = MemoryStatusListSnapshotRepo::default();
    let lists = MemoryStatusLists::default().with_snapshot(&snapshots);
    let material = SigningMaterial::new(
        Some(vec![
            BASE64_STANDARD.encode(pem::parse(certificate()).unwrap().contents()),
        ]),
        Arc::new(SigningKey::from_pem(KEY).unwrap()),
    )
    .unwrap();
    AppState {
        service: Arc::new(Service::from_arcs(
            Arc::new(lists),
            Arc::new(MemoryCredentials::default()),
            Arc::new(MokaStatusListCache::new(
                std::num::NonZeroU64::new(config.cache.ttl).unwrap(),
                config.cache.max_capacity,
            )),
            Some(Arc::new(snapshots)),
            Arc::new(FixtureCertificate(Arc::new(material))),
        )),
        public_base_url: config.server.resolved_public_base_url(),
        aggregation_uri: config.server.aggregation_uri.clone(),
        token_exp_secs: config.status_list.token_exp_secs,
        token_ttl_secs: config.status_list.token_ttl_secs,
        max_status_index: config.limits.max_status_index,
        max_statuses_per_request: config.limits.max_statuses_per_request,
        max_serialized_list_size: config.limits.max_serialized_list_size,
        max_lists_per_issuer: config.limits.max_lists_per_issuer,
        snapshot_retention_secs: config.status_list.snapshot_retention_secs,
        management_auth: (&config.management_auth).into(),
        token_bytes_cache: TokenBytesCache::new(config.token_bytes_cache.max_capacity),
        readiness: Readiness::default(),
    }
}
const ISSUER: &str = "conformance-issuer";

pub(super) struct TestServer {
    pub(super) base_url: String,
    pub(super) client: reqwest::Client,
}

impl TestServer {
    pub(super) async fn start(aggregation_uri: Option<String>) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut config = fixture_config();
        config.server.aggregation_uri = aggregation_uri.filter(|value| !value.trim().is_empty());
        // HttpServer::new owns binding. Retry if another parallel test/process
        // acquires the OS-selected port between releasing it and server startup.
        let (base_url, server) = {
            let mut started = None;
            for attempt in 0..10 {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                config.server.port = listener.local_addr().unwrap().port();
                let base_url = format!("http://127.0.0.1:{}", config.server.port);
                // Connect directly to HTTP rather than a production TLS terminator.
                config.server.public_base_url = Some(format!("{base_url}/api/v1"));
                drop(listener);
                match HttpServer::new(&config, fixture_state(&config), prometheus::Registry::new())
                    .await
                {
                    Ok(server) => {
                        started = Some((base_url, server));
                        break;
                    }
                    Err(error)
                        if attempt < 9
                            && error.chain().any(|cause| {
                                cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                                    error.kind() == std::io::ErrorKind::AddrInUse
                                })
                            }) =>
                    {
                        continue;
                    }
                    Err(error) => panic!("failed to start conformance server: {error:?}"),
                }
            }
            started.expect("server bound within retry limit")
        };
        // Each #[tokio::test] owns its runtime; shutdown drops its server tasks.
        tokio::spawn(server.run());
        let client = reqwest::Client::builder()
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let app = Self { base_url, client };
        let key = SigningKey::from_pem(KEY).unwrap();
        let public = key.public_key_bytes();
        let response = app
            .client
            .post(app.url("/api/v1/credentials"))
            .json(&json!({"issuer": ISSUER, "public_key": {
                "kty": "EC", "crv": "P-256", "alg": "ES256",
                "x": BASE64_URL_SAFE_NO_PAD.encode(&public[1..33]),
                "y": BASE64_URL_SAFE_NO_PAD.encode(&public[33..65]),
            }}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::ACCEPTED,
            "{}",
            response.text().await.unwrap()
        );
        app
    }

    pub(super) fn bearer_token(&self) -> String {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
            &json!({"iss": ISSUER, "iat": now, "exp": now + 300}),
            &jsonwebtoken::EncodingKey::from_ec_pem(KEY.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    pub(super) fn url(&self, uri: &str) -> String {
        if uri.starts_with('/') {
            format!("{}{uri}", self.base_url)
        } else {
            uri.to_owned()
        }
    }
}
