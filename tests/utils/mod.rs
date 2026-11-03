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
        models::credential::{Credential, Issuer, PublicJwk},
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
            "management": {"host": "127.0.0.1", "port": 0},
            "admin": {"host": "127.0.0.1", "port": 0},
            "links": {"documentation": "https://github.com/adorsys/status-list-server"},
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
        "management_auth": {"leeway_secs": 60, "max_token_lifetime_secs": 300, "audiences": [], "issuers_file": "issuers.yaml"},
        "admin_auth": {"leeway_secs": 60, "max_token_lifetime_secs": 300, "audiences": ["status-list-server-admin"]},
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

fn fixture_state(config: &Config, registry_override: Option<&str>) -> AppState {
    use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
    let snapshots = MemoryStatusListSnapshotRepo::default();
    let lists = MemoryStatusLists::default().with_snapshot(&snapshots);
    let material = SigningMaterial::new(
        Some(vec![
            BASE64_STANDARD.encode(pem::parse(certificate()).unwrap().contents()),
        ]),
        Arc::new(SigningKey::from_pem(KEY).unwrap()),
    )
    .unwrap();
    let signing_key = SigningKey::from_pem(KEY).unwrap();
    let public = signing_key.public_key_bytes();
    let default_registry = format!(
        "version: 1\nissuers:\n  - id: {ISSUER}\n    aggregation_id: {AGGREGATION_ID}\n    keys:\n      - kid: {KEY_ID}\n        alg: ES256\n        jwk:\n          kty: EC\n          crv: P-256\n          kid: {KEY_ID}\n          alg: ES256\n          x: {}\n          y: {}\nadmins: []\n",
        BASE64_URL_SAFE_NO_PAD.encode(&public[1..33]),
        BASE64_URL_SAFE_NO_PAD.encode(&public[33..65]),
    );
    let registry_yaml = registry_override.unwrap_or(&default_registry);
    let registry = Arc::new(
        status_list_server::server::auth::issuer_registry::RegistryHandle::from_yaml(registry_yaml)
            .unwrap(),
    );
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
        aggregation_uri: config
            .server
            .aggregation_uri(config.telemetry.environment)
            .unwrap(),
        aggregation_withheld_from: Default::default(),
        token_exp_secs: config.status_list.token_exp_secs,
        token_ttl_secs: config.status_list.token_ttl_secs,
        max_status_index: config.limits.max_status_index,
        max_statuses_per_request: config.limits.max_statuses_per_request,
        max_serialized_list_size: config.limits.max_serialized_list_size,
        max_lists_per_issuer: config.limits.max_lists_per_issuer,
        snapshot_retention_secs: config.status_list.snapshot_retention_secs,
        management_auth: (&config.management_auth).into(),
        admin_auth: (&config.admin_auth).into(),
        admin_registry: registry.clone(),
        hosted_issuer_store: None,
        issuer_registry: registry.clone(),
        issuer_key_resolver: registry,
        links: status_list_server::server::ServiceLinks {
            documentation: status_list_server::config::REPOSITORY_URL.to_string(),
            portal: None,
        },
        token_bytes_cache: TokenBytesCache::new(config.token_bytes_cache.max_capacity),
        readiness: Readiness::default(),
    }
}
const ISSUER: &str = "conformance-issuer";
const KEY_ID: &str = "conformance-key";
const AGGREGATION_ID: &str = "00000000-0000-4000-8000-000000000001";

pub(super) struct TestServer {
    pub(super) base_url: String,
    pub(super) management_url: String,
    pub(super) client: reqwest::Client,
    pub(super) aggregation_id: String,
    token_kid: String,
}

impl TestServer {
    pub(super) async fn start(aggregation_uri: Option<String>) -> Self {
        Self::start_with_registry(aggregation_uri, None).await
    }

    pub(super) async fn start_with_registry(
        aggregation_uri: Option<String>,
        registry_override: Option<String>,
    ) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut config = fixture_config();
        config.server.aggregation_uri = aggregation_uri;
        // HttpServer::new owns binding. Retry if another parallel test/process
        // acquires the OS-selected port between releasing it and server startup.
        let (base_url, management_url, server) = {
            let mut started = None;
            for attempt in 0..10 {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                config.server.port = listener.local_addr().unwrap().port();
                let base_url = format!("http://127.0.0.1:{}", config.server.port);
                // Connect directly to HTTP rather than a production TLS terminator.
                config.server.public_base_url = Some(format!("{base_url}/api/v1"));
                drop(listener);
                let state = fixture_state(&config, registry_override.as_deref());
                let key = SigningKey::from_pem(KEY).unwrap();
                let public = key.public_key_bytes();
                let public_jwk = json!({
                    "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": KEY_ID,
                    "x": BASE64_URL_SAFE_NO_PAD.encode(&public[1..33]),
                    "y": BASE64_URL_SAFE_NO_PAD.encode(&public[33..65]),
                });
                state
                    .service
                    .publish_credential_with_aggregation_id(
                        Credential {
                            issuer: Issuer(ISSUER.to_owned()),
                            public_key: PublicJwk::try_new(
                                serde_json::to_vec(&public_jwk).unwrap(),
                            )
                            .unwrap(),
                        },
                        status_list_server::domain::models::credential::AggregationId(
                            AGGREGATION_ID.parse().unwrap(),
                        ),
                    )
                    .await
                    .unwrap();
                match HttpServer::new(&config, state, prometheus::Registry::new()).await {
                    Ok(server) => {
                        let management_url = format!("http://{}", server.management_addr());
                        started = Some((base_url, management_url, server));
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
        // Hold the sender alive for the server task's lifetime so the graceful
        // shutdown future never resolves mid-test; teardown happens on runtime drop.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let _shutdown_tx = shutdown_tx;
            server.run(shutdown_rx).await
        });
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
        Self {
            base_url,
            management_url,
            client,
            aggregation_id: AGGREGATION_ID.to_owned(),
            token_kid: registry_override
                .as_deref()
                .and_then(|yaml| serde_saphyr::from_str::<serde_json::Value>(yaml).ok())
                .and_then(|value| {
                    value["issuers"][0]["keys"][0]["kid"]
                        .as_str()
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| KEY_ID.to_owned()),
        }
    }

    pub(super) fn bearer_token(&self) -> String {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(self.token_kid.clone());
        header.typ = Some("statuslist-management+jwt".to_owned());
        jsonwebtoken::encode(
            &header,
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
