use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use status_list_server::{
    config::Config,
    crypto::SigningKey,
    domain::{
        models::status_list::StatusListError,
        ports::{CertificateProvider, SigningMaterial},
        service::Service,
    },
    outbound::{
        cache::DisabledStatusListCache,
        memory::{MemoryCredentials, MemoryStatusLists},
    },
    server::{AppState, ManagementAuthConfig, cache::TokenBytesCache, health::Readiness},
    startup::HttpServer,
};

const KEY: &str = include_str!("../../test_data/ec-private.pem");

pub(super) fn test_certificate() -> &'static str {
    static CERT: OnceLock<String> = OnceLock::new();
    CERT.get_or_init(|| {
        let key = rcgen::KeyPair::from_pem(KEY).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        BASE64_STANDARD.encode(cert.der())
    })
}

struct FixtureCertificate;

#[async_trait]
impl CertificateProvider for FixtureCertificate {
    async fn signing_material(&self) -> Result<Arc<SigningMaterial>, StatusListError> {
        Ok(Arc::new(SigningMaterial::new(
            Some(vec![test_certificate().to_owned()]),
            Arc::new(SigningKey::from_pem(KEY).unwrap()),
        )?))
    }
}

pub(super) struct TestServer {
    pub(super) state: AppState,
    pub(super) base_url: String,
    pub(super) client: reqwest::Client,
    task: tokio::task::JoinHandle<color_eyre::Result<()>>,
}

impl TestServer {
    pub(super) async fn start(aggregation_uri: Option<String>) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut config = Config::load_from_overrides(&[]).unwrap();
        config.server.host = "127.0.0.1".into();
        config.server.port = 0;
        config.server.aggregation_uri = aggregation_uri.clone();
        let state = AppState {
            service: Arc::new(Service::from_arcs(
                Arc::new(MemoryStatusLists::default()),
                Arc::new(MemoryCredentials::default()),
                Arc::new(DisabledStatusListCache),
                None,
                Arc::new(FixtureCertificate),
            )),
            public_base_url: "http://127.0.0.1/api/v1".into(),
            aggregation_uri,
            token_exp_secs: 900,
            token_ttl_secs: 300,
            max_status_index: 100_000,
            max_statuses_per_request: 5_000,
            max_serialized_list_size: 1_048_576,
            max_lists_per_issuer: 1_000,
            snapshot_retention_secs: 0,
            management_auth: ManagementAuthConfig::default(),
            token_bytes_cache: TokenBytesCache::new(1_048_576),
            readiness: Readiness::default(),
        };
        let server = HttpServer::new(&config, state.clone(), prometheus::Registry::new())
            .await
            .unwrap();
        let base_url = format!("http://{}", server.local_addr().unwrap());
        let task = tokio::spawn(server.run());
        // The listener is already bound; requests can queue until the server task polls.
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
            state,
            base_url,
            client,
            task,
        }
    }

    pub(super) fn url(&self, uri: &str) -> String {
        if uri.starts_with('/') {
            format!("{}{uri}", self.base_url)
        } else {
            uri.to_owned()
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
