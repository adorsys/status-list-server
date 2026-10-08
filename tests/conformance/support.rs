use std::time::Duration;

use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use serde_json::json;
use status_list_server::{
    config::Config, crypto::SigningKey, setup::build_state, startup::HttpServer,
};
use tokio::net::TcpListener;

pub(super) const KEY: &str = include_str!("../../test_data/ec-private.pem");
pub(super) const CERT: &str = include_str!("../../test_data/ec-cert.pem");
const ISSUER: &str = "conformance-issuer";

pub(super) struct TestServer {
    pub(super) base_url: String,
    pub(super) client: reqwest::Client,
    task: tokio::task::JoinHandle<color_eyre::Result<()>>,
}

impl TestServer {
    pub(super) async fn start(aggregation_uri: Option<String>) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        // Resolve the fixture's public hostname to our bound socket in the client.
        // This also respects build_state's APP_ENV=production loopback-host guard.
        let base_url = format!("http://example.com:{}", address.port());
        let mut config = Config::load_without_environment(&[
            ("database.backend", "memory"),
            ("cache.backend", "memory"),
            ("cache.ttl", "300"),
            ("cache.max_capacity", "100"),
            ("token_bytes_cache.max_capacity", "1048576"),
            ("server.host", "127.0.0.1"),
            ("server.port", "0"),
            ("server.domain", "example.com"),
            ("server.enable_metrics", "false"),
            (
                "server.aggregation_uri",
                aggregation_uri.as_deref().unwrap_or(""),
            ),
            ("server.cert.store.certificate", CERT),
            ("server.cert.store.signing_key", KEY),
            ("status_list.token_exp_secs", "900"),
            ("status_list.token_ttl_secs", "300"),
            ("status_list.snapshot_retention_secs", "3600"),
            ("telemetry.environment", "development"),
            ("rate_limit.strict_burst_size", "100"),
            ("rate_limit.permissive_burst_size", "100"),
        ])
        .unwrap();
        // Production public URLs require HTTPS at the external TLS terminator.
        // This loopback-only test connects directly to HttpServer's HTTP listener.
        config.server.public_base_url = Some(format!("{base_url}/api/v1"));
        let state = build_state(&config).await.unwrap();
        let server =
            HttpServer::from_listener(&config, state, prometheus::Registry::new(), listener)
                .unwrap();
        let task = tokio::spawn(server.run());
        let client = reqwest::Client::builder()
            .resolve("example.com", address)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let app = Self {
            base_url,
            client,
            task,
        };
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

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
