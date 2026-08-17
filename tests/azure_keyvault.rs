#![cfg(feature = "azure-kv")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::error::{ErrorKind, ResultExt as _};
use azure_core::http::headers::{HeaderName, HeaderValue, Headers};
use azure_core::http::{AsyncRawResponse, Method};
use status_list_server::{cert_manager::storage::Storage, outbound::azure_kv::AzureKeyVaultClient};
use testcontainers_modules::testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
};

const EMULATOR_IMAGE: &str = "jamesgoulddev/azure-keyvault-emulator";
const EMULATOR_TAG: &str = "3.1.3";
const DUMMY_JWT_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

#[derive(Debug)]
struct DummyTokenCredential;

#[async_trait::async_trait]
impl TokenCredential for DummyTokenCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        Ok(AccessToken::new(
            DUMMY_JWT_TOKEN.to_string(),
            time::OffsetDateTime::now_utc() + time::Duration::hours(24),
        ))
    }
}

// Custom HTTP transport that accepts self-signed certificates.
#[derive(Debug)]
struct InsecureHttpClient {
    inner: reqwest::Client,
}

impl InsecureHttpClient {
    fn new() -> Self {
        let client = reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build insecure reqwest client");
        Self { inner: client }
    }
}

fn from_method(method: Method) -> reqwest::Method {
    match method {
        Method::Delete => reqwest::Method::DELETE,
        Method::Get => reqwest::Method::GET,
        Method::Head => reqwest::Method::HEAD,
        Method::Patch => reqwest::Method::PATCH,
        Method::Post => reqwest::Method::POST,
        Method::Put => reqwest::Method::PUT,
        _ => unreachable!("unsupported HTTP method"),
    }
}

fn to_headers(map: &reqwest::header::HeaderMap) -> Headers {
    let mut headers_map: HashMap<HeaderName, HeaderValue> = HashMap::new();
    for (name, value) in map.iter() {
        if let Ok(val_str) = value.to_str() {
            let header_name = HeaderName::from(name.as_str().to_owned());
            if header_name
                .as_str()
                .eq_ignore_ascii_case("www-authenticate")
            {
                if let Some(existing) = headers_map.get(&header_name) {
                    if !existing.as_str().contains("scope=") && val_str.contains("scope=") {
                        headers_map.insert(header_name, HeaderValue::from(val_str.to_owned()));
                    }
                } else {
                    headers_map.insert(header_name, HeaderValue::from(val_str.to_owned()));
                }
            } else {
                headers_map.insert(header_name, HeaderValue::from(val_str.to_owned()));
            }
        }
    }
    Headers::from(headers_map)
}

#[async_trait::async_trait]
impl azure_core::http::HttpClient for InsecureHttpClient {
    async fn execute_request(
        &self,
        request: &azure_core::http::Request,
    ) -> azure_core::Result<AsyncRawResponse> {
        let url = request.url().clone();

        let mut req = self.inner.request(from_method(request.method()), url);

        for (name, value) in request.headers().iter() {
            req = req.header(name.as_str(), value.as_str());
        }

        let body = request.body().clone();
        let req = match body {
            azure_core::http::request::Body::Bytes(bytes) => req.body(bytes).build(),
            azure_core::http::request::Body::SeekableStream(stream) => {
                req.body(reqwest::Body::wrap_stream(stream)).build()
            }
        }
        .with_context(ErrorKind::Other, "failed to build reqwest request")?;

        let rsp = self.inner.execute(req).await.map_err(|err| {
            let kind = if err.is_connect() {
                ErrorKind::Connection
            } else {
                ErrorKind::Io
            };
            azure_core::Error::with_error(kind, err, "failed to execute reqwest request")
        })?;

        let status = rsp.status();
        let headers = to_headers(rsp.headers());
        let body_bytes = rsp.bytes().await.map_err(|e| {
            azure_core::Error::with_error(ErrorKind::Io, e, "failed to read response body")
        })?;

        Ok(AsyncRawResponse::from_bytes(
            status.as_u16().into(),
            headers,
            body_bytes,
        ))
    }
}

async fn start_emulator(
    cache_ttl: Duration,
) -> (
    testcontainers_modules::testcontainers::ContainerAsync<GenericImage>,
    AzureKeyVaultClient,
) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let certs_dir = std::path::Path::new(manifest_dir).join("test_data/certs");
    let certs_path = certs_dir.to_str().unwrap().to_string();

    let container = GenericImage::new(EMULATOR_IMAGE, EMULATOR_TAG)
        .with_exposed_port(4997.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Now listening on:"))
        .with_mount(Mount::bind_mount(&certs_path, "/certs"))
        .start()
        .await
        .expect("Failed to start Azure Key Vault emulator container");

    let port = container
        .get_host_port_ipv4(4997)
        .await
        .expect("Failed to resolve host port");

    // the emulator serves HTTPS with our self-signed cert.
    let url = url::Url::parse(&format!("https://127.0.0.1:{port}")).expect("Failed to parse URL");
    let http_client: Arc<dyn azure_core::http::HttpClient> = Arc::new(InsecureHttpClient::new());

    let client = AzureKeyVaultClient::builder(url)
        .credential(Arc::new(DummyTokenCredential))
        .http_client(http_client)
        .verify_challenge_resource(false)
        .secrets_cache_ttl(cache_ttl)
        .build()
        .expect("Failed to build AzureKeyVaultClient");

    (container, client)
}

#[tokio::test]
async fn test_azure_keyvault_storage_lifecycle() {
    let (_container, client) = start_emulator(Duration::ZERO).await;

    let secret_key = "test-cert-key";
    let secret_value =
        "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEF\n-----END PRIVATE KEY-----";

    // Secret should not exist initially
    let initial_load = client
        .load(secret_key)
        .await
        .expect("Failed to check secret existence");
    assert!(initial_load.is_none(), "Secret should not exist initially");

    // Store secret
    client
        .store(secret_key, secret_value)
        .await
        .expect("Failed to store secret");

    // Load secret and verify payload
    let loaded = client
        .load(secret_key)
        .await
        .expect("Failed to load secret");
    assert_eq!(loaded.as_deref(), Some(secret_value));

    // Overwrite secret with new version (brief sleep ensures distinct version timestamp)
    tokio::time::sleep(Duration::from_millis(500)).await;
    let updated_value =
        "-----BEGIN PRIVATE KEY-----\nUPDATED_KEY_MATERIAL\n-----END PRIVATE KEY-----";
    client
        .store(secret_key, updated_value)
        .await
        .expect("Failed to overwrite secret");

    let loaded_updated = client
        .load(secret_key)
        .await
        .expect("Failed to load updated secret");
    assert_eq!(
        loaded_updated.as_deref(),
        Some(updated_value),
        "Loaded secret payload should match updated value"
    );

    // Delete secret
    client
        .delete(secret_key)
        .await
        .expect("Failed to delete secret");

    let load_after_delete = client
        .load(secret_key)
        .await
        .expect("Failed to load after delete");
    assert!(load_after_delete.is_none());
}

#[tokio::test]
async fn test_azure_keyvault_cache_behavior() {
    let (_container, client) = start_emulator(Duration::from_secs(60)).await;

    let secret_key = "cached-secret-key";
    let secret_value = "secret-content-v1";

    client
        .store(secret_key, secret_value)
        .await
        .expect("Failed to store secret");

    let first_load = client.load(secret_key).await.expect("Failed first load");
    assert_eq!(first_load.as_deref(), Some(secret_value));

    // Second fetch should be served from cache
    let second_load = client.load(secret_key).await.expect("Failed second load");
    assert_eq!(second_load.as_deref(), Some(secret_value));
}
