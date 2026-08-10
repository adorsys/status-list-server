//! This module provides a [`Storage`] implementation that stores certificate
//! material in Google Cloud Storage buckets. Authentication uses Google Cloud
//! service account credentials via OAuth2 JWT bearer tokens.
//!
//! # Object Key Convention
//!
//! Object keys are the certificate manager's logical keys, optionally qualified
//! with a `key_prefix`. For example, key `certs-example.com-cert_data.json` and
//! prefix `status-list/certs` are stored as
//! `status-list/certs/certs-example.com-cert_data.json`.
//!
//! # Authentication
//!
//! Authentication requires a Google Cloud service account key JSON, which can be
//! provided either:
//! - Inline via configuration (`service_account_key`)
//! - Via a file path (`service_account_key_path`)
//!
//! The service account must have the `storage.objects` permissions for the
//! target bucket:
//! - `storage.objects.get`
//! - `storage.objects.create`
//! - `storage.objects.delete`

use std::time::Duration;

use async_trait::async_trait;
use color_eyre::eyre::eyre;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::cert_manager::storage::{Storage, StorageError};

const DEFAULT_API_BASE: &str = "https://storage.googleapis.com";
const OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_write";
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(3600);

/// Cache for short-lived OAuth2 access tokens specific to GCS.
///
/// Similar to the TokenCache used by DNS providers, but works with StorageError.
struct TokenCache {
    inner: tokio::sync::Mutex<Option<CachedToken>>,
}

struct CachedToken {
    token: SecretString,
    expires_at: std::time::Instant,
}

impl TokenCache {
    // Refresh tokens slightly before they expire
    const EXPIRY_SKEW: Duration = Duration::from_secs(60);

    fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(None),
        }
    }

    /// Return the cached token, or mint a new one when absent or expired
    async fn get_or_mint<F, Fut>(&self, mint: F) -> Result<SecretString, StorageError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(SecretString, Duration), StorageError>>,
    {
        let mut guard = self.inner.lock().await;
        if let Some(cached) = guard.as_ref() {
            if std::time::Instant::now() < cached.expires_at {
                return Ok(cached.token.clone());
            }
        }

        let (token, ttl) = mint().await?;
        *guard = Some(CachedToken {
            token: token.clone(),
            expires_at: std::time::Instant::now() + ttl.saturating_sub(Self::EXPIRY_SKEW),
        });
        Ok(token)
    }
}

/// Google Cloud Storage implementation of the [`Storage`] trait.
///
/// Stores certificate material as objects in a GCS bucket with optional
/// key prefix for organizational purposes.
pub struct GoogleCloudStorage {
    client: Client,
    bucket: String,
    key_prefix: String,
    client_email: String,
    token_uri: String,
    encoding_key: EncodingKey,
    api_base: String,
    token_cache: TokenCache,
}

/// Relevant fields of a Google service account key JSON.
#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: String,
}

#[derive(Serialize)]
struct TokenClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl GoogleCloudStorage {
    /// Create a new GCS storage instance.
    ///
    /// # Arguments
    ///
    /// * `service_account_key_json` - The service account key JSON content
    /// * `bucket` - The GCS bucket name
    /// * `key_prefix` - Optional prefix for all object keys (can be empty)
    ///
    /// # Errors
    ///
    /// Returns an error if the service account key JSON is invalid or the
    /// private key cannot be parsed.
    pub fn new(
        service_account_key_json: &str,
        bucket: impl Into<String>,
        key_prefix: impl Into<String>,
    ) -> Result<Self, StorageError> {
        let key: ServiceAccountKey = serde_json::from_str(service_account_key_json)
            .map_err(|e| StorageError::Gcs(eyre!("Invalid service account key JSON: {e}")))?;
        let encoding_key = EncodingKey::from_rsa_pem(key.private_key.as_bytes())
            .map_err(|e| StorageError::Gcs(eyre!("Invalid service account private key: {e}")))?;

        Ok(Self {
            client: Client::new(),
            bucket: bucket.into(),
            key_prefix: key_prefix.into(),
            client_email: key.client_email,
            token_uri: key.token_uri,
            encoding_key,
            api_base: DEFAULT_API_BASE.to_string(),
            token_cache: TokenCache::new(),
        })
    }

    /// Override the API base URL (used in tests).
    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.api_base = api_base.into().trim_end_matches('/').to_string();
        self
    }

    /// Get the full object name including prefix.
    fn qualify_key(&self, key: &str) -> String {
        let prefix = self.key_prefix.trim_matches('/');
        let key = key.trim_start_matches('/');
        if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", prefix, key)
        }
    }

    /// Get the storage API URL for an object.
    fn object_url(&self, object_name: &str) -> String {
        format!(
            "{}/storage/v1/b/{}/o/{}",
            self.api_base,
            self.bucket,
            urlencoding::encode(object_name)
        )
    }

    /// Get the download URL for an object (media link).
    fn media_url(&self, object_name: &str) -> String {
        format!(
            "{}/storage/v1/b/{}/o/{}/media",
            self.api_base,
            self.bucket,
            urlencoding::encode(object_name)
        )
    }

    /// Get the upload URL for an object (simple upload).
    fn upload_url(&self, object_name: &str) -> String {
        format!(
            "{}/upload/storage/v1/b/{}/o?name={}",
            self.api_base,
            self.bucket,
            urlencoding::encode(object_name)
        )
    }

    /// Obtain an access token for GCS API requests.
    async fn access_token(&self) -> Result<SecretString, StorageError> {
        self.token_cache
            .get_or_mint(|| async {
                let iat = time::OffsetDateTime::now_utc().unix_timestamp();
                let claims = TokenClaims {
                    iss: &self.client_email,
                    scope: OAUTH_SCOPE,
                    aud: &self.token_uri,
                    iat,
                    exp: iat + DEFAULT_TOKEN_LIFETIME.as_secs() as i64,
                };
                let assertion = jsonwebtoken::encode(
                    &Header::new(Algorithm::RS256),
                    &claims,
                    &self.encoding_key,
                )
                .map_err(|e| StorageError::Gcs(eyre!("Failed to sign token request: {e}")))?;

                let response = self
                    .client
                    .post(&self.token_uri)
                    .form(&[
                        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                        ("assertion", &assertion),
                    ])
                    .send()
                    .await
                    .map_err(|e| StorageError::Gcs(e.into()))?;

                let status = response.status();
                if !status.is_success() {
                    let body = response.text().await.unwrap_or_default();
                    return Err(StorageError::Gcs(eyre!(
                        "Token exchange failed (status {status}): {body}"
                    )));
                }

                let token: TokenResponse = response
                    .json()
                    .await
                    .map_err(|e| StorageError::Gcs(eyre!("Invalid token response: {e}")))?;

                Ok((
                    token.access_token.into(),
                    Duration::from_secs(token.expires_in),
                ))
            })
            .await
    }
}

#[async_trait]
impl Storage for GoogleCloudStorage {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let token = self.access_token().await?;
        let object_name = self.qualify_key(key);
        let url = self.upload_url(&object_name);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .bearer_auth(token.expose_secret())
            .body(value.to_string())
            .send()
            .await
            .map_err(|e| StorageError::Gcs(e.into()))?;

        let status = response.status();
        if status.is_success() {
            info!("Stored object {} in bucket {}", object_name, self.bucket);
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(StorageError::Gcs(eyre!(
                "Failed to store object (status {}): {}",
                status,
                body
            )))
        }
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        let token = self.access_token().await?;
        let object_name = self.qualify_key(key);
        let url = self.media_url(&object_name);

        let response = self
            .client
            .get(&url)
            .bearer_auth(token.expose_secret())
            .send()
            .await
            .map_err(|e| StorageError::Gcs(e.into()))?;

        match response.status() {
            StatusCode::OK => {
                let data = response
                    .text()
                    .await
                    .map_err(|e| StorageError::Gcs(e.into()))?;
                Ok(Some(data))
            }
            StatusCode::NOT_FOUND => Ok(None),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(StorageError::Gcs(eyre!(
                    "Failed to load object (status {status}): {body}"
                )))
            }
        }
    }

    async fn update(&self, key: &str, value: &str) -> Result<(), StorageError> {
        // GCS objects are immutable, so update is just a store operation
        self.store(key, value).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let token = self.access_token().await?;
        let object_name = self.qualify_key(key);
        let url = self.object_url(&object_name);

        let response = self
            .client
            .delete(&url)
            .bearer_auth(token.expose_secret())
            .send()
            .await
            .map_err(|e| StorageError::Gcs(e.into()))?;

        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::OK => {
                info!("Deleted object {} from bucket {}", object_name, self.bucket);
                Ok(())
            }
            StatusCode::NOT_FOUND => {
                // Object doesn't exist, consider it a success (idempotent delete)
                warn!(
                    "Object {} not found in bucket {} during delete (already deleted?)",
                    object_name, self.bucket
                );
                Ok(())
            }
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(StorageError::Gcs(eyre!(
                    "Failed to delete object (status {status}): {body}"
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // A throwaway RSA key generated only for these tests; it grants access to
    // nothing and is deliberately named .dummy.pem for secret scanners.
    const TEST_KEY_PEM: &str = include_str!("../../test_data/gcloud_test_key.dummy.pem");

    fn provider(server: &MockServer) -> GoogleCloudStorage {
        let key = json!({
            "client_email": "acme@test-project.iam.gserviceaccount.com",
            "private_key": TEST_KEY_PEM,
            "token_uri": format!("{}/token", server.uri()),
        });
        GoogleCloudStorage::new(&key.to_string(), "test-bucket", "status-list/certs")
            .unwrap()
            .with_api_base(server.uri())
    }

    async fn mount_token_mock(server: &MockServer, expected_mints: u64) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "gcp-token",
                "expires_in": 3600,
            })))
            .expect(expected_mints)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn store_creates_object() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;

        Mock::given(method("POST"))
            .and(path("/upload/storage/v1/b/test-bucket/o"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "status-list/certs/certs-example.com-cert_data.json",
                "bucket": "test-bucket",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let storage = provider(&server);
        storage.store("certs-example.com-cert_data.json", "test data").await.unwrap();
    }

    #[tokio::test]
    async fn load_returns_object_content() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;

        Mock::given(method("GET"))
            .and(path("/storage/v1/b/test-bucket/o/status-list%2Fcerts%2Fcerts-example.com-cert_data.json/media"))
            .respond_with(ResponseTemplate::new(200).set_body_string("test data"))
            .expect(1)
            .mount(&server)
            .await;

        let storage = provider(&server);
        let result = storage.load("certs-example.com-cert_data.json").await.unwrap();
        assert_eq!(result, Some("test data".to_string()));
    }

    #[tokio::test]
    async fn load_returns_none_for_missing_object() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;

        Mock::given(method("GET"))
            .and(path("/storage/v1/b/test-bucket/o/status-list%2Fcerts%2Fmissing.json/media"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let storage = provider(&server);
        let result = storage.load("missing.json").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn delete_removes_object() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;

        Mock::given(method("DELETE"))
            .and(path("/storage/v1/b/test-bucket/o/status-list%2Fcerts%2Fdelete-me.json"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let storage = provider(&server);
        storage.delete("delete-me.json").await.unwrap();
    }

    #[tokio::test]
    async fn delete_is_idempotent_for_missing_object() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;

        Mock::given(method("DELETE"))
            .and(path("/storage/v1/b/test-bucket/o/status-list%2Fcerts%2Fmissing.json"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let storage = provider(&server);
        // Should succeed even if object doesn't exist
        storage.delete("missing.json").await.unwrap();
    }

    #[tokio::test]
    async fn update_overwrites_object() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;

        // GCS update is just a store operation
        Mock::given(method("POST"))
            .and(path("/upload/storage/v1/b/test-bucket/o"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "status-list/certs/certs-example.com-cert_data.json",
                "bucket": "test-bucket",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let storage = provider(&server);
        storage.update("certs-example.com-cert_data.json", "updated data").await.unwrap();
    }

    #[tokio::test]
    async fn qualify_key_with_prefix() {
        let server = MockServer::start().await;
        mount_token_mock(&server, 1).await;

        Mock::given(method("POST"))
            .and(path("/upload/storage/v1/b/test-bucket/o"))
            .and(query_param("name", "status-list/certs/test-key.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "status-list/certs/test-key.json"})))
            .expect(1)
            .mount(&server)
            .await;

        let storage = provider(&server);
        storage.store("test-key.json", "data").await.unwrap();
    }

    #[tokio::test]
    async fn qualify_key_without_prefix() {
        let key = json!({
            "client_email": "acme@test-project.iam.gserviceaccount.com",
            "private_key": TEST_KEY_PEM,
            "token_uri": "http://localhost/token",
        });
        let storage = GoogleCloudStorage::new(&key.to_string(), "test-bucket", "")
            .unwrap();

        assert_eq!(storage.qualify_key("test-key.json"), "test-key.json");
        assert_eq!(storage.qualify_key("/test-key.json"), "test-key.json");
    }
}
