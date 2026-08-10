#![cfg(all(feature = "acme", feature = "gcs"))]

use status_list_server::{cert_manager::storage::Storage, outbound::gcs::GoogleCloudStorage};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// A throwaway RSA key generated only for these tests; it grants access to
// nothing and is deliberately named .dummy.pem for secret scanners.
const TEST_KEY_PEM: &str = include_str!("../test_data/gcloud_test_key.dummy.pem");

const BUCKET: &str = "status-list-certs";

fn gcs_provider(server: &MockServer) -> GoogleCloudStorage {
    let key = serde_json::json!({
        "client_email": "acme@test-project.iam.gserviceaccount.com",
        "private_key": TEST_KEY_PEM,
        "token_uri": format!("{}/token", server.uri()),
    });
    GoogleCloudStorage::new(&key.to_string(), BUCKET, "tenant-a/certificates")
        .unwrap()
        .with_api_base(server.uri())
}

async fn mount_token_mock(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "gcp-token",
            "expires_in": 3600,
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn gcs_storage_round_trip() {
    let server = MockServer::start().await;
    mount_token_mock(&server).await;

    // Store mock
    Mock::given(method("POST"))
        .and(path("/upload/storage/v1/b/status-list-certs/o"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "tenant-a/certificates/certs-example.com-cert_data.json",
            "bucket": BUCKET,
        })))
        .expect(2) // Called twice (store and update)
        .mount(&server)
        .await;

    // Load mock
    Mock::given(method("GET"))
        .and(path("/storage/v1/b/status-list-certs/o/tenant-a%2Fcertificates%2Fcerts-example.com-cert_data.json/media"))
        .respond_with(ResponseTemplate::new(200).set_body_string("v1"))
        .mount(&server)
        .await;

    // Delete mock
    Mock::given(method("DELETE"))
        .and(path("/storage/v1/b/status-list-certs/o/tenant-a%2Fcertificates%2Fcerts-example.com-cert_data.json"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let storage = gcs_provider(&server);
    let key = "certs-example.com-cert_data.json";

    // Test store
    storage.store(key, "v1").await.unwrap();

    // Test load
    let loaded = storage.load(key).await.unwrap();
    assert_eq!(loaded, Some("v1".to_string()));

    // Test update (same as store in GCS)
    storage.update(key, "v2").await.unwrap();

    // Test delete
    storage.delete(key).await.unwrap();
}

#[tokio::test]
async fn gcs_storage_load_missing_returns_none() {
    let server = MockServer::start().await;
    mount_token_mock(&server).await;

    Mock::given(method("GET"))
        .and(path("/storage/v1/b/status-list-certs/o/tenant-a%2Fcertificates%2Fmissing.json/media"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let storage = gcs_provider(&server);
    let result = storage.load("missing.json").await.unwrap();
    assert_eq!(result, None);
}

#[tokio::test]
async fn gcs_storage_delete_is_idempotent() {
    let server = MockServer::start().await;
    mount_token_mock(&server).await;

    Mock::given(method("DELETE"))
        .and(path("/storage/v1/b/status-list-certs/o/tenant-a%2Fcertificates%2Fmissing.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let storage = gcs_provider(&server);
    // Should not fail when deleting non-existent object
    storage.delete("missing.json").await.unwrap();
}

#[tokio::test]
async fn gcs_storage_key_prefixing() {
    let server = MockServer::start().await;
    mount_token_mock(&server).await;

    // Verify the qualified key is used in the URL
    Mock::given(method("POST"))
        .and(path("/upload/storage/v1/b/status-list-certs/o"))
        .and(query_param("name", "tenant-a/certificates/nested/key.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "tenant-a/certificates/nested/key.json",
            "bucket": BUCKET,
        })))
        .mount(&server)
        .await;

    let storage = gcs_provider(&server);
    storage.store("nested/key.json", "data").await.unwrap();
}
