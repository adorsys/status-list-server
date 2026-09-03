#![cfg(feature = "gcp")]

use std::time::Duration;

use status_list_server::{
    cert_manager::storage::Storage, outbound::gcp_secret::GcpSecretManagerClient,
};
use testcontainers_modules::testcontainers::{
    GenericImage,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

const EMULATOR_IMAGE: &str = "ghcr.io/blackwell-systems/gcp-secret-manager-emulator-dual";
const EMULATOR_TAG: &str = "1.9";
const TEST_PROJECT_ID: &str = "test-project";

async fn start_emulator(
    cache_ttl: Duration,
) -> (
    testcontainers_modules::testcontainers::ContainerAsync<GenericImage>,
    GcpSecretManagerClient,
) {
    let container = GenericImage::new(EMULATOR_IMAGE, EMULATOR_TAG)
        .with_exposed_port(8080.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "Ready to accept both gRPC and REST requests",
        ))
        .start()
        .await
        .expect("Failed to start GCP Secret Manager emulator container");

    let port = container
        .get_host_port_ipv4(8080)
        .await
        .expect("Failed to resolve gRPC host port");

    let endpoint = format!("http://127.0.0.1:{port}");

    let client = GcpSecretManagerClient::builder(TEST_PROJECT_ID)
        .endpoint(Some(&endpoint))
        .allow_anonymous_credentials(true)
        .secrets_cache_ttl(cache_ttl)
        .build()
        .await
        .expect("Failed to build GcpSecretManagerClient");

    (container, client)
}

#[tokio::test]
async fn test_gcp_secret_manager_storage_lifecycle() {
    let (_container, client) = start_emulator(Duration::ZERO).await;

    let secret_key = "keys-status.example.com";
    let secret_value = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----";

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

    // Overwrite secret with new version
    let updated_value =
        "-----BEGIN PRIVATE KEY-----\nUPDATED_KEY_MATERIAL...\n-----END PRIVATE KEY-----";
    client
        .store(secret_key, updated_value)
        .await
        .expect("Failed to overwrite secret");

    let loaded_updated = client
        .load(secret_key)
        .await
        .expect("Failed to load updated secret");
    assert_eq!(loaded_updated.as_deref(), Some(updated_value));

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
async fn test_gcp_secret_manager_cache_behavior() {
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

#[tokio::test]
async fn test_gcp_secret_manager_reachable() {
    let (_container, client) = start_emulator(Duration::ZERO).await;

    let reachable_result = client.reachable().await;
    assert!(
        reachable_result.is_ok(),
        "Client should be reachable via emulator: {reachable_result:?}"
    );
}
