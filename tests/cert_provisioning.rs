#![cfg(feature = "aws")]

//! Integration tests for the ACME certificate provisioning flow.
//!
//! These tests require Docker to be running. They spin up:
//! - **Pebble** (ACME CA test server)
//! - **challtestsrv** (DNS server for Pebble)
//! - **LocalStack** (Secrets Manager)
//! - **Vault** (if enabled) or **OpenBao** (if enabled)

use std::{sync::Arc, time::Duration};

use aws_config::BehaviorVersion;
#[cfg(feature = "vault")]
use secrecy::SecretString;
#[cfg(feature = "vault")]
use status_list_server::{cert_manager::storage::Storage, outbound::vault::VaultClient};
use status_list_server::{
    cert_manager::{
        CertManager,
        challenge::{Dns01Handler, PebbleDnsProvider},
        http_client::DefaultHttpClient,
    },
    outbound::aws::AwsSecretsManager,
};
#[cfg(feature = "vault")]
use testcontainers_modules::hashicorp_vault::HashicorpVault;
use testcontainers_modules::{
    localstack::LocalStack,
    testcontainers::{
        ContainerAsync, GenericImage, ImageExt,
        core::{IntoContainerPort, WaitFor},
        runners::AsyncRunner,
    },
};

const PEBBLE_IMAGE: &str = "ghcr.io/letsencrypt/pebble";
const PEBBLE_TAG: &str = "2.10";

const CHALLTESTSRV_IMAGE: &str = "ghcr.io/letsencrypt/pebble-challtestsrv";
const CHALLTESTSRV_TAG: &str = "2.10";

const AWS_REGION: &str = "us-east-1";

#[cfg(feature = "vault")]
const OPENBAO_IMAGE: &str = "openbao/openbao";
#[cfg(feature = "vault")]
const OPENBAO_TAG: &str = "2.6";

/// Minica root CA that signs Pebble's own TLS server certificate.
const PEBBLE_MINICA_ROOT_CA: &[u8] = include_bytes!("../test_data/pebble.pem");

/// Holds all running containers and resolved ports for a single test run.
/// Containers are stopped automatically when this is dropped.
struct TestInfra {
    _challtestsrv: ContainerAsync<GenericImage>,
    _pebble: ContainerAsync<GenericImage>,
    _localstack: ContainerAsync<LocalStack>,

    pebble_acme_port: u16,
    challtestsrv_port: u16,
    localstack_port: u16,
}

impl TestInfra {
    /// Spin up all containers on a shared Docker network.
    ///
    /// `test_name` is included in Docker resource names for easier debugging.
    /// A random suffix keeps repeated and parallel test runs from colliding.
    async fn start(test_name: &str) -> Self {
        let run_id = uuid::Uuid::new_v4().simple();
        let resource_prefix = format!("{test_name}-{run_id}");
        let network = format!("acme-{resource_prefix}-net");
        let challtestsrv_name = format!("challtestsrv-{resource_prefix}");
        let pebble_name = format!("pebble-{resource_prefix}");

        let challtestsrv = GenericImage::new(CHALLTESTSRV_IMAGE, CHALLTESTSRV_TAG)
            .with_exposed_port(8055.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Starting management server"))
            .with_network(&network)
            .with_container_name(&challtestsrv_name)
            .with_cmd(vec!["-http01=", "-https01=", "-tlsalpn01="])
            .start()
            .await
            .expect("Failed to start challtestsrv");

        let pebble = GenericImage::new(PEBBLE_IMAGE, PEBBLE_TAG)
            .with_exposed_port(14000.tcp())
            .with_wait_for(WaitFor::message_on_stdout("ACME directory available at"))
            .with_env_var("PEBBLE_VA_NOSLEEP", "1")
            // Disable Pebble's intentional nonce rejection to prevent flaky tests
            // See: https://github.com/letsencrypt/pebble#invalid-anti-replay-nonce-errors
            .with_env_var("PEBBLE_WFE_NONCEREJECT", "0")
            .with_network(&network)
            .with_container_name(&pebble_name)
            .with_cmd(vec![
                "-config",
                "/test/config/pebble-config.json",
                "-strict",
                "-dnsserver",
                &format!("{challtestsrv_name}:8053"),
            ])
            .start()
            .await
            .expect("Failed to start Pebble");

        let localstack = LocalStack::default()
            .with_tag("4.14")
            .with_env_var("SERVICES", "secretsmanager")
            .start()
            .await
            .expect("Failed to start LocalStack");

        let pebble_acme_port = pebble.get_host_port_ipv4(14000).await.unwrap();
        let challtestsrv_port = challtestsrv.get_host_port_ipv4(8055).await.unwrap();
        let localstack_port = localstack.get_host_port_ipv4(4566).await.unwrap();

        Self {
            _challtestsrv: challtestsrv,
            _pebble: pebble,
            _localstack: localstack,
            pebble_acme_port,
            challtestsrv_port,
            localstack_port,
        }
    }

    /// Build an AWS SDK config pointing at the LocalStack endpoint.
    async fn aws_config(&self) -> aws_config::SdkConfig {
        aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(AWS_REGION))
            .endpoint_url(format!("http://127.0.0.1:{}", self.localstack_port))
            .test_credentials()
            .load()
            .await
    }

    /// Build a `CertManager` with one cryptographic-material backend for both
    /// certificate chains and signing keys.
    async fn build_cert_manager(
        &self,
        domain: &str,
        material_storage: impl Storage + 'static,
    ) -> CertManager {
        let challtestsrv_url = format!("http://127.0.0.1:{}", self.challtestsrv_port);
        let dns_provider = PebbleDnsProvider::new(&challtestsrv_url);
        let challenge_handler = Dns01Handler::new(dns_provider);

        let acme_directory_url = format!("https://127.0.0.1:{}/dir", self.pebble_acme_port);
        let http_client = DefaultHttpClient::new(Some(PEBBLE_MINICA_ROOT_CA))
            .expect("Failed to create ACME HTTP client");

        CertManager::new(
            vec![domain],
            "test@example.com",
            Some("Test Org"),
            &acme_directory_url,
        )
        .expect("Failed to create CertManager")
        .with_crypto_storage(material_storage)
        .with_challenge_handler(challenge_handler)
        .with_acme_http_client(http_client)
    }
}

#[cfg(feature = "vault")]
fn build_vault_storage(vault_port: u16) -> VaultClient {
    let vault_url = format!("http://127.0.0.1:{vault_port}");
    VaultClient::builder(vault_url, SecretString::from("root".to_string()))
        .mount("secret")
        .path_prefix("status-list")
        .secrets_cache_ttl(Duration::ZERO)
        .build()
        .expect("Failed to build VaultClient")
}

#[tokio::test]
async fn test_cert_provisioning_with_aws_secrets_manager() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let infra = TestInfra::start("provision").await;
    let aws_config = infra.aws_config().await;
    let material_storage = AwsSecretsManager::new(&aws_config, Duration::from_millis(0))
        .await
        .expect("Failed to create AwsSecretsManager");
    let cert_manager = infra
        .build_cert_manager("test.example.com", material_storage)
        .await;

    // Request a certificate
    let cert_data = cert_manager
        .request_certificate()
        .await
        .expect("Certificate provisioning failed");

    // Verify the certificate
    assert!(
        cert_data
            .certificate
            .contains("-----BEGIN CERTIFICATE-----")
    );
    assert!(cert_data.valid_from < cert_data.expires_at);
    assert!(cert_data.updated_at > 0);

    // Verify certificate and signing key are in the same material backend.
    let aws_config = infra.aws_config().await;
    let secrets = aws_sdk_secretsmanager::Client::new(&aws_config)
        .list_secrets()
        .send()
        .await
        .expect("Failed to list secrets");
    let names: Vec<_> = secrets
        .secret_list()
        .iter()
        .filter_map(|s| s.name())
        .collect();
    assert!(
        names.iter().any(|name| name.contains("cert_data.json")),
        "certificate data should be present in Secrets Manager"
    );
    assert!(
        names.contains(&"keys-test.example.com"),
        "signing key should be present in Secrets Manager"
    );

    // Verify cert chain extraction
    let cert_chain = cert_manager
        .cert_chain_parts()
        .await
        .expect("Failed to extract cert chain");
    assert!(cert_chain.is_some());
    let parts = cert_chain.unwrap();
    assert!(!parts.is_empty());
}

#[tokio::test]
async fn test_certificate_renewal_with_existing_cert() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let infra = TestInfra::start("renew").await;
    let aws_config = infra.aws_config().await;
    let material_storage = AwsSecretsManager::new(&aws_config, Duration::from_millis(0))
        .await
        .expect("Failed to create AwsSecretsManager");
    let cert_manager = Arc::new(
        infra
            .build_cert_manager("renew.example.com", material_storage)
            .await,
    );

    // Initial provisioning
    let initial_cert = cert_manager
        .request_certificate()
        .await
        .expect("Initial certificate provisioning failed");

    // Renewal should be a no-op
    cert_manager
        .renew_cert_if_needed()
        .await
        .expect("Renewal check failed");

    let current_cert = cert_manager
        .certificate()
        .await
        .expect("Failed to retrieve certificate")
        .expect("Certificate should still exist");

    assert_eq!(initial_cert.certificate, current_cert.certificate);
    assert_eq!(initial_cert.valid_from, current_cert.valid_from);
    assert_eq!(initial_cert.expires_at, current_cert.expires_at);
}

#[cfg(feature = "vault")]
#[tokio::test]
async fn test_cert_provisioning_with_hashicorp_vault() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let infra = TestInfra::start("vault-provision").await;
    let _vault_container = HashicorpVault::default()
        .with_tag("2.0")
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
        .start()
        .await
        .expect("Failed to start HashicorpVault container");
    let vault_port = _vault_container.get_host_port_ipv4(8200).await.unwrap();

    let material_storage = build_vault_storage(vault_port);
    let cert_manager = infra
        .build_cert_manager("vault.example.com", material_storage)
        .await;

    // Request a certificate
    let cert_data = cert_manager
        .request_certificate()
        .await
        .expect("Certificate provisioning failed with Vault material backend");

    // Verify the certificate content
    assert!(
        cert_data
            .certificate
            .contains("-----BEGIN CERTIFICATE-----")
    );
    assert!(cert_data.valid_from < cert_data.expires_at);
    assert!(cert_data.updated_at > 0);

    // Verify certificate and signing key were stored in Vault through one material backend.
    let vault_reader = build_vault_storage(vault_port);
    let certificate = Storage::load(&vault_reader, "certs-example.com-cert_data.json")
        .await
        .expect("Failed to load certificate data from Vault");
    assert!(
        certificate.is_some(),
        "certificate data should be present in Vault"
    );
    let signing_key = Storage::load(&vault_reader, "keys-vault.example.com")
        .await
        .expect("Failed to load signing_key from Vault");
    assert!(
        signing_key.is_some(),
        "signing_key should be present in Vault"
    );

    // Verify cert chain extraction
    let cert_chain = cert_manager
        .cert_chain_parts()
        .await
        .expect("Failed to extract cert chain");
    assert!(cert_chain.is_some());
    let parts = cert_chain.unwrap();
    assert!(!parts.is_empty());
}

#[cfg(feature = "vault")]
#[tokio::test]
async fn test_cert_provisioning_with_openbao() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let infra = TestInfra::start("openbao-provision").await;
    let _openbao_container = GenericImage::new(OPENBAO_IMAGE, OPENBAO_TAG)
        .with_exposed_port(8200.tcp())
        .with_wait_for(WaitFor::message_on_stdout(
            "Development mode should NOT be used in production",
        ))
        .with_env_var("BAO_DEV_ROOT_TOKEN_ID", "root")
        .with_env_var("BAO_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
        .start()
        .await
        .expect("Failed to start OpenBao container");
    let openbao_port = _openbao_container.get_host_port_ipv4(8200).await.unwrap();

    let material_storage = build_vault_storage(openbao_port);
    let cert_manager = infra
        .build_cert_manager("openbao.example.com", material_storage)
        .await;

    // Request a certificate
    let cert_data = cert_manager
        .request_certificate()
        .await
        .expect("Certificate provisioning failed with OpenBao material backend");

    // Verify the certificate content
    assert!(
        cert_data
            .certificate
            .contains("-----BEGIN CERTIFICATE-----")
    );
    assert!(cert_data.valid_from < cert_data.expires_at);
    assert!(cert_data.updated_at > 0);

    // Verify certificate and signing key were stored in OpenBao through one material backend.
    let openbao_reader = build_vault_storage(openbao_port);
    let certificate = Storage::load(&openbao_reader, "certs-example.com-cert_data.json")
        .await
        .expect("Failed to load certificate data from OpenBao");
    assert!(
        certificate.is_some(),
        "certificate data should be present in OpenBao"
    );
    let signing_key = Storage::load(&openbao_reader, "keys-openbao.example.com")
        .await
        .expect("Failed to load signing_key from OpenBao");
    assert!(
        signing_key.is_some(),
        "signing_key should be present in OpenBao"
    );

    // Verify cert chain extraction
    let cert_chain = cert_manager
        .cert_chain_parts()
        .await
        .expect("Failed to extract cert chain");
    assert!(cert_chain.is_some());
    let parts = cert_chain.unwrap();
    assert!(!parts.is_empty());
}
