//! Integration tests for the ACME certificate provisioning flow.
//!
//! These tests require Docker to be running. They spin up:
//! - **Pebble** (ACME CA test server)
//! - **challtestsrv** (DNS server for Pebble)
//! - **LocalStack** (S3 + Secrets Manager)
//! - **Redis** (S3 cache layer)

use std::{sync::Arc, time::Duration};

use aws_config::BehaviorVersion;
use aws_sdk_s3::Client as S3Client;
use status_list_server::cert_manager::{
    CertManager,
    challenge::{Dns01Handler, PebbleDnsUpdater},
    http_client::DefaultHttpClient,
    storage::{AwsS3, AwsSecretsManager, Redis as RedisStorage},
};
use testcontainers_modules::{
    localstack::LocalStack,
    redis::Redis,
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

const BUCKET_NAME: &str = "status-list-adorsys";
const AWS_REGION: &str = "us-east-1";

/// Minica root CA that signs Pebble's own TLS server certificate.
const PEBBLE_MINICA_ROOT_CA: &[u8] = include_bytes!("../src/test_resources/pebble.pem");

/// Holds all running containers and resolved ports for a single test run.
/// Containers are stopped automatically when this is dropped.
struct TestInfra {
    _challtestsrv: ContainerAsync<GenericImage>,
    _pebble: ContainerAsync<GenericImage>,
    _localstack: ContainerAsync<LocalStack>,
    _redis: ContainerAsync<Redis>,

    pebble_acme_port: u16,
    challtestsrv_port: u16,
    localstack_port: u16,
    redis_port: u16,
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
            .with_env_var("SERVICES", "s3,secretsmanager")
            .start()
            .await
            .expect("Failed to start LocalStack");

        let redis = Redis::default()
            .with_tag("8.6")
            .start()
            .await
            .expect("Failed to start Redis");

        let pebble_acme_port = pebble.get_host_port_ipv4(14000).await.unwrap();
        let challtestsrv_port = challtestsrv.get_host_port_ipv4(8055).await.unwrap();
        let localstack_port = localstack.get_host_port_ipv4(4566).await.unwrap();
        let redis_port = redis.get_host_port_ipv4(6379).await.unwrap();

        Self {
            _challtestsrv: challtestsrv,
            _pebble: pebble,
            _localstack: localstack,
            _redis: redis,
            pebble_acme_port,
            challtestsrv_port,
            localstack_port,
            redis_port,
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

    /// Create a Redis connection manager for the cache layer.
    async fn redis_connection(&self) -> redis::aio::ConnectionManager {
        let url = format!("redis://127.0.0.1:{}", self.redis_port);
        let client = redis::Client::open(url).expect("Failed to create Redis client");
        client
            .get_connection_manager()
            .await
            .expect("Failed to get Redis connection manager")
    }

    /// Build a `CertManager` with storage topology:
    /// `AwsS3` + `Redis` cache for certs, `AwsSecretsManager` for secrets.
    async fn build_cert_manager(&self, domain: &str) -> CertManager {
        let aws_config = self.aws_config().await;
        let redis_conn = self.redis_connection().await;

        let cache = RedisStorage::new(redis_conn);
        let cert_storage = AwsS3::new(&aws_config, BUCKET_NAME, AWS_REGION).with_cache(cache);
        let secrets_storage = AwsSecretsManager::new(&aws_config, Duration::from_millis(0))
            .await
            .expect("Failed to create AwsSecretsManager");

        let challtestsrv_url = format!("http://127.0.0.1:{}", self.challtestsrv_port);
        let dns_updater = PebbleDnsUpdater::new(&challtestsrv_url);
        let challenge_handler = Dns01Handler::new(dns_updater);

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
        .with_cert_storage(cert_storage)
        .with_secrets_storage(secrets_storage)
        .with_challenge_handler(challenge_handler)
        .with_acme_http_client(http_client)
    }

    /// Create an S3 client (path-style).
    async fn s3_client(&self) -> S3Client {
        let aws_config = self.aws_config().await;
        let c = S3Client::new(&aws_config);
        let dev_config = c.config().to_builder().force_path_style(true).build();
        S3Client::from_conf(dev_config)
    }

    /// Create a Secrets Manager client.
    async fn secrets_manager_client(&self) -> aws_sdk_secretsmanager::Client {
        let aws_config = self.aws_config().await;
        aws_sdk_secretsmanager::Client::new(&aws_config)
    }
}

#[tokio::test]
async fn test_full_certificate_provisioning() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let infra = TestInfra::start("provision").await;
    let cert_manager = infra.build_cert_manager("test.example.com").await;

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

    // Verify certificate is persisted in S3
    let s3 = infra.s3_client().await;
    let objects = s3
        .list_objects_v2()
        .bucket(BUCKET_NAME)
        .send()
        .await
        .expect("Failed to list S3 objects");
    let keys: Vec<_> = objects.contents().iter().filter_map(|o| o.key()).collect();
    assert!(keys.iter().any(|k| k.contains("cert_data.json")));

    // Verify signing key is in Secrets Manager
    let sm = infra.secrets_manager_client().await;
    let secrets = sm
        .list_secrets()
        .send()
        .await
        .expect("Failed to list secrets");
    let names: Vec<_> = secrets
        .secret_list()
        .iter()
        .filter_map(|s| s.name())
        .collect();
    assert!(!names.is_empty());

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
    let cert_manager = Arc::new(infra.build_cert_manager("renew.example.com").await);

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
