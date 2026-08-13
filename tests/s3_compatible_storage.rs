#![cfg(all(feature = "acme", feature = "s3-compatible"))]

use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client as S3Client;
use status_list_server::{cert_manager::storage::Storage, outbound::s3_compatible::S3Compatible};
use testcontainers_modules::testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::HttpWaitStrategy},
    runners::AsyncRunner,
};

const MINIO_ACCESS_KEY: &str = "minioadmin";
const MINIO_SECRET_KEY: &str = "minioadmin";
const MINIO_REGION: &str = "us-east-1";
const BUCKET: &str = "status-list-certs";

async fn minio_sdk_config(endpoint_url: String) -> aws_config::SdkConfig {
    aws_config::defaults(BehaviorVersion::latest())
        .region(aws_config::Region::new(MINIO_REGION))
        .endpoint_url(endpoint_url)
        .credentials_provider(Credentials::new(
            MINIO_ACCESS_KEY,
            MINIO_SECRET_KEY,
            None,
            None,
            "minio-test",
        ))
        .load()
        .await
}

#[tokio::test]
async fn s3_compatible_storage_round_trips_against_minio() {
    let minio = GenericImage::new("minio/minio", "RELEASE.2025-09-07T16-13-09Z")
        .with_exposed_port(9000.tcp())
        .with_wait_for(WaitFor::http(
            HttpWaitStrategy::new("/minio/health/ready")
                .with_port(9000.tcp())
                .with_expected_status_code(200_u16),
        ))
        .with_env_var("MINIO_ROOT_USER", MINIO_ACCESS_KEY)
        .with_env_var("MINIO_ROOT_PASSWORD", MINIO_SECRET_KEY)
        .with_cmd(vec!["server", "/data"])
        .start()
        .await
        .expect("Failed to start MinIO");

    let port = minio
        .get_host_port_ipv4(9000)
        .await
        .expect("Failed to resolve MinIO port");
    let endpoint_url = format!("http://127.0.0.1:{port}");
    let sdk_config = minio_sdk_config(endpoint_url.clone()).await;
    let storage = S3Compatible::builder()
        .endpoint_url(&endpoint_url)
        .region(MINIO_REGION)
        .bucket(BUCKET)
        .key_prefix("tenant-a/certificates")
        .force_path_style(true)
        .auto_create_bucket(true)
        .credentials(MINIO_ACCESS_KEY, MINIO_SECRET_KEY)
        .build()
        .await
        .expect("Failed to build S3-compatible storage");

    let key = "certs-example.com-cert_data.json";
    assert_eq!(storage.load(key).await.unwrap(), None);

    storage.store(key, "v1").await.unwrap();
    assert_eq!(storage.load(key).await.unwrap().as_deref(), Some("v1"));

    storage.update(key, "v2").await.unwrap();
    assert_eq!(storage.load(key).await.unwrap().as_deref(), Some("v2"));

    let client = S3Client::from_conf(
        S3Client::new(&sdk_config)
            .config()
            .to_builder()
            .force_path_style(true)
            .build(),
    );
    let objects = client
        .list_objects_v2()
        .bucket(BUCKET)
        .send()
        .await
        .expect("Failed to list objects");
    let keys: Vec<_> = objects.contents().iter().filter_map(|o| o.key()).collect();
    assert_eq!(
        keys,
        vec!["tenant-a/certificates/certs-example.com-cert_data.json"]
    );

    storage.delete(key).await.unwrap();
    assert_eq!(storage.load(key).await.unwrap(), None);
}
