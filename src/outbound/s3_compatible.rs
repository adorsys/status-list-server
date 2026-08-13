//! S3-compatible outbound certificate storage adapter.
//!
//! This module implements [`Storage`] for certificate material stored in
//! MinIO, Ceph/RadosGW, or any endpoint exposing the S3 API. Configuration is
//! supplied through [`S3CompatibleBuilder`]: endpoint URL, region, bucket,
//! optional key prefix, path-style addressing, bucket auto-creation, and
//! optional explicit credentials.

use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::{Client as S3Client, config::Builder as S3ConfigBuilder};
use color_eyre::eyre::eyre;

use crate::{
    cert_manager::storage::{Storage, StorageError},
    outbound::s3_object_store::{S3ErrorKind, S3ObjectStore},
};

/// Builder for S3-compatible object storage.
#[derive(Debug, Clone)]
pub struct S3CompatibleBuilder {
    endpoint_url: Option<String>,
    region: String,
    bucket: Option<String>,
    key_prefix: String,
    force_path_style: bool,
    auto_create_bucket: bool,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
}

impl Default for S3CompatibleBuilder {
    fn default() -> Self {
        Self {
            endpoint_url: None,
            region: "us-east-1".to_string(),
            bucket: None,
            key_prefix: String::new(),
            force_path_style: true,
            auto_create_bucket: true,
            access_key_id: None,
            secret_access_key: None,
        }
    }
}

impl S3CompatibleBuilder {
    pub fn endpoint_url(mut self, endpoint_url: impl Into<String>) -> Self {
        self.endpoint_url = Some(endpoint_url.into());
        self
    }

    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = region.into();
        self
    }

    pub fn bucket(mut self, bucket: impl Into<String>) -> Self {
        self.bucket = Some(bucket.into());
        self
    }

    pub fn key_prefix(mut self, key_prefix: impl Into<String>) -> Self {
        self.key_prefix = key_prefix.into();
        self
    }

    pub fn force_path_style(mut self, force_path_style: bool) -> Self {
        self.force_path_style = force_path_style;
        self
    }

    pub fn auto_create_bucket(mut self, auto_create_bucket: bool) -> Self {
        self.auto_create_bucket = auto_create_bucket;
        self
    }

    pub fn credentials(
        mut self,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        self.access_key_id = Some(access_key_id.into());
        self.secret_access_key = Some(secret_access_key.into());
        self
    }

    pub async fn build(self) -> Result<S3Compatible, StorageError> {
        let Self {
            endpoint_url,
            region,
            bucket,
            key_prefix,
            force_path_style,
            auto_create_bucket,
            access_key_id,
            secret_access_key,
        } = self;

        let endpoint_url = required_non_empty(endpoint_url, "s3_compatible.endpoint_url")?;
        let bucket = required_non_empty(bucket, "s3_compatible.bucket")?;

        let access_key_id = access_key_id.filter(|value| !value.trim().is_empty());
        let secret_access_key = secret_access_key.filter(|value| !value.trim().is_empty());

        let mut config_loader = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.clone()))
            .endpoint_url(endpoint_url);

        match (access_key_id, secret_access_key) {
            (Some(access_key_id), Some(secret_access_key)) => {
                config_loader = config_loader.credentials_provider(Credentials::new(
                    access_key_id,
                    secret_access_key,
                    None,
                    None,
                    "s3-compatible-config",
                ));
            }
            (None, None) => {}
            _ => {
                return Err(StorageError::Backend(eyre!(
                    "s3_compatible.access_key_id and s3_compatible.secret_access_key must be configured together"
                )));
            }
        }

        let sdk_config = config_loader.load().await;
        let s3_config = S3ConfigBuilder::from(&sdk_config)
            .force_path_style(force_path_style)
            .build();
        let store = S3ObjectStore::new(
            S3Client::from_conf(s3_config),
            bucket,
            region,
            key_prefix,
            auto_create_bucket,
            S3ErrorKind::Backend,
        );
        Ok(S3Compatible { store })
    }
}

/// S3-compatible object storage for certificate material.
///
/// Object keys are the certificate manager's logical keys, optionally qualified
/// with `key_prefix`. For example, key `certs-example.com-cert_data.json` and
/// prefix `status-list/certs` are stored as
/// `status-list/certs/certs-example.com-cert_data.json`.
pub struct S3Compatible {
    store: S3ObjectStore,
}

impl S3Compatible {
    pub fn builder() -> S3CompatibleBuilder {
        S3CompatibleBuilder::default()
    }
}

#[async_trait]
impl Storage for S3Compatible {
    async fn store(&self, key: &str, data: &str) -> Result<(), StorageError> {
        self.store.put(key, data).await
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.store.get(key).await
    }

    async fn update(&self, key: &str, data: &str) -> Result<(), StorageError> {
        self.store.put(key, data).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.store.delete(key).await
    }
}

fn required_non_empty(value: Option<String>, name: &str) -> Result<String, StorageError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| StorageError::Backend(eyre!("{name} is required")))
}
