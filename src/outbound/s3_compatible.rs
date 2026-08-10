use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_s3::{Client as S3Client, config::Builder as S3ConfigBuilder};
use color_eyre::eyre::eyre;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::utils::cert_manager::storage::{Storage, StorageError};

/// S3-compatible object storage for certificate material.
///
/// Object keys are the certificate manager's logical keys, optionally qualified
/// with `key_prefix`. For example, key `certs-example.com-cert_data.json` and
/// prefix `status-list/certs` are stored as
/// `status-list/certs/certs-example.com-cert_data.json`.
pub struct S3Compatible {
    client: S3Client,
    bucket: String,
    region: String,
    key_prefix: String,
    auto_create_bucket: bool,
    bucket_exists: AtomicBool,
}

impl S3Compatible {
    const BUCKET_MAX_RETRIES: u32 = 3;
    const BUCKET_RETRY_DELAY: Duration = Duration::from_millis(500);

    pub fn new(
        config: &SdkConfig,
        bucket: impl Into<String>,
        region: impl Into<String>,
        key_prefix: impl Into<String>,
        force_path_style: bool,
        auto_create_bucket: bool,
    ) -> Self {
        let s3_config = S3ConfigBuilder::from(config)
            .force_path_style(force_path_style)
            .build();
        Self {
            client: S3Client::from_conf(s3_config),
            bucket: bucket.into(),
            region: region.into(),
            key_prefix: key_prefix.into(),
            auto_create_bucket,
            bucket_exists: AtomicBool::new(false),
        }
    }

    fn qualify_key(&self, key: &str) -> String {
        qualify_key(&self.key_prefix, key)
    }

    async fn ensure_bucket_exists(&self) -> Result<(), StorageError> {
        use aws_sdk_s3::{error::SdkError, types::CreateBucketConfiguration};

        if self.bucket_exists.load(Ordering::Relaxed) {
            return Ok(());
        }

        for attempt in 0..Self::BUCKET_MAX_RETRIES {
            match self.client.head_bucket().bucket(&self.bucket).send().await {
                Ok(_) => {
                    self.bucket_exists.store(true, Ordering::Relaxed);
                    return Ok(());
                }
                Err(SdkError::ServiceError(err)) if err.err().is_not_found() => {
                    if !self.auto_create_bucket {
                        return Err(StorageError::BucketUnavailable(self.bucket.clone()));
                    }

                    let mut req = self.client.create_bucket().bucket(&self.bucket);
                    if self.region != "us-east-1" {
                        let location_constraint = self.region.parse().map_err(|_| {
                            StorageError::ObjectStorage(eyre!(
                                "invalid S3-compatible region '{}' for LocationConstraint",
                                self.region
                            ))
                        })?;
                        req = req.create_bucket_configuration(
                            CreateBucketConfiguration::builder()
                                .location_constraint(location_constraint)
                                .build(),
                        );
                    }

                    match req.send().await {
                        Ok(_) => {
                            info!("Created S3-compatible bucket {}", self.bucket);
                            self.bucket_exists.store(true, Ordering::Relaxed);
                            return Ok(());
                        }
                        Err(create_err) if attempt == Self::BUCKET_MAX_RETRIES - 1 => {
                            return Err(StorageError::ObjectStorage(create_err.into()));
                        }
                        Err(create_err) => warn!(
                            "Failed to create S3-compatible bucket {}: {create_err}. Retrying...",
                            self.bucket
                        ),
                    }
                }
                Err(err) if attempt == Self::BUCKET_MAX_RETRIES - 1 => {
                    return Err(StorageError::ObjectStorage(err.into()));
                }
                Err(err) => warn!(
                    "Error checking S3-compatible bucket {}: {err}. Retrying...",
                    self.bucket
                ),
            }

            sleep(Self::BUCKET_RETRY_DELAY).await;
        }

        Err(StorageError::BucketUnavailable(self.bucket.clone()))
    }
}

#[async_trait]
impl Storage for S3Compatible {
    async fn store(&self, key: &str, data: &str) -> Result<(), StorageError> {
        self.ensure_bucket_exists().await?;
        let object_key = self.qualify_key(key);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .body(data.as_bytes().to_vec().into())
            .send()
            .await
            .map_err(|e| StorageError::ObjectStorage(e.into()))?;
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        use aws_sdk_s3::error::SdkError;

        self.ensure_bucket_exists().await?;
        let object_key = self.qualify_key(key);
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .send()
            .await
        {
            Ok(output) => {
                let bytes = output
                    .body
                    .collect()
                    .await
                    .map_err(|e| StorageError::ObjectStorage(e.into()))?;
                let data = String::from_utf8(bytes.into_bytes().into())
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                Ok(Some(data))
            }
            Err(SdkError::ServiceError(err)) if err.err().is_no_such_key() => Ok(None),
            Err(err) => Err(StorageError::ObjectStorage(err.into())),
        }
    }

    async fn update(&self, key: &str, data: &str) -> Result<(), StorageError> {
        self.store(key, data).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.ensure_bucket_exists().await?;
        let object_key = self.qualify_key(key);
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .send()
            .await
            .map_err(|e| StorageError::ObjectStorage(e.into()))?;
        Ok(())
    }
}

fn qualify_key(prefix: &str, key: &str) -> String {
    let prefix = prefix.trim_matches('/');
    let key = key.trim_start_matches('/');
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}/{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::qualify_key;

    #[test]
    fn qualifies_keys_with_normalized_prefix() {
        assert_eq!(
            qualify_key("status-list/certs", "certs-example.com-cert_data.json"),
            "status-list/certs/certs-example.com-cert_data.json"
        );
        assert_eq!(
            qualify_key("/status-list/certs/", "/certs-example.com-cert_data.json"),
            "status-list/certs/certs-example.com-cert_data.json"
        );
        assert_eq!(
            qualify_key("", "certs-example.com-cert_data.json"),
            "certs-example.com-cert_data.json"
        );
    }
}
