use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use aws_sdk_s3::{Client as S3Client, types::CreateBucketConfiguration};
use color_eyre::eyre::{Report, eyre};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::cert_manager::storage::StorageError;

#[derive(Clone, Copy)]
pub(crate) enum S3ErrorKind {
    AwsSdk,
    Backend,
}

impl S3ErrorKind {
    fn map(self, err: impl Into<Report>) -> StorageError {
        match self {
            Self::AwsSdk => StorageError::AwsSdk(err.into()),
            Self::Backend => StorageError::Backend(err.into()),
        }
    }
}

pub(crate) struct S3ObjectStore {
    client: S3Client,
    bucket: String,
    region: String,
    key_prefix: String,
    auto_create_bucket: bool,
    bucket_exists: AtomicBool,
    error_kind: S3ErrorKind,
}

impl S3ObjectStore {
    const BUCKET_MAX_RETRIES: u32 = 3;
    const BUCKET_RETRY_DELAY: Duration = Duration::from_millis(500);

    pub(crate) fn new(
        client: S3Client,
        bucket: impl Into<String>,
        region: impl Into<String>,
        key_prefix: impl Into<String>,
        auto_create_bucket: bool,
        error_kind: S3ErrorKind,
    ) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            region: region.into(),
            key_prefix: key_prefix.into(),
            auto_create_bucket,
            bucket_exists: AtomicBool::new(false),
            error_kind,
        }
    }

    pub(crate) fn qualify_key(&self, key: &str) -> String {
        qualify_key(&self.key_prefix, key)
    }

    pub(crate) async fn ensure_bucket_exists(&self) -> Result<(), StorageError> {
        use aws_sdk_s3::error::SdkError;

        if self.bucket_exists.load(Ordering::Relaxed) {
            return Ok(());
        }

        for attempt in 0..Self::BUCKET_MAX_RETRIES {
            match self.client.head_bucket().bucket(&self.bucket).send().await {
                Ok(_) => {
                    info!("Bucket {} already exists. Skipping...", self.bucket);
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
                            self.error_kind.map(eyre!(
                                "Invalid region '{}' for LocationConstraint",
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
                            info!("Bucket {} created successfully", self.bucket);
                            self.bucket_exists.store(true, Ordering::Relaxed);
                            return Ok(());
                        }
                        Err(create_err) if attempt == Self::BUCKET_MAX_RETRIES - 1 => {
                            return Err(self.error_kind.map(create_err));
                        }
                        Err(create_err) => warn!(
                            "Failed to create bucket {}: {create_err}. Retrying...",
                            self.bucket
                        ),
                    }
                }
                Err(err) if attempt == Self::BUCKET_MAX_RETRIES - 1 => {
                    return Err(self.error_kind.map(err));
                }
                Err(err) => warn!("Error checking bucket {}: {err}. Retrying...", self.bucket),
            }

            sleep(Self::BUCKET_RETRY_DELAY).await;
        }

        Err(StorageError::BucketUnavailable(self.bucket.clone()))
    }

    pub(crate) async fn put(&self, key: &str, data: &str) -> Result<(), StorageError> {
        self.ensure_bucket_exists().await?;
        let object_key = self.qualify_key(key);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .body(data.as_bytes().to_vec().into())
            .send()
            .await
            .map_err(|e| self.error_kind.map(e))?;
        Ok(())
    }

    pub(crate) async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
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
                    .map_err(|e| self.error_kind.map(e))?;
                let data = String::from_utf8(bytes.into_bytes().into())
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                Ok(Some(data))
            }
            Err(SdkError::ServiceError(err)) if err.err().is_no_such_key() => Ok(None),
            Err(err) => Err(self.error_kind.map(err)),
        }
    }

    pub(crate) async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.ensure_bucket_exists().await?;
        let object_key = self.qualify_key(key);
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .send()
            .await
            .map_err(|e| self.error_kind.map(e))?;
        Ok(())
    }
}

pub(crate) fn qualify_key(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else if prefix.ends_with('/') {
        format!("{}{}", prefix, key)
    } else {
        format!("{prefix}/{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::qualify_key;

    #[test]
    fn qualifies_keys_with_optional_prefix() {
        assert_eq!(
            qualify_key("status-list/certs", "certs-example.com-cert_data.json"),
            "status-list/certs/certs-example.com-cert_data.json"
        );
        assert_eq!(
            qualify_key("status-list/certs/", "certs-example.com-cert_data.json"),
            "status-list/certs/certs-example.com-cert_data.json"
        );
        assert_eq!(
            qualify_key("", "certs-example.com-cert_data.json"),
            "certs-example.com-cert_data.json"
        );
    }
}
