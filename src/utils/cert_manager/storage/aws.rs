use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_secretsmanager::{
    operation::get_secret_value::GetSecretValueError, Client as SecretsClient,
    Config as SecretsConfig,
};
use aws_secretsmanager_caching::SecretsManagerCachingClient as SecretsCacheClient;
use color_eyre::eyre::eyre;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::{cert_manager::storage::StorageError, utils::cert_manager::Storage};

/// Type used for AWS Secrets Manager operations
pub struct AwsSecretsManager {
    client: SecretsClient,
    cache: SecretsCacheClient,
}

impl AwsSecretsManager {
    /// Create a new instance of [AwsSecretsManager] with the given AWS SDK config
    pub async fn new(config: &SdkConfig) -> Result<Self, StorageError> {
        let client = SecretsClient::new(config);
        let asm_builder = SecretsConfig::from(config).to_builder();
        // Cache size: 100 and a TTL of 5 minutes
        let cache = SecretsCacheClient::from_builder(
            asm_builder,
            NonZeroUsize::new(100).unwrap(),
            Duration::from_secs(300),
            true,
        )
        .await
        .map_err(|e| StorageError::AwsSdk(e.into()))?;

        Ok(Self { client, cache })
    }
}

#[async_trait]
impl Storage for AwsSecretsManager {
    async fn store(&self, name: &str, data: &str) -> Result<(), StorageError> {
        use aws_sdk_secretsmanager::error::SdkError;

        // Store a secret only if it does not already exist
        match self.client.describe_secret().secret_id(name).send().await {
            Ok(_) => {
                warn!("Secret {name} already exists. Skipping...");
                Ok(())
            }
            Err(SdkError::ServiceError(err)) if err.err().is_resource_not_found_exception() => {
                // Secret does not exist, try to create it
                self.client
                    .create_secret()
                    .name(name)
                    .secret_string(data)
                    .send()
                    .await
                    .map_err(|e| StorageError::AwsSdk(e.into()))?;
                Ok(())
            }
            Err(sdk_err) => Err(StorageError::AwsSdk(sdk_err.into())),
        }
    }

    async fn load(&self, name: &str) -> Result<Option<String>, StorageError> {
        use aws_sdk_secretsmanager::error::SdkError;

        match self.cache.get_secret_value(name, None, None, false).await {
            Ok(value) => Ok(value.secret_string),
            Err(err) => {
                // Check for ResourceNotFoundException
                if let Some(SdkError::ServiceError(service_err)) =
                    err.downcast_ref::<SdkError<GetSecretValueError>>()
                {
                    if service_err.err().is_resource_not_found_exception() {
                        return Ok(None);
                    }
                }
                Err(StorageError::AwsSdk(eyre!("{err}")))
            }
        }
    }

    async fn update(&self, name: &str, data: &str) -> Result<(), StorageError> {
        self.client
            .put_secret_value()
            .secret_id(name)
            .secret_string(data)
            .send()
            .await
            .map_err(|e| StorageError::AwsSdk(e.into()))?;

        // Force the secret refresh in the cache
        let _ = self.cache.get_secret_value(name, None, None, true).await;
        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        self.client
            .delete_secret()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| StorageError::AwsSdk(e.into()))?;

        // Invalidate cache by refreshing the secret
        let _ = self.cache.get_secret_value(name, None, None, true).await;
        Ok(())
    }
}

/// Struct representing AWS S3 storage with optional caching mechanism
pub struct AwsS3 {
    client: S3Client,
    bucket: String,
    cache: Option<Box<dyn Storage>>,
    bucket_exists: AtomicBool,
}

impl AwsS3 {
    /// Create a new instance of [AwsS3Storage] with the given AWS SDK config and bucket name
    pub fn new(config: &SdkConfig, bucket_name: impl Into<String>) -> Self {
        Self {
            client: S3Client::new(config),
            bucket: bucket_name.into(),
            cache: None,
            bucket_exists: AtomicBool::new(false),
        }
    }

    /// Set the cache layer if needed
    pub fn with_cache(mut self, cache: impl Storage + 'static) -> Self {
        self.cache = Some(Box::new(cache));
        self
    }

    // Helper function to ensure the S3 bucket exists before any operation
    async fn ensure_bucket_exists(&self) -> Result<(), StorageError> {
        use aws_sdk_s3::error::SdkError;

        // return if bucket is already verified
        if self.bucket_exists.load(Ordering::Relaxed) {
            return Ok(());
        }

        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY: Duration = Duration::from_millis(500);

        for attempt in 0..MAX_RETRIES {
            // Check if the bucket exists
            match self.client.head_bucket().bucket(&self.bucket).send().await {
                Ok(_) => {
                    info!("Bucket {} already exists. Skipping...", self.bucket);
                    self.bucket_exists.store(true, Ordering::Relaxed);
                    return Ok(());
                }
                Err(SdkError::ServiceError(err)) if err.err().is_not_found() => {
                    // Bucket not found, attempt to create it
                    match self
                        .client
                        .create_bucket()
                        .bucket(&self.bucket)
                        .send()
                        .await
                    {
                        Ok(_) => {
                            info!("Bucket {} created successfully", self.bucket);
                            self.bucket_exists.store(true, Ordering::Relaxed);
                            return Ok(());
                        }
                        Err(create_err) => {
                            if attempt == MAX_RETRIES - 1 {
                                return Err(StorageError::AwsSdk(create_err.into()));
                            }
                            warn!(
                                "Failed to create bucket {}: {create_err}. Retrying...",
                                self.bucket
                            );
                        }
                    }
                }
                Err(err) => {
                    if attempt == MAX_RETRIES - 1 {
                        return Err(StorageError::AwsSdk(err.into()));
                    }
                    warn!("Error checking bucket {}: {err}. Retrying...", self.bucket);
                }
            }

            // Wait a bit before retrying
            if attempt < MAX_RETRIES - 1 {
                sleep(RETRY_DELAY).await;
            }
        }
        Err(StorageError::BucketUnavailable(self.bucket.clone()))
    }
}

#[async_trait]
impl Storage for AwsS3 {
    async fn store(&self, key: &str, data: &str) -> Result<(), StorageError> {
        // Ensure the bucket exists
        self.ensure_bucket_exists().await?;

        // Invalidate cache
        if let Some(cache) = &self.cache {
            if let Err(e) = cache.delete(key).await {
                warn!("Failed to invalidate cache for {key}: {e}");
            }
        }

        // Store the object in the bucket
        let body = data.as_bytes().to_vec();
        match self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body.into())
            .send()
            .await
        {
            Ok(_) => {
                info!("Stored object {key} in bucket {}", self.bucket);
                Ok(())
            }
            Err(e) => {
                // We make sure cache stays invalid
                if let Some(cache) = &self.cache {
                    let _ = cache.delete(key).await;
                }
                Err(StorageError::AwsSdk(e.into()))
            }
        }
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        use aws_sdk_s3::error::SdkError;

        // Check the cache first if it exists
        if let Some(cache) = &self.cache {
            match cache.load(key).await {
                Ok(Some(data)) => {
                    return Ok(Some(data));
                }
                Ok(None) => (),
                Err(e) => warn!("Cache error for {key}: {e}"),
            }
        }

        // If not found in cache, try to get directly from S3
        self.ensure_bucket_exists().await?;
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => {
                let bytes = output
                    .body
                    .collect()
                    .await
                    .map_err(|e| StorageError::AwsSdk(e.into()))?;
                let data = String::from_utf8(bytes.into_bytes().into())
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                // Update cache if it exists
                if let Some(cache) = &self.cache {
                    if let Err(e) = cache.store(key, &data).await {
                        warn!("Failed to update cache for {key}: {e}");
                    }
                }
                Ok(Some(data))
            }
            Err(SdkError::ServiceError(err)) if err.err().is_no_such_key() => Ok(None),
            Err(sdk_err) => Err(StorageError::AwsSdk(sdk_err.into())),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        match self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => {
                // Invalidate cache
                if let Some(cache) = &self.cache {
                    if let Err(e) = cache.delete(key).await {
                        warn!("Failed to invalidate cache for {key}: {e}");
                    }
                }
                Ok(())
            }
            Err(e) => Err(StorageError::AwsSdk(e.into())),
        }
    }
}
