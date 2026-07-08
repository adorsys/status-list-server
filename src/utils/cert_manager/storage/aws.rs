use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_s3::{Client as S3Client, types::CreateBucketConfiguration};
use aws_sdk_secretsmanager::Client as SecretsClient;
use color_eyre::eyre::eyre;
use moka::future::Cache;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::{cert_manager::storage::StorageError, utils::cert_manager::Storage};

/// Type used for AWS Secrets Manager operations
pub struct AwsSecretsManager {
    client: SecretsClient,
    cache: Option<Cache<String, String>>,
}

impl AwsSecretsManager {
    /// Create a new instance of [AwsSecretsManager] with the given AWS SDK config
    pub async fn new(
        config: &SdkConfig,
        secrets_cache_ttl: Duration,
        secrets_cache_max_capacity: usize,
    ) -> Result<Self, StorageError> {
        let client = SecretsClient::new(config);
<<<<<<< HEAD
        let asm_builder = SecretsConfig::from(config).to_builder();

        let cache = SecretsCacheClient::from_builder(
            asm_builder,
            NonZeroUsize::new(secrets_cache_max_capacity)
                .ok_or_else(|| StorageError::AwsSdk(eyre!("secrets_cache_max_capacity must be greater than 0")))?,
            secrets_cache_ttl,
            true,
        )
        .await
        .map_err(|e| StorageError::AwsSdk(e.into()))?;
=======
        let cache = (!secrets_cache_ttl.is_zero()).then(|| {
            Cache::builder()
                .max_capacity(100)
                .time_to_live(secrets_cache_ttl)
                .build()
        });
>>>>>>> main

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

        if let Some(cache) = &self.cache
            && let Some(value) = cache.get(name).await
        {
            return Ok(Some(value));
        }

        match self.client.get_secret_value().secret_id(name).send().await {
            Ok(value) => {
                if let Some(secret_string) = value.secret_string {
                    if let Some(cache) = &self.cache {
                        cache.insert(name.to_string(), secret_string.clone()).await;
                    }
                    Ok(Some(secret_string))
                } else {
                    Ok(None)
                }
            }
            Err(SdkError::ServiceError(service_err))
                if service_err.err().is_resource_not_found_exception() =>
            {
                Ok(None)
            }
            Err(err) => Err(StorageError::AwsSdk(eyre!("{err}"))),
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

        if let Some(cache) = &self.cache {
            cache.insert(name.to_string(), data.to_string()).await;
        }
        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        self.client
            .delete_secret()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| StorageError::AwsSdk(e.into()))?;

        if let Some(cache) = &self.cache {
            cache.invalidate(name).await;
        }
        Ok(())
    }
}

/// Struct representing AWS S3 storage with optional caching mechanism
pub struct AwsS3 {
    client: S3Client,
    bucket: String,
    region: String,
    key_prefix: String,
    max_retries: u32,
    retry_delay: Duration,
    cache: Option<Box<dyn Storage>>,
    bucket_exists: AtomicBool,
}

impl AwsS3 {
    /// Create a new instance of [`AwsS3`] with the given AWS SDK config and bucket name
    pub fn new(
        config: &SdkConfig,
        bucket_name: impl Into<String>,
        region: impl Into<String>,
        key_prefix: impl Into<String>,
        max_retries: u32,
        retry_delay: Duration,
    ) -> Self {
        let client = if std::env::var("APP_ENV").as_deref() == Ok("production") {
            S3Client::new(config)
        } else {
            let dev_config = S3Client::new(config)
                .config()
                .to_builder()
                .force_path_style(true)
                .build();
            S3Client::from_conf(dev_config)
        };
        Self {
            client,
            bucket: bucket_name.into(),
            region: region.into(),
            key_prefix: key_prefix.into(),
            max_retries,
            retry_delay,
            cache: None,
            bucket_exists: AtomicBool::new(false),
        }
    }

    /// Set the cache layer if needed
    pub fn with_cache(mut self, cache: impl Storage + 'static) -> Self {
        self.cache = Some(Box::new(cache));
        self
    }

    /// Qualify a key by prepending the configured S3 key prefix.
    /// If the prefix is empty, the key is returned as-is.
    fn qualify_key(&self, key: &str) -> String {
        if self.key_prefix.is_empty() {
            key.to_string()
        } else if self.key_prefix.ends_with('/') {
            format!("{}{}", self.key_prefix, key)
        } else {
            format!("{}/{}", self.key_prefix, key)
        }
    }

    // Helper function to ensure the S3 bucket exists before any operation
    async fn ensure_bucket_exists(&self) -> Result<(), StorageError> {
        use aws_sdk_s3::error::SdkError;

        // return if bucket is already verified
        if self.bucket_exists.load(Ordering::Relaxed) {
            return Ok(());
        }

        let max_retries = self.max_retries;

        for attempt in 0..max_retries {
            // Check if the bucket exists
            match self.client.head_bucket().bucket(&self.bucket).send().await {
                Ok(_) => {
                    info!("Bucket {} already exists. Skipping...", self.bucket);
                    self.bucket_exists.store(true, Ordering::Relaxed);
                    return Ok(());
                }
                Err(SdkError::ServiceError(err)) if err.err().is_not_found() => {
                    // Bucket not found, attempt to create it
                    let mut req = self.client.create_bucket().bucket(&self.bucket);
                    if self.region != "us-east-1" {
                        let location_constraint = self.region.parse().map_err(|_| {
                            StorageError::AwsSdk(eyre!(
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
                        Err(create_err) => {
                            if attempt == max_retries - 1 {
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
                    if attempt == max_retries - 1 {
                        return Err(StorageError::AwsSdk(err.into()));
                    }
                    warn!("Error checking bucket {}: {err}. Retrying...", self.bucket);
                }
            }

            // Wait a bit before retrying
            if attempt < max_retries - 1 {
                sleep(self.retry_delay).await;
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
        if let Some(cache) = &self.cache
            && let Err(e) = cache.delete(key).await
        {
            warn!("Failed to invalidate cache for {key}: {e}");
        }

        // Store the object in the bucket
        let s3_key = self.qualify_key(key);
        let body = data.as_bytes().to_vec();
        match self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&s3_key)
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
        let s3_key = self.qualify_key(key);
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&s3_key)
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
                if let Some(cache) = &self.cache
                    && let Err(e) = cache.store(key, &data).await
                {
                    warn!("Failed to update cache for {key}: {e}");
                }
                Ok(Some(data))
            }
            Err(SdkError::ServiceError(err)) if err.err().is_no_such_key() => Ok(None),
            Err(sdk_err) => Err(StorageError::AwsSdk(sdk_err.into())),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let s3_key = self.qualify_key(key);
        match self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
        {
            Ok(_) => {
                // Invalidate cache
                if let Some(cache) = &self.cache
                    && let Err(e) = cache.delete(key).await
                {
                    warn!("Failed to invalidate cache for {key}: {e}");
                }
                Ok(())
            }
            Err(e) => Err(StorageError::AwsSdk(e.into())),
        }
    }
}
