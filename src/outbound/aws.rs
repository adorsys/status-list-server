//! AWS outbound certificate storage adapters.
//!
//! This module implements [`Storage`] for AWS Secrets Manager and S3-backed
//! certificate material. S3 objects are qualified with the configured key
//! prefix, while optional Redis-backed caching is wired by the composition root.

use std::time::Duration;

use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_secretsmanager::Client as SecretsClient;
use color_eyre::eyre::eyre;
use moka::future::Cache;
use tracing::{info, warn};

use crate::{
    cert_manager::storage::{Storage, StorageError},
    outbound::s3_object_store::{S3ErrorKind, S3ObjectStore},
};

/// AWS Secrets Manager.
pub struct AwsSecretsManager {
    client: SecretsClient,
    cache: Option<Cache<String, String>>,
}

impl AwsSecretsManager {
    // Create a new instance of [AwsSecretsManager] with the given AWS SDK config.
    ///
    /// # Caching Behavior
    /// - If `secrets_cache_ttl` is zero, **caching is disabled**: all secret requests go directly to AWS.
    /// - If `secrets_cache_ttl` is non-zero, an in-memory cache is created with that TTL.
    ///
    /// This TTL semantics is consistent with other caches in the application
    /// (status-list cache for status-lists and Redis for certificate data).
    pub async fn new(
        config: &SdkConfig,
        secrets_cache_ttl: Duration,
    ) -> Result<Self, StorageError> {
        const SECRETS_CACHE_MAX_CAPACITY: u64 = 100;

        let client = SecretsClient::new(config);
        let cache = (!secrets_cache_ttl.is_zero()).then(|| {
            Cache::builder()
                .max_capacity(SECRETS_CACHE_MAX_CAPACITY)
                .time_to_live(secrets_cache_ttl)
                .build()
        });
        if secrets_cache_ttl.is_zero() {
            info!("AWS Secrets cache disabled (TTL=0)");
        }

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

/// AWS S3 bucket with optional caching layer
pub struct AwsS3 {
    store: S3ObjectStore,
    cache: Option<Box<dyn Storage>>,
}

impl AwsS3 {
    /// Create a new instance of [`AwsS3`] with the given AWS parameters.
    pub fn new(
        config: &SdkConfig,
        bucket_name: impl Into<String>,
        region: impl Into<String>,
        key_prefix: impl Into<String>,
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
        let store = S3ObjectStore::new(
            client,
            bucket_name,
            region,
            key_prefix,
            true,
            S3ErrorKind::AwsSdk,
        );
        Self { store, cache: None }
    }

    /// Set the cache layer if needed
    pub fn with_cache(mut self, cache: impl Storage + 'static) -> Self {
        self.cache = Some(Box::new(cache));
        self
    }
}

#[async_trait]
impl Storage for AwsS3 {
    async fn store(&self, key: &str, data: &str) -> Result<(), StorageError> {
        // Ensure the bucket exists
        self.store.ensure_bucket_exists().await?;

        // Invalidate cache
        if let Some(cache) = &self.cache
            && let Err(e) = cache.delete(key).await
        {
            warn!("Failed to invalidate cache for {key}: {e}");
        }

        // Store the object in the bucket
        match self.store.put(key, data).await {
            Ok(_) => {
                info!("Stored object {key} in S3");
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
        match self.store.get(key).await {
            Ok(Some(data)) => {
                if let Some(cache) = &self.cache
                    && let Err(e) = cache.store(key, &data).await
                {
                    warn!("Failed to update cache for {key}: {e}");
                }
                Ok(Some(data))
            }
            other => other,
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        match self.store.delete(key).await {
            Ok(_) => {
                if let Some(cache) = &self.cache
                    && let Err(e) = cache.delete(key).await
                {
                    warn!("Failed to invalidate cache for {key}: {e}");
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
