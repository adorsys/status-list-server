use std::time::Duration;

use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_secretsmanager::Client as SecretsClient;
use color_eyre::eyre::eyre;
use moka::future::Cache;
use tracing::{info, warn};

use crate::cert_manager::storage::{Storage, StorageError};

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
    /// (status-list cache for status-lists and certificate data).
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
                    .map_err(|e| StorageError::Backend(e.into()))?;
                Ok(())
            }
            Err(sdk_err) => Err(StorageError::Backend(sdk_err.into())),
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
            Err(err) => Err(StorageError::Backend(eyre!("{err}"))),
        }
    }

    async fn update(&self, name: &str, data: &str) -> Result<(), StorageError> {
        self.client
            .put_secret_value()
            .secret_id(name)
            .secret_string(data)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.into()))?;

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
            .map_err(|e| StorageError::Backend(e.into()))?;

        if let Some(cache) = &self.cache {
            cache.invalidate(name).await;
        }
        Ok(())
    }

    /// Verify the Secrets Manager API is reachable without touching any real
    /// secret, by issuing a `DescribeSecret` call for a name that is expected
    /// not to exist. This only requires the narrow `secretsmanager:DescribeSecret`
    /// permission.
    async fn reachable(&self) -> Result<(), StorageError> {
        use aws_sdk_secretsmanager::error::SdkError;

        match self
            .client
            .describe_secret()
            .secret_id("__health_probe_test__")
            .send()
            .await
        {
            // Secret intentionally does not exist, but the API is reachable.
            Err(SdkError::ServiceError(err)) if err.err().is_resource_not_found_exception() => {
                Ok(())
            }
            Err(e) => Err(StorageError::Backend(e.into())),
            Ok(_) => Ok(()),
        }
    }
}
