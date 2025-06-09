mod aws;
mod redis;

pub use crate::utils::cert_manager::storage::redis::Redis;
use ::redis::RedisError;
use async_trait::async_trait;
pub use aws::{AwsS3, AwsSecretsManager};
use color_eyre::eyre::Error as Report;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Redis error: {0}")]
    Redis(#[from] RedisError),

    #[error("AWS SDK error: {0}")]
    AwsSdk(#[source] Report),

    #[error("The data is invalid: {0}")]
    InvalidData(String),

    #[error("Bucket {0} is unavailable")]
    BucketUnavailable(String),
}

/// Abstract interface for storage backends used by the certificate manager.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Store the value identified by the given key
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError>;
    /// Get the value specified by the given key
    async fn load(&self, key: &str) -> Result<Option<String>, StorageError>;
    /// Update the value associated with the given key
    async fn update(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.store(key, value).await
    }
    /// Delete the value associated with the given key
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
}
