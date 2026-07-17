mod memory;

#[cfg(feature = "aws-s3")]
mod aws;

#[cfg(feature = "redis-cache")]
mod redis;

pub use memory::MemoryStorage;

#[cfg(feature = "redis-cache")]
pub use crate::utils::cert_manager::storage::redis::Redis;

#[cfg(feature = "aws-s3")]
pub use aws::{AwsS3, AwsSecretsManager};

#[cfg(feature = "redis-cache")]
use ::redis::RedisError;

#[cfg(feature = "aws-s3")]
use color_eyre::eyre::Error as Report;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[cfg(feature = "redis-cache")]
    #[error("Redis error: {0}")]
    Redis(#[from] RedisError),

    #[cfg(feature = "aws-s3")]
    #[error("AWS SDK error: {0}")]
    AwsSdk(#[from] Report),

    #[error("The data is invalid: {0}")]
    InvalidData(String),

    #[cfg(feature = "aws-s3")]
    #[error("Bucket {0} is unavailable")]
    BucketUnavailable(String),

    #[error("Storage backend not available: {0}")]
    BackendUnavailable(String),
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

// Implement Storage for Box<dyn Storage> to allow dynamic dispatch
#[async_trait]
impl Storage for Box<dyn Storage> {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        (**self).store(key, value).await
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        (**self).load(key).await
    }

    async fn update(&self, key: &str, value: &str) -> Result<(), StorageError> {
        (**self).update(key, value).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        (**self).delete(key).await
    }
}
