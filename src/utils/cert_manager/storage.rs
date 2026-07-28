use async_trait::async_trait;
use color_eyre::eyre::Error as Report;
#[cfg(feature = "redis")]
use redis::RedisError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Redis error: {0}")]
    #[cfg(feature = "redis")]
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

#[async_trait]
impl<T: Storage + ?Sized> Storage for Box<T> {
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
