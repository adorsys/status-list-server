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

    #[error("storage backend error: {0}")]
    Backend(#[source] Report),

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

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct MemoryStorage {
    values: Arc<RwLock<HashMap<String, String>>>,
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.values
            .write()
            .await
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        Ok(self.values.read().await.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.values.write().await.remove(key);
        Ok(())
    }
}
