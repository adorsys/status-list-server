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

    /// Verify the backend is reachable without reading or storing any secret
    /// material. Used by the readiness probe: the default implementation
    /// considers the backend reachable, and concrete adapters that can cheaply
    /// prove reachability (e.g. a bucket `HEAD`) override this.
    async fn reachable(&self) -> Result<(), StorageError> {
        Ok(())
    }
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

    async fn reachable(&self) -> Result<(), StorageError> {
        (**self).reachable().await
    }
}

/// Normalize a storage key so it is valid and consistent across all secrets backends
/// (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, Memory).
///
/// Azure Key Vault is the most restrictive provider, requiring 1–127 characters
/// and admitting only ASCII alphanumeric characters and hyphens `[0-9a-zA-Z-]`.
/// This function replaces any character outside `[0-9a-zA-Z-]` with `-` and truncates
/// to 127 characters.
pub fn normalize_key(key: &str) -> String {
    let sanitized: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if sanitized.len() > 127 {
        sanitized[..127].to_string()
    } else {
        sanitized
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
        let normalized = normalize_key(key);
        self.values
            .write()
            .await
            .insert(normalized, value.to_string());
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        let normalized = normalize_key(key);
        Ok(self.values.read().await.get(&normalized).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let normalized = normalize_key(key);
        self.values.write().await.remove(&normalized);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_key() {
        assert_eq!(
            normalize_key("keys-status.example.com"),
            "keys-status-example-com"
        );
        assert_eq!(
            normalize_key("acme_accounts-example.com"),
            "acme-accounts-example-com"
        );
        assert_eq!(
            normalize_key("certs-status.example.com-cert_data.json"),
            "certs-status-example-com-cert-data-json"
        );
        assert_eq!(normalize_key("valid-key-123"), "valid-key-123");
        assert_eq!(
            normalize_key("key/with:special@chars.and+symbols"),
            "key-with-special-chars-and-symbols"
        );

        let long_key = "a".repeat(200);
        let normalized_long = normalize_key(&long_key);
        assert_eq!(normalized_long.len(), 127);
    }
}
