use async_trait::async_trait;
use color_eyre::eyre::Error as Report;
use moka::future::Cache;
#[cfg(feature = "redis")]
use redis::RedisError;
use std::time::Duration;
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

/// Cache policy for server cryptographic material.
///
/// Certificate material and private-key material are configured separately so
/// deployments can cache public certificate chains while forcing each private
/// key read to hit the backing secrets system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoMaterialCachePolicy {
    pub certificate_ttl: Duration,
    pub signing_key_ttl: Duration,
}

impl CryptoMaterialCachePolicy {
    pub const NO_CACHE: Self = Self {
        certificate_ttl: Duration::ZERO,
        signing_key_ttl: Duration::ZERO,
    };

    pub fn new(certificate_ttl: Duration, signing_key_ttl: Duration) -> Self {
        Self {
            certificate_ttl,
            signing_key_ttl,
        }
    }
}

impl Default for CryptoMaterialCachePolicy {
    fn default() -> Self {
        Self::NO_CACHE
    }
}

/// Consolidated storage backend for the server certificate chain, signing key,
/// and adjacent ACME account material.
pub struct CryptoMaterialStorage {
    backend: Box<dyn Storage>,
    certificate_cache: Option<Cache<String, String>>,
    signing_key_cache: Option<Cache<String, String>>,
}

impl CryptoMaterialStorage {
    const CACHE_MAX_CAPACITY: u64 = 16;

    pub fn new(backend: impl Storage + 'static) -> Self {
        Self::with_cache_policy(backend, CryptoMaterialCachePolicy::NO_CACHE)
    }

    pub fn with_cache_policy(
        backend: impl Storage + 'static,
        policy: CryptoMaterialCachePolicy,
    ) -> Self {
        let certificate_cache = cache_for_ttl(policy.certificate_ttl);
        let signing_key_cache = cache_for_ttl(policy.signing_key_ttl);
        if policy.signing_key_ttl.is_zero() {
            tracing::info!("server signing-key material cache disabled");
        }
        Self {
            backend: Box::new(backend),
            certificate_cache,
            signing_key_cache,
        }
    }

    pub async fn store_certificate_data(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.backend.store(key, value).await?;
        if let Some(cache) = &self.certificate_cache {
            cache.insert(key.to_string(), value.to_string()).await;
        }
        Ok(())
    }

    pub async fn load_certificate_data(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.load_with_cache(key, self.certificate_cache.as_ref())
            .await
    }

    pub async fn store_signing_key(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.backend.store(key, value).await?;
        if let Some(cache) = &self.signing_key_cache {
            cache.insert(key.to_string(), value.to_string()).await;
        }
        Ok(())
    }

    pub async fn load_signing_key(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.load_with_cache(key, self.signing_key_cache.as_ref())
            .await
    }

    pub async fn update_signing_key(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.backend.update(key, value).await?;
        if let Some(cache) = &self.signing_key_cache {
            cache.insert(key.to_string(), value.to_string()).await;
        }
        Ok(())
    }

    pub async fn load_secret(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.backend.load(key).await
    }

    pub async fn store_secret(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.backend.store(key, value).await
    }

    pub async fn delete_secret(&self, key: &str) -> Result<(), StorageError> {
        self.backend.delete(key).await
    }

    pub async fn invalidate_material(
        &self,
        certificate_key: &str,
        signing_key_key: &str,
    ) -> Result<(), StorageError> {
        if let Some(cache) = &self.certificate_cache {
            cache.invalidate(certificate_key).await;
        }
        if let Some(cache) = &self.signing_key_cache {
            cache.invalidate(signing_key_key).await;
        }
        Ok(())
    }

    pub async fn reachable(&self) -> Result<(), StorageError> {
        self.backend.reachable().await
    }

    async fn load_with_cache(
        &self,
        key: &str,
        cache: Option<&Cache<String, String>>,
    ) -> Result<Option<String>, StorageError> {
        if let Some(cache) = cache
            && let Some(value) = cache.get(key).await
        {
            return Ok(Some(value));
        }
        let loaded = self.backend.load(key).await?;
        if let (Some(cache), Some(value)) = (cache, loaded.as_ref()) {
            cache.insert(key.to_string(), value.clone()).await;
        }
        Ok(loaded)
    }
}

fn cache_for_ttl(ttl: Duration) -> Option<Cache<String, String>> {
    (!ttl.is_zero()).then(|| {
        Cache::builder()
            .max_capacity(CryptoMaterialStorage::CACHE_MAX_CAPACITY)
            .time_to_live(ttl)
            .build()
    })
}
