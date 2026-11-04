use async_trait::async_trait;
use color_eyre::eyre::Error as Report;
use moka::future::Cache;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage backend error: {0}")]
    Backend(#[source] Report),

    #[error("The data is invalid: {0}")]
    InvalidData(String),
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError>;
    async fn load(&self, key: &str) -> Result<Option<String>, StorageError>;
    async fn update(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.store(key, value).await
    }
    async fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// Must not read or write secrets. Defaults to Ok for backends with no cheap probe.
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

use sha2::{Digest, Sha256};

/// Azure Key Vault is strictest: 127 chars of `[0-9a-zA-Z-]`, so anything else becomes '-'.
/// Longer keys keep 110 chars plus a hash suffix so shared prefixes don't collide.
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
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let digest = hex::encode(hasher.finalize());
        let hash_suffix = &digest[..16];
        // ASCII only after the mapping above, so slicing at byte 110 is safe.
        let prefix = &sanitized[..110];
        format!("{prefix}-{hash_suffix}")
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

/// Certs are cached until renewal; the key's TTL is configurable, down to no caching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoCachePolicy {
    pub signing_key_ttl: Duration,
}

impl CryptoCachePolicy {
    pub const NO_PRIVATE_KEY_CACHE: Self = Self {
        signing_key_ttl: Duration::ZERO,
    };

    pub fn new(signing_key_ttl: Duration) -> Self {
        Self { signing_key_ttl }
    }
}

impl Default for CryptoCachePolicy {
    fn default() -> Self {
        Self::NO_PRIVATE_KEY_CACHE
    }
}

pub struct CryptoStorage {
    backend: Box<dyn Storage>,
    certificate_cache: Cache<String, String>,
    signing_key_cache: Option<Cache<String, String>>,
}

impl CryptoStorage {
    const CERT_CACHE_CAPACITY: u64 = 1;
    const KEY_CACHE_CAPACITY: u64 = 1;

    pub fn new(backend: impl Storage + 'static) -> Self {
        Self::with_cache_policy(backend, CryptoCachePolicy::default())
    }

    pub fn with_cache_policy(backend: impl Storage + 'static, policy: CryptoCachePolicy) -> Self {
        let certificate_cache = Cache::builder()
            .max_capacity(CryptoStorage::CERT_CACHE_CAPACITY)
            .build();
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
        self.certificate_cache
            .insert(key.to_string(), value.to_string())
            .await;
        Ok(())
    }

    pub async fn update_certificate_data(
        &self,
        key: &str,
        value: &str,
    ) -> Result<(), StorageError> {
        self.backend.update(key, value).await?;
        self.certificate_cache
            .insert(key.to_string(), value.to_string())
            .await;
        Ok(())
    }

    pub async fn load_certificate_data(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.load_with_cache(key, Some(&self.certificate_cache))
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

    pub async fn invalidate_signing_key(&self, signing_key_key: &str) -> Result<(), StorageError> {
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
            .max_capacity(CryptoStorage::KEY_CACHE_CAPACITY)
            .time_to_live(ttl)
            .build()
    })
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

        let long_key1 = format!("keys-{}-test1", "a".repeat(150));
        let long_key2 = format!("keys-{}-test2", "a".repeat(150));
        let norm1 = normalize_key(&long_key1);
        let norm2 = normalize_key(&long_key2);
        assert_eq!(norm1.len(), 127);
        assert_eq!(norm2.len(), 127);
        assert_ne!(
            norm1, norm2,
            "Distinct long keys sharing a prefix must not collide"
        );
    }
}
