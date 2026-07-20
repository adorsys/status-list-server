use moka::future::Cache as MokaCache;
use std::{sync::Arc, time::Duration};

use crate::models::StatusListRecord;

#[derive(Clone)]
pub struct StatusListCache {
    inner: MokaCache<String, Arc<StatusListRecord>>,
}

impl StatusListCache {
    /// Creates a new status-list cache with a time-to-live (TTL) setting.
    ///
    /// # TTL Semantics
    /// A value of `ttl_secs = 0` **disables caching**: entries expire immediately and all reads
    /// fall through to the underlying storage. This is consistent with other cache implementations
    /// in the application ([`CertChainCache`](super::CertChainCache) and
    /// [`Redis`](crate::cert_manager::storage::Redis) for certificates).
    ///
    /// # Parameters
    /// * `ttl_secs` - Time-to-live in seconds (0 = disabled, >0 = cache enabled with that TTL)
    /// * `max_capacity` - Maximum number of entries to cache
    pub fn new(ttl_secs: u64, max_capacity: u64) -> Self {
        if ttl_secs == 0 {
            tracing::info!("Status-list cache TTL=0: entries expire immediately");
        }
        let builder = MokaCache::builder().max_capacity(max_capacity);
        let inner = builder.time_to_live(Duration::from_secs(ttl_secs)).build();
        Self { inner }
    }

    pub async fn get(&self, key: &str) -> Option<Arc<StatusListRecord>> {
        self.inner.get(key).await
    }

    pub async fn insert(&self, key: String, value: impl Into<Arc<StatusListRecord>>) {
        self.inner.insert(key, value.into()).await;
    }

    pub async fn invalidate(&self, key: &str) {
        self.inner.invalidate(key).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{StatusList, StatusListRecord};

    fn sample_record(id: &str) -> StatusListRecord {
        StatusListRecord {
            list_id: id.to_string(),
            issuer: "issuer".to_string(),
            sub: "sub".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "test".to_string(),
            },
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn cache_enabled_works() {
        let cache = StatusListCache::new(60, 10);
        let record = sample_record("list-1");
        cache.insert("list-1".to_string(), record.clone()).await;
        assert!(cache.get("list-1").await.is_some());
    }

    #[tokio::test]
    async fn cache_disabled_returns_none() {
        let cache = StatusListCache::new(0, 10);
        cache
            .insert("list-1".to_string(), sample_record("list-1"))
            .await;
        assert!(cache.get("list-1").await.is_none());
    }
}
