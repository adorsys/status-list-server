use moka::future::Cache as MokaCache;
use std::{sync::Arc, time::Duration};

use crate::models::StatusListRecord;

#[derive(Clone)]
pub struct StatusListCache {
    inner: MokaCache<String, Arc<StatusListRecord>>,
}

impl StatusListCache {
    /// Creates a cache.
    ///
    /// A **zero** TTL (`ttl_secs = 0`) keeps the cache active with **no
    /// expiry**; entries persist until explicitly invalidated. This is
    /// consistent with [`CertChainCache`](super::CertChainCache).
    pub fn new(ttl_secs: u64, max_capacity: u64) -> Self {
        if ttl_secs == 0 {
            tracing::info!("Cache TTL=0: entries will never expire (no time-based eviction)");
        }
        let builder = MokaCache::builder().max_capacity(max_capacity);
        let inner = if ttl_secs == 0 {
            builder.build()
        } else {
            builder.time_to_live(Duration::from_secs(ttl_secs)).build()
        };
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
    async fn cache_ttl_zero_means_no_expiry() {
        let cache = StatusListCache::new(0, 10);
        cache
            .insert("list-1".to_string(), sample_record("list-1"))
            .await;
        // TTL=0 means no time-based eviction — entries persist.
        assert!(cache.get("list-1").await.is_some());
    }
}
