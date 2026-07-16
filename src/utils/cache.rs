use moka::future::Cache as MokaCache;
use std::time::Duration;

use crate::models::StatusListRecord;

#[derive(Clone)]
pub(crate) struct Cache {
    inner: MokaCache<String, StatusListRecord>,
}

impl Cache {
    /// Creates a cache; TTL=0 disables it naturally.
    pub(crate) fn new(ttl_secs: u64, max_capacity: u64) -> Self {
        if ttl_secs == 0 {
            tracing::info!("Cache disabled (TTL=0)");
        }
        let inner = MokaCache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(max_capacity)
            .build();
        Self { inner }
    }

    pub(crate) async fn get(&self, key: &str) -> Option<StatusListRecord> {
        self.inner.get(key).await
    }

    pub(crate) async fn insert(&self, key: String, value: StatusListRecord) {
        self.inner.insert(key, value).await;
    }

    pub(crate) async fn invalidate(&self, key: &str) {
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
        let cache = Cache::new(60, 10);
        let record = sample_record("list-1");
        cache.insert("list-1".to_string(), record.clone()).await;
        assert!(cache.get("list-1").await.is_some());
    }

    #[tokio::test]
    async fn cache_disabled_returns_none() {
        let cache = Cache::new(0, 10);
        cache
            .insert("list-1".to_string(), sample_record("list-1"))
            .await;
        assert!(cache.get("list-1").await.is_none());
    }
}
