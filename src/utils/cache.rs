use moka::future::Cache as MokaCache;
use std::time::Duration;

use crate::models::StatusListRecord;
use crate::{
    domain,
    ports::{PortError, StatusListCache},
};
use async_trait::async_trait;

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

#[async_trait]
impl StatusListCache for Cache {
    async fn get(&self, key: &str) -> Result<Option<domain::StatusListRecord>, PortError> {
        Ok(self.get(key).await.map(|record| domain::StatusListRecord {
            list_id: record.list_id,
            issuer: domain::Issuer(record.issuer),
            status_list: domain::StatusList {
                bits: record.status_list.bits,
                lst: record.status_list.lst,
            },
            sub: record.sub,
        }))
    }

    async fn put(&self, record: domain::StatusListRecord) -> Result<(), PortError> {
        self.insert(
            record.list_id.clone(),
            StatusListRecord {
                list_id: record.list_id,
                issuer: record.issuer.0,
                status_list: crate::models::StatusList {
                    bits: record.status_list.bits,
                    lst: record.status_list.lst,
                },
                sub: record.sub,
            },
        )
        .await;
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<(), PortError> {
        self.invalidate(key).await;
        Ok(())
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
