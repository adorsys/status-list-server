//! In-process status-list cache adapter.
use async_trait::async_trait;
use moka::future::Cache as MokaCache;
use std::time::Duration;

use crate::{
    domain::{self, StatusListRecord},
    ports::{PortError, StatusListCache},
};

#[derive(Clone)]
pub struct MokaStatusListCache {
    inner: MokaCache<String, StatusListRecord>,
}

impl MokaStatusListCache {
    pub fn new(ttl_secs: u64, max_capacity: u64) -> Self {
        if ttl_secs == 0 {
            tracing::info!("Cache disabled (TTL=0)");
        }
        let inner = MokaCache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(max_capacity)
            .build();
        Self { inner }
    }
}

#[async_trait]
impl StatusListCache for MokaStatusListCache {
    async fn get(&self, key: &str) -> Result<Option<domain::StatusListRecord>, PortError> {
        Ok(self.inner.get(key).await)
    }

    async fn put(&self, record: domain::StatusListRecord) -> Result<(), PortError> {
        self.inner.insert(record.list_id.clone(), record).await;
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<(), PortError> {
        self.inner.invalidate(key).await;
        Ok(())
    }
}
