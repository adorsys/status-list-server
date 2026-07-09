use std::{sync::Arc, time::Duration};

use moka::future::Cache;

pub type CertificateChain = Arc<[String]>;

const CACHE_CAPACITY: u64 = 16;
const HIT_METRIC: &str = "certificate_chain_cache_hits_total";
const MISS_METRIC: &str = "certificate_chain_cache_misses_total";
const INVALIDATION_METRIC: &str = "certificate_chain_cache_invalidations_total";

#[derive(Clone)]
pub struct CertChainCache {
    inner: Cache<String, CertificateChain>,
}

impl CertChainCache {
    pub fn new(ttl: Duration) -> Self {
        let builder = Cache::builder().max_capacity(CACHE_CAPACITY);
        let inner = if ttl.is_zero() {
            builder.build()
        } else {
            builder.time_to_live(ttl).build()
        };
        Self { inner }
    }

    pub async fn get(&self, key: &str) -> Option<CertificateChain> {
        let cached = self.inner.get(key).await;
        let metric = if cached.is_some() {
            HIT_METRIC
        } else {
            MISS_METRIC
        };
        metrics::counter!(metric).increment(1);
        cached
    }

    pub async fn insert(&self, key: String, value: CertificateChain) {
        self.inner.insert(key, value).await;
    }

    pub async fn update(&self, key: String, value: CertificateChain) {
        metrics::counter!(INVALIDATION_METRIC).increment(1);
        self.inner.insert(key, value).await;
    }

    #[cfg(test)]
    pub async fn invalidate(&self, key: &str) {
        metrics::counter!(INVALIDATION_METRIC).increment(1);
        self.inner.invalidate(key).await;
    }
}
