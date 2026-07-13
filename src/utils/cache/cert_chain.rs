use std::{sync::Arc, time::Duration};

use moka::future::Cache;

pub type CertificateChain = Arc<[String]>;

// One CertManager serves a single TLD+1, so only one chain is ever cached.
const CACHE_CAPACITY: u64 = 1;
const HIT_METRIC: &str = "certificate_chain_cache_hits_total";
const MISS_METRIC: &str = "certificate_chain_cache_misses_total";
const REPLACEMENT_METRIC: &str = "certificate_chain_cache_replacements_total";

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

    /// Replace the cached entry for `key` with `value`.
    ///
    /// Used after a new certificate is provisioned so the next read returns
    /// the fresh chain without an extra storage load and parse.
    pub async fn replace(&self, key: String, value: CertificateChain) {
        metrics::counter!(REPLACEMENT_METRIC).increment(1);
        self.inner.insert(key, value).await;
    }

    #[cfg(test)]
    pub async fn invalidate(&self, key: &str) {
        self.inner.invalidate(key).await;
    }
}
