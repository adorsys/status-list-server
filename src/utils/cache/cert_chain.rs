use std::{sync::Arc, time::Duration};

use moka::future::Cache;
use opentelemetry::{
    metrics::Counter,
    {KeyValue, global},
};

pub(crate) type CertificateChain = Arc<[String]>;

// One CertManager serves a single TLD+1, so only one chain is ever cached.
const CACHE_CAPACITY: u64 = 1;
const HIT_METRIC: &str = "certificate_chain_cache_hits_total";
const MISS_METRIC: &str = "certificate_chain_cache_misses_total";
const REPLACEMENT_METRIC: &str = "certificate_chain_cache_replacements_total";

/// An in-memory cache of type [`CertificateChain`] keyed by the cert storage
/// key (`cert_key`). One [`CertManager`](crate::cert_manager::CertManager)
/// instance owns exactly one `CertChainCache`, so the cache holds at most one
/// entry per running process.
///
/// # TTL semantics
///
/// A **zero** TTL (`Duration::ZERO`) keeps the cache active with **no expiry**;
/// entries persist until explicitly replaced by the provisioning hook.
///
/// This intentionally differs from [`StatusListCache`](crate::ports::StatusListCache),
/// where `ttl = 0` **disables** the cache entirely (inserts expire immediately).
/// The rationale is that certificate chains only change when explicitly provisioned,
/// making the "never expire" behavior safe for single-replica deployments.
#[derive(Clone)]
pub(crate) struct CertChainCache {
    inner: Cache<String, CertificateChain>,
    /// Domain label attached to every emitted counter. Empty string means
    /// "no label".
    domain_label: String,
    hit_counter: Counter<u64>,
    miss_counter: Counter<u64>,
    replacement_counter: Counter<u64>,
}

impl CertChainCache {
    /// Construct a `CertChainCache`.
    ///
    /// `domain` is used as the value of the `domain` label on every emitted
    /// counter so multi-domain deployments don't aggregate blindly. Pass an
    /// empty string to opt out of the label entirely.
    ///
    /// Counters are created eagerly from the OpenTelemetry global meter
    /// provider. If no provider is installed yet, the no-op meter is used
    /// and counters become live once the real provider is set.
    pub(crate) fn new(ttl: Duration, domain: impl AsRef<str>) -> Self {
        let meter = global::meter("status-list-server");

        let hit_counter = meter
            .u64_counter(HIT_METRIC)
            .with_description("Certificate chain cache hits")
            .build();
        let miss_counter = meter
            .u64_counter(MISS_METRIC)
            .with_description("Certificate chain cache misses")
            .build();
        let replacement_counter = meter
            .u64_counter(REPLACEMENT_METRIC)
            .with_description("Certificate chain cache replacements (post-provisioning)")
            .build();

        let builder = Cache::builder().max_capacity(CACHE_CAPACITY);
        let inner = if ttl.is_zero() {
            tracing::warn!(
                "chain_cache_ttl=0: chain cached for process lifetime; \
                renewals on other replicas will not be observed"
            );
            builder.build()
        } else {
            builder.time_to_live(ttl).build()
        };
        Self {
            inner,
            domain_label: domain.as_ref().to_string(),
            hit_counter,
            miss_counter,
            replacement_counter,
        }
    }

    /// Zero-initialise all counters so they appear in Prometheus scrapes
    /// before first use. With OpenTelemetry counters this is a no-op since
    /// the meter automatically registers instruments, but we keep the method
    /// for API compatibility.
    pub(crate) fn init_counters(&self) {
        // OTel counters are registered on creation; adding 0 ensures they
        // appear in the first scrape.
        self.hit_counter.add(0, &self.attributes());
        self.miss_counter.add(0, &self.attributes());
        self.replacement_counter.add(0, &self.attributes());
    }

    pub(crate) async fn get(&self, key: &str) -> Option<CertificateChain> {
        let cached = self.inner.get(key).await;
        if cached.is_some() {
            self.hit_counter.add(1, &self.attributes());
        } else {
            self.miss_counter.add(1, &self.attributes());
        }
        cached
    }

    pub(crate) async fn insert(&self, key: String, value: CertificateChain) {
        self.inner.insert(key, value).await;
    }

    /// Replace the cached entry for `key` with `value`.
    ///
    /// Used after a new certificate is provisioned so the next read returns
    /// the fresh chain without an extra storage load and parse.
    pub(crate) async fn replace(&self, key: String, value: CertificateChain) {
        self.replacement_counter.add(1, &self.attributes());
        self.inner.insert(key, value).await;
    }

    #[cfg(test)]
    pub(crate) async fn invalidate(&self, key: &str) {
        self.inner.invalidate(key).await;
    }

    fn attributes(&self) -> Vec<KeyValue> {
        if self.domain_label.is_empty() {
            vec![]
        } else {
            vec![KeyValue::new("domain", self.domain_label.clone())]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_counters_work_with_otel() {
        // Verifies counters work when cache is constructed (mirrors production
        // ordering where the cache is built before telemetry is fully wired).

        let cache = CertChainCache::new(Duration::ZERO, "example.com");

        let chain: CertificateChain = Arc::from(vec!["a".to_string()]);
        cache.insert("k".to_string(), chain.clone()).await;

        // hit
        assert!(cache.get("k").await.is_some());
        // miss
        assert!(cache.get("missing").await.is_none());
        // replacement
        let new_chain: CertificateChain = Arc::from(vec!["b".to_string()]);
        cache.replace("k".to_string(), new_chain).await;

        // With the no-op meter (no global provider installed in tests),
        // counters silently discard values. The test verifies the code
        // compiles and runs without panicking.
    }
}
