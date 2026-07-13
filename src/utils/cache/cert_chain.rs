use std::{sync::Arc, time::Duration};

use moka::future::Cache;

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
#[derive(Clone)]
pub(crate) struct CertChainCache {
    inner: Cache<String, CertificateChain>,
    // Pre-resolved handles so per-call counter increments don't repeat the
    // recorder lookup or allocate label strings on the hot path.
    hit_counter: metrics::Counter,
    miss_counter: metrics::Counter,
    replacement_counter: metrics::Counter,
}

impl CertChainCache {
    /// Construct a `CertChainCache`.
    ///
    /// `domain` is used as the value of the `domain` label on every emitted
    /// counter so multi-domain deployments don't aggregate blindly. Pass an
    /// empty string to opt out of the label entirely.
    pub(crate) fn new(ttl: Duration, domain: impl AsRef<str>) -> Self {
        metrics::describe_counter!(
            HIT_METRIC,
            metrics::Unit::Count,
            "Certificate chain cache hits"
        );
        metrics::describe_counter!(
            MISS_METRIC,
            metrics::Unit::Count,
            "Certificate chain cache misses"
        );
        metrics::describe_counter!(
            REPLACEMENT_METRIC,
            metrics::Unit::Count,
            "Certificate chain cache replacements (post-provisioning)"
        );

        let domain = domain.as_ref();
        let (hit_counter, miss_counter, replacement_counter) = if domain.is_empty() {
            let h = metrics::counter!(HIT_METRIC);
            let m = metrics::counter!(MISS_METRIC);
            let r = metrics::counter!(REPLACEMENT_METRIC);
            (h, m, r)
        } else {
            let h = metrics::counter!(HIT_METRIC, "domain" => domain.to_string());
            let m = metrics::counter!(MISS_METRIC, "domain" => domain.to_string());
            let r = metrics::counter!(REPLACEMENT_METRIC, "domain" => domain.to_string());
            (h, m, r)
        };
        // Zero-init so the counters appear in Prometheus before first use.
        hit_counter.increment(0);
        miss_counter.increment(0);
        replacement_counter.increment(0);

        let builder = Cache::builder().max_capacity(CACHE_CAPACITY);
        let inner = if ttl.is_zero() {
            builder.build()
        } else {
            builder.time_to_live(ttl).build()
        };
        Self {
            inner,
            hit_counter,
            miss_counter,
            replacement_counter,
        }
    }

    pub(crate) async fn get(&self, key: &str) -> Option<CertificateChain> {
        let cached = self.inner.get(key).await;
        if cached.is_some() {
            self.hit_counter.increment(1);
        } else {
            self.miss_counter.increment(1);
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
        self.replacement_counter.increment(1);
        self.inner.insert(key, value).await;
    }

    #[cfg(test)]
    pub(crate) async fn invalidate(&self, key: &str) {
        self.inner.invalidate(key).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hit_miss_counters_increment() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let cache = CertChainCache::new(Duration::ZERO, "example.com");
                let chain: CertificateChain = Arc::from(vec!["a".to_string()]);
                cache.insert("k".to_string(), chain).await;
                assert!(cache.get("k").await.is_some());
                assert!(cache.get("missing").await.is_none());
            });
        });

        let snapshot = snapshotter.snapshot().into_hashmap();
        let mut hits = 0u64;
        let mut misses = 0u64;
        let mut replacements = 0u64;
        for (composite_key, (_, _, debug_value)) in &snapshot {
            let name = composite_key.key().name();
            match (name, debug_value) {
                (HIT_METRIC, DebugValue::Counter(c)) => hits = *c,
                (MISS_METRIC, DebugValue::Counter(c)) => misses = *c,
                (REPLACEMENT_METRIC, DebugValue::Counter(c)) => replacements = *c,
                _ => {}
            }
        }
        assert_eq!(hits, 1, "exactly one hit expected");
        assert_eq!(misses, 1, "exactly one miss expected");
        assert_eq!(replacements, 0, "zero replacements yet");
    }
}
