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
///
/// # TTL semantics
///
/// A **zero** TTL (`Duration::ZERO`) keeps the cache active with **no expiry**;
/// entries persist until explicitly replaced by the provisioning hook.
///
/// This intentionally differs from [`StatusListCache`](super::StatusListCache),
/// where `ttl = 0` **disables** the cache entirely. The rationale is that
/// certificate chains only change when explicitly provisioned, making the
/// "never expire" behavior safe for single-replica deployments.
///
/// # Configuration Note
///
/// Operators who want caching disabled for certificate chains should use a large
/// TTL value (e.g., `u64::MAX` for effectively permanent caching) rather than 0.
/// See [`CertConfig::chain_cache_ttl`](crate::config::CertConfig::chain_cache_ttl) for configuration.
#[derive(Clone)]
pub(crate) struct CertChainCache {
    inner: Cache<String, CertificateChain>,
    /// Domain label attached to every emitted counter.  Empty string means
    /// "no label".
    domain_label: String,
}

impl CertChainCache {
    /// Construct a `CertChainCache`.
    ///
    /// `domain` is used as the value of the `domain` label on every emitted
    /// counter so multi-domain deployments don't aggregate blindly. Pass an
    /// empty string to opt out of the label entirely.
    ///
    /// Counter descriptions are registered eagerly so they appear in
    /// Prometheus immediately, but the counter handles themselves are resolved
    /// lazily on each `get`/`replace` call. This makes the cache safe to
    /// construct before the global metrics recorder is installed.
    pub(crate) fn new(ttl: Duration, domain: impl AsRef<str>) -> Self {
        // Describe counters — these are idempotent and safe to call before
        // a recorder is installed (descriptions are buffered).
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

        let builder = Cache::builder().max_capacity(CACHE_CAPACITY);
        let inner = if ttl.is_zero() {
            builder.build()
        } else {
            builder.time_to_live(ttl).build()
        };
        Self {
            inner,
            domain_label: domain.as_ref().to_string(),
        }
    }

    /// Zero-initialise all counters so they appear in Prometheus scrapes
    /// before first use. **Must** be called after the global metrics recorder
    /// has been installed.
    pub(crate) fn init_counters(&self) {
        self.hit_counter().increment(0);
        self.miss_counter().increment(0);
        self.replacement_counter().increment(0);
    }

    pub(crate) async fn get(&self, key: &str) -> Option<CertificateChain> {
        let cached = self.inner.get(key).await;
        if cached.is_some() {
            self.hit_counter().increment(1);
        } else {
            self.miss_counter().increment(1);
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
        self.replacement_counter().increment(1);
        self.inner.insert(key, value).await;
    }

    #[cfg(test)]
    pub(crate) async fn invalidate(&self, key: &str) {
        self.inner.invalidate(key).await;
    }

    // -- private helpers for lazy counter resolution --------------------------

    fn hit_counter(&self) -> metrics::Counter {
        if self.domain_label.is_empty() {
            metrics::counter!(HIT_METRIC)
        } else {
            metrics::counter!(HIT_METRIC, "domain" => self.domain_label.clone())
        }
    }

    fn miss_counter(&self) -> metrics::Counter {
        if self.domain_label.is_empty() {
            metrics::counter!(MISS_METRIC)
        } else {
            metrics::counter!(MISS_METRIC, "domain" => self.domain_label.clone())
        }
    }

    fn replacement_counter(&self) -> metrics::Counter {
        if self.domain_label.is_empty() {
            metrics::counter!(REPLACEMENT_METRIC)
        } else {
            metrics::counter!(REPLACEMENT_METRIC, "domain" => self.domain_label.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mimics production ordering: the cache is constructed **before** the
    /// metrics recorder is installed. Counters must still land because they
    /// are resolved lazily on each `get`/`replace` call.
    #[test]
    fn test_counters_work_when_cache_constructed_before_recorder() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        // 1. Build the cache WITHOUT a recorder — mirrors build_state().
        let cache = CertChainCache::new(Duration::ZERO, "example.com");

        // 2. Install a recorder — mirrors attach_metrics() in HttpServer::new().
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let chain: CertificateChain = Arc::from(vec!["a".to_string()]);
                cache.insert("k".to_string(), chain.clone()).await;

                // hit
                assert!(cache.get("k").await.is_some());
                // miss
                assert!(cache.get("missing").await.is_none());
                // replacement
                let new_chain: CertificateChain = Arc::from(vec!["b".to_string()]);
                cache.replace("k".to_string(), new_chain).await;
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
        assert_eq!(replacements, 1, "exactly one replacement expected");
    }
}
