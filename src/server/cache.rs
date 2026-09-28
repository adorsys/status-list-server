use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use moka::future::Cache as MokaCache;
use opentelemetry::{
    metrics::Counter,
    {KeyValue, global},
};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::OwnedMutexGuard;

const HIT_METRIC: &str = "token_bytes_cache_hits";
const MISS_METRIC: &str = "token_bytes_cache_misses";

/// Cache-hit/miss SLI counters for the signed-token bytes cache.
///
/// Handles are resolved through [`crate::utils::metrics::cached_instruments`]
/// so a fresh global meter provider (e.g. a re-run of `setup_metrics` in tests)
/// never leaves stale no-op handles, matching the pattern used by
/// `outbound::cache` and `utils::cache::cert_chain`.
#[derive(Clone)]
struct TokenCacheMetrics {
    hits: Counter<u64>,
    misses: Counter<u64>,
}

fn token_cache_metrics() -> TokenCacheMetrics {
    static METRICS: std::sync::OnceLock<std::sync::Mutex<Option<(u64, TokenCacheMetrics)>>> =
        std::sync::OnceLock::new();
    crate::utils::metrics::cached_instruments(&METRICS, || {
        let meter = global::meter("status-list-server");
        TokenCacheMetrics {
            hits: meter
                .u64_counter(HIT_METRIC)
                .with_description("Signed status-list token bytes cache hits")
                .build(),
            misses: meter
                .u64_counter(MISS_METRIC)
                .with_description("Signed status-list token bytes cache misses")
                .build(),
        }
    })
}

/// The gzip state of a cached representation. Only JWT output is ever
/// gzip-compressed; CWT is always stored raw, so this is a plain boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TokenEncoding {
    Identity,
    Gzip,
}

/// One cached signed representation: the served opaque bytes plus the
/// `Content-Encoding` they were produced with (feeds the response header).
///
/// The bytes are stored as [`Bytes`] so a cache hit can be moved straight into
/// an Axum response body without copying the (potentially large) representation.
#[derive(Debug, Clone)]
pub(crate) struct CachedToken {
    pub(crate) bytes: Bytes,
    pub(crate) encoding: Option<&'static str>,
}

/// The typed identity of a cached signed representation.
///
/// Every field is a distinct cache-key dimension: the list and its content hash
/// pin the payload, the signer fingerprint pins the signing material, and the
/// window/format/encoding/aggregation/ttl/exp dimensions pin the HTTP
/// representation. Using a hashable value type instead of a delimiter-encoded
/// string keeps the dimensions typed and lets the cache stay independent of the
/// signing-material type that produced the fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TokenCacheKey {
    pub(crate) list_id: String,
    pub(crate) content_hash: String,
    pub(crate) signer_fingerprint: String,
    pub(crate) window_start: i64,
    pub(crate) format: String,
    pub(crate) encoding: TokenEncoding,
    pub(crate) aggregation_uri: String,
    pub(crate) token_ttl_secs: u64,
    pub(crate) token_exp_secs: u64,
}

/// An in-memory cache of fully signed, serialised status-list token bytes.
///
/// Entries are keyed by `TokenCacheKey` and are valid for exactly the anchored
/// token window `[window_start, window_start + exp_secs)`. Because `iat` is
/// anchored to `window_start`, the bytes are identical for every request in the
/// same window, so the cache lets a fresh `200` reuse a single sign per
/// `(list, window, format)` per replica.
///
/// Content changes and list identity are covered by the key: a changed list has
/// a different content hash (immediate miss), and `list_id` keeps otherwise
/// identical `(content, window, format)` values from different lists distinct.
/// Signing-key rotation and certificate renewal are covered by the signer
/// fingerprint, so a rotated key immediately misses and re-signs with the new
/// key. Expiry is covered by the window bound checked at lookup time plus moka's
/// `time_to_live`, so no eager invalidation is needed.
///
/// Per-replica by design: ETag consistency across replicas is out of scope and
/// would require a shared store (see the ticket's open questions).
#[derive(Clone, Debug)]
pub struct TokenBytesCache {
    inner: MokaCache<TokenCacheKey, CachedToken>,
    /// Per-key in-flight locks that serialize the expensive re-sign path so that
    /// concurrent misses for the same key build the token only once (single
    /// flight). Steady-state hits take the lock-free fast path in
    /// [`TokenBytesCache::get_or_build`], so this only ever contends during a
    /// genuine miss.
    inflight: Arc<Inflight>,
}

/// Per-key single-flight lock registry.
///
/// Each live entry is an `Arc<AsyncMutex<()>>` retained by this map *and* by
/// every waiter currently holding or awaiting the lock. The entry is removed
/// only once the last waiter for that key releases its guard, so a key can
/// never be reclaimed — and a second, fresh mutex created — while a build is
/// still in flight. This is what preserves the one-build-per-key guarantee even
/// when many distinct keys (and hence many in-flight locks) are churned
/// concurrently. Using a capacity-bounded cache here would be incorrect: it
/// could evict a key while its builder still holds the mutex, letting a later
/// miss acquire a different mutex and perform a second sign for the same token.
#[derive(Debug)]
struct Inflight {
    locks: Mutex<HashMap<TokenCacheKey, Arc<AsyncMutex<()>>>>,
}

impl Inflight {
    fn new() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Acquire the per-key serialization lock, registering `key` so concurrent
    /// callers share the same mutex. The returned guard removes the map entry
    /// when the last waiter for `key` drops it.
    async fn lock(self: &Arc<Self>, key: &TokenCacheKey) -> InflightGuard {
        let arc = {
            let mut locks = self.locks.lock().unwrap();
            locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let guard = arc.clone().lock_owned().await;
        InflightGuard {
            inflight: Arc::clone(self),
            key: key.clone(),
            guard,
        }
    }
}

/// RAII guard that releases a per-key single-flight lock and reclaims the map
/// entry once this is the last waiter for the key.
struct InflightGuard {
    inflight: Arc<Inflight>,
    key: TokenCacheKey,
    guard: tokio::sync::OwnedMutexGuard<()>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // `guard` owns one strong reference to the lock's Arc; the map entry
        // owns another while present. If this guard is the only holder besides
        // the map entry (strong_count == 2), no other waiter is using the lock,
        // so remove the entry to reclaim memory. New waiters clone the Arc
        // while holding the map lock, so they are accounted for here and never
        // observe a half-reclaimed entry.
        if Arc::strong_count(OwnedMutexGuard::<()>::mutex(&self.guard)) == 2 {
            let mut locks = self.inflight.locks.lock().unwrap();
            if let Some(entry) = locks.get(&self.key)
                && Arc::ptr_eq(entry, OwnedMutexGuard::<()>::mutex(&self.guard))
            {
                locks.remove(&self.key);
            }
        }
    }
}

impl TokenBytesCache {
    /// Build an in-process signed-token bytes cache.
    ///
    /// `ttl_secs` bounds how long an entry may be retained by moka in addition
    /// to its window-based validity; `max_capacity` bounds memory for large
    /// lists. A `ttl_secs` of `0` preserves the "cache disabled" semantics used
    /// elsewhere in this codebase (`MokaStatusListCache`): entries expire
    /// immediately and every request re-signs. Configuration validation ensures
    /// a non-zero `ttl_secs` is at least `token_exp_secs`, so an entry is never
    /// evicted in the middle of a validity window.
    pub(crate) fn new(ttl_secs: u64, max_capacity: u64) -> Self {
        if ttl_secs == 0 {
            tracing::info!("Signed-token bytes cache disabled (TTL=0)");
        }
        let inner = MokaCache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(max_capacity)
            .build();
        let inflight = Arc::new(Inflight::new());
        Self { inner, inflight }
    }

    /// Return cached bytes for `key`, only for an entry whose anchored window
    /// `[window_start, window_start + exp_secs)` still contains `now`. Past that
    /// bound the bytes are expired and must be re-signed.
    ///
    /// Unlike a plain lookup, a miss is not simply reported: `init` is invoked
    /// to build the token, deduplicated through a per-key in-flight lock so at
    /// most one builder runs per `key` under concurrency (the "single sign per
    /// window per replica" guarantee). Callers that are not interested in
    /// building should use `get` instead.
    ///
    /// Returns `Ok(None)` when the window is already closed (the bytes are not
    /// cached and `init` is *not* called); the caller must re-sign with a fresh
    /// window. Returns `Ok(Some(_))` on a hit or a successful build, and
    /// `Err(e)` if `init` fails (nothing is cached on error).
    pub(crate) async fn get_or_build<F, Fut, E>(
        &self,
        key: &TokenCacheKey,
        window_start: i64,
        exp_secs: i64,
        now: i64,
        init: F,
    ) -> Result<Option<CachedToken>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<CachedToken, E>>,
    {
        // Guard the window bound explicitly so a closed window never serves
        // bytes beyond their `exp` even before moka's own TTL fires.
        if now < window_start || now >= window_start.saturating_add(exp_secs) {
            token_cache_metrics()
                .misses
                .add(1, &[KeyValue::new("cache", "token_bytes")]);
            return Ok(None);
        }

        let metrics = token_cache_metrics();

        // Lock-free fast path: the value is already cached.
        if let Some(cached) = self.inner.get(key).await {
            metrics
                .hits
                .add(1, &[KeyValue::new("cache", "token_bytes")]);
            return Ok(Some(cached));
        }

        // Slow path: serialize re-signs for this key so concurrent misses build
        // exactly once. The per-key lock is retained until the last waiter has
        // left, so it can never be reclaimed mid-build (see [`Inflight`]).
        let _guard = self.inflight.lock(key).await;

        // Double-checked lookup: another caller may have built the token while
        // we waited for the lock.
        if let Some(cached) = self.inner.get(key).await {
            metrics
                .hits
                .add(1, &[KeyValue::new("cache", "token_bytes")]);
            return Ok(Some(cached));
        }

        // We are the elected builder.
        metrics
            .misses
            .add(1, &[KeyValue::new("cache", "token_bytes")]);
        let value = init().await?;
        self.inner.insert(key.clone(), value.clone()).await;
        Ok(Some(value))
    }

    /// Look up cached bytes for `key`, only returning a hit for an entry whose
    /// anchored window `[window_start, window_start + exp_secs)` still contains
    /// `now`. Past that bound the bytes are expired and must be re-signed.
    ///
    /// Test helper: the serving path uses [`TokenBytesCache::get_or_build`].
    #[cfg(test)]
    pub(crate) async fn get(
        &self,
        key: &TokenCacheKey,
        window_start: i64,
        exp_secs: i64,
        now: i64,
    ) -> Option<CachedToken> {
        if now < window_start || now >= window_start.saturating_add(exp_secs) {
            token_cache_metrics()
                .misses
                .add(1, &[KeyValue::new("cache", "token_bytes")]);
            return None;
        }
        let cached = self.inner.get(key).await;
        let metrics = token_cache_metrics();
        if cached.is_some() {
            metrics
                .hits
                .add(1, &[KeyValue::new("cache", "token_bytes")]);
        } else {
            metrics
                .misses
                .add(1, &[KeyValue::new("cache", "token_bytes")]);
        }
        cached
    }

    #[cfg(test)]
    pub(crate) async fn insert(&self, key: TokenCacheKey, value: CachedToken) {
        self.inner.insert(key, value).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{TelemetryConfig, TelemetryEnvironment},
        utils::metrics::{metrics_test_lock, setup_metrics},
    };
    use opentelemetry_sdk::Resource;
    use prometheus::{Encoder, Registry, TextEncoder};

    /// A default test key at window `w`, overridable per dimension via struct
    /// update syntax.
    fn base_key(w: i64) -> TokenCacheKey {
        TokenCacheKey {
            list_id: "list".to_string(),
            content_hash: "hash".to_string(),
            signer_fingerprint: "signer".to_string(),
            window_start: w,
            format: "jwt".to_string(),
            encoding: TokenEncoding::Identity,
            aggregation_uri: String::new(),
            token_ttl_secs: 300,
            token_exp_secs: 900,
        }
    }

    async fn cached(w: i64) -> (TokenBytesCache, TokenCacheKey) {
        let cache = TokenBytesCache::new(300, 100);
        let key = base_key(w);
        cache
            .insert(
                key.clone(),
                CachedToken {
                    bytes: Bytes::from(vec![1, 2, 3]),
                    encoding: None,
                },
            )
            .await;
        (cache, key)
    }

    #[tokio::test]
    async fn hit_within_window() {
        let (cache, key) = cached(1000).await;
        assert!(cache.get(&key, 1000, 900, 1400).await.is_some());
    }

    #[tokio::test]
    async fn miss_after_window_expires() {
        // now == window_start + exp -> beyond exp, must be a miss even though the
        // value is still retained by moka.
        let (cache, key) = cached(1000).await;
        assert!(cache.get(&key, 1000, 900, 1900).await.is_none());
    }

    #[tokio::test]
    async fn get_or_build_single_flights_concurrent_misses() {
        // At most one signing operation per (list, window, format) per replica.
        // N concurrent misses for the same key must run the builder exactly once
        // and share the resulting bytes.
        let cache = TokenBytesCache::new(300, 100);
        let key = base_key(1000);

        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let key = key.clone();
            let builds = builds.clone();
            handles.push(tokio::spawn(async move {
                let out = cache
                    .get_or_build(&key, 1000, 900, 1400, || {
                        let builds = builds.clone();
                        async move {
                            builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(CachedToken {
                                bytes: Bytes::from(vec![7u8, 8, 9]),
                                encoding: None,
                            })
                        }
                    })
                    .await
                    .expect("infallible");
                out.expect("window open, so Some")
            }));
        }
        for h in handles {
            let val = h.await.expect("task");
            assert_eq!(*val.bytes, vec![7u8, 8, 9]);
        }
        assert_eq!(
            builds.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "concurrent misses must run the builder exactly once (single flight)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn get_or_build_single_flights_under_lock_churn() {
        // Regression guard for the lock-registry design: with a capacity-bounded
        // cache as the lock registry, many distinct keys (each miss holding its
        // own in-flight lock) could evict the lock for another key that is still
        // mid-build, letting a later miss create a second mutex and run a second
        // build for the same key. The ref-counted registry must retain each
        // key's lock until its last waiter leaves, so a target key is still
        // built exactly once even while the map is churned by unrelated keys.
        let cache = TokenBytesCache::new(300, 100);

        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // One target key whose single-build guarantee we must preserve.
        let target_key = TokenCacheKey {
            list_id: "target-list".to_string(),
            ..base_key(1000)
        };

        // Many distinct keys whose concurrent misses churn the lock registry
        // and the data cache simultaneously with the target's own concurrent
        // misses.
        let target_clones: Vec<_> = (0..16)
            .map(|_| (cache.clone(), target_key.clone()))
            .collect();
        let churn_keys: Vec<_> = (0..64)
            .map(|i| TokenCacheKey {
                list_id: format!("list-{i}"),
                ..base_key(1000)
            })
            .collect();

        let mut handles = Vec::new();

        for (cache, k) in target_clones {
            let builds = builds.clone();
            handles.push(tokio::spawn(async move {
                let out = cache
                    .get_or_build(&k, 1000, 900, 1400, || {
                        let builds = builds.clone();
                        async move {
                            builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(CachedToken {
                                bytes: Bytes::from(vec![7u8, 8, 9]),
                                encoding: None,
                            })
                        }
                    })
                    .await
                    .expect("infallible");
                out.expect("window open, so Some")
            }));
        }

        for k in churn_keys {
            let cache = cache.clone();
            handles.push(tokio::spawn(async move {
                let out = cache
                    .get_or_build(&k, 1000, 900, 1400, || async {
                        Ok::<_, std::convert::Infallible>(CachedToken {
                            bytes: Bytes::from(vec![1u8, 2, 3]),
                            encoding: None,
                        })
                    })
                    .await
                    .expect("infallible");
                out.expect("window open, so Some")
            }));
        }

        for h in handles {
            h.await.expect("task");
        }

        assert_eq!(
            builds.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the target key must be built exactly once even while other keys churn the lock registry"
        );
    }

    #[tokio::test]
    async fn key_dimensions_are_distinct() {
        let base = base_key(1000);
        let other_window = TokenCacheKey {
            window_start: 1001,
            ..base.clone()
        };
        let other_signer = TokenCacheKey {
            signer_fingerprint: "signer2".to_string(),
            ..base.clone()
        };
        let other_format = TokenCacheKey {
            format: "cwt".to_string(),
            ..base.clone()
        };
        let other_gzip = TokenCacheKey {
            encoding: TokenEncoding::Gzip,
            ..base.clone()
        };
        let other_list = TokenCacheKey {
            list_id: "list2".to_string(),
            ..base.clone()
        };
        let other_aggregation = TokenCacheKey {
            aggregation_uri: "https://agg".to_string(),
            ..base.clone()
        };
        let other_ttl = TokenCacheKey {
            token_ttl_secs: 600,
            ..base.clone()
        };
        let other_exp = TokenCacheKey {
            token_exp_secs: 1200,
            ..base.clone()
        };

        assert_ne!(base, other_window);
        assert_ne!(base, other_signer);
        assert_ne!(base, other_format);
        assert_ne!(base, other_gzip);
        assert_ne!(base, other_list);
        assert_ne!(
            base, other_aggregation,
            "aggregation_uri must be in the key"
        );
        assert_ne!(base, other_ttl, "token_ttl_secs must be in the key");
        assert_ne!(base, other_exp, "token_exp_secs must be in the key");
        assert_eq!(base, base_key(1000));
    }

    #[test]
    fn cache_counts_hits_and_misses_are_exported() {
        let _metrics_guard = metrics_test_lock();
        let registry = Registry::new();
        let config = TelemetryConfig {
            environment: TelemetryEnvironment::Development,
            otlp_endpoint: "http://localhost:4317".to_string(),
            sampler_ratio: 1.0,
            enabled: false,
        };
        let _meter_provider = setup_metrics(
            &registry,
            &config,
            Resource::builder()
                .with_service_name("status-list-server-test")
                .build(),
        )
        .expect("metrics setup");

        let cache = TokenBytesCache::new(300, 100);
        let cache_key = TokenCacheKey {
            list_id: "l".to_string(),
            content_hash: "h".to_string(),
            signer_fingerprint: "s".to_string(),
            ..base_key(1000)
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            cache
                .insert(
                    cache_key.clone(),
                    CachedToken {
                        bytes: Bytes::from(vec![1]),
                        encoding: None,
                    },
                )
                .await;
            assert!(cache.get(&cache_key, 1000, 900, 1400).await.is_some());
            assert!(cache.get(&cache_key, 1000, 900, 1400).await.is_some()); // hit again
            assert!(cache.get(&base_key(1000), 1000, 900, 1400).await.is_none());
        });

        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buffer)
            .expect("encode metrics");
        let body = String::from_utf8(buffer).expect("metrics are valid UTF-8");
        for metric in [HIT_METRIC, MISS_METRIC] {
            let sample = format!(
                r#"{metric}_total{{cache="token_bytes",otel_scope_name="status-list-server"}}"#
            );
            assert!(
                body.contains(&sample),
                "missing metric series {sample}; body:\n{body}"
            );
        }
    }
}
