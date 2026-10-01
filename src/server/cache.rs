use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use moka::future::Cache as MokaCache;
use moka::policy::Expiry;
use opentelemetry::{
    metrics::{Counter, ObservableGauge},
    {KeyValue, global},
};

const HIT_METRIC: &str = "token_bytes_cache_hits";
const MISS_METRIC: &str = "token_bytes_cache_misses";
const ENTRY_COUNT_METRIC: &str = "token_bytes_cache_entries";
const TOTAL_BYTES_METRIC: &str = "token_bytes_cache_size";

/// Cache-hit/miss SLI counters plus size gauges for the signed-token bytes
/// cache.
///
/// Handles are resolved through [`crate::utils::metrics::cached_instruments`]
/// so a fresh global meter provider (e.g. a re-run of `setup_metrics` in tests)
/// never leaves stale no-op handles, matching the pattern used by
/// `outbound::cache` and `utils::cache::cert_chain`.
#[derive(Clone)]
struct TokenCacheMetrics {
    hits: Counter<u64>,
    misses: Counter<u64>,
    // The observable size gauges are retained only to keep them registered with
    // the meter; their values are read via their callbacks at scrape time, so
    // the fields are never dereferenced.
    #[allow(dead_code)]
    entry_count: ObservableGauge<u64>,
    #[allow(dead_code)]
    total_bytes: ObservableGauge<u64>,
}

/// The most recently built [`TokenBytesCache`], exposed to the observable size
/// gauges so they read live `entry_count`/`weighted_size` at scrape time instead
/// of depending on being refreshed on a request path. Production runs a single
/// per-replica cache, so one slot is enough; tests that build throwaway caches
/// simply overwrite it.
static SIZE_GAUGE_CACHE: std::sync::OnceLock<std::sync::Mutex<Option<TokenBytesCache>>> =
    std::sync::OnceLock::new();

fn set_size_gauge_cache(cache: TokenBytesCache) {
    let cell = SIZE_GAUGE_CACHE.get_or_init(|| std::sync::Mutex::new(None));
    let mut guard = cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(cache);
}

fn size_gauge_cache() -> Option<TokenBytesCache> {
    let cell = SIZE_GAUGE_CACHE.get_or_init(|| std::sync::Mutex::new(None));
    let guard = cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone()
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
            entry_count: meter
                .u64_observable_gauge(ENTRY_COUNT_METRIC)
                .with_description("Number of entries currently resident in the signed-token bytes cache")
                .with_callback(|observer| {
                    if let Some(cache) = size_gauge_cache() {
                        observer.observe(
                            cache.inner.entry_count(),
                            &[KeyValue::new("cache", "token_bytes")],
                        );
                    }
                })
                .build(),
            total_bytes: meter
                .u64_observable_gauge(TOTAL_BYTES_METRIC)
                .with_description("Total weighted size (bytes) currently resident in the signed-token bytes cache")
                .with_callback(|observer| {
                    if let Some(cache) = size_gauge_cache() {
                        observer.observe(
                            cache.inner.weighted_size(),
                            &[KeyValue::new("cache", "token_bytes")],
                        );
                    }
                })
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
///
/// `created_at_unix` is the wall-clock second the entry was built. The cache's
/// per-entry expiry ([`EntryExpiry`]) uses it to expire each entry at the end of
/// its own validity window, rather than on a fixed TTL.
#[derive(Debug, Clone)]
pub(crate) struct CachedToken {
    pub(crate) bytes: Bytes,
    pub(crate) encoding: Option<&'static str>,
    pub(crate) created_at_unix: i64,
}

/// The typed identity of a cached signed representation.
///
/// Every field is a distinct cache-key dimension: the list and its content hash
/// pin the payload, the signer fingerprint pins the signing material, and the
/// window/format/encoding/aggregation/ttl/exp dimensions pin the HTTP
/// representation.
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
/// Per replica and byte-bounded (`max_capacity_bytes`): each entry is weighed by
/// its byte size. Entries are keyed by `TokenCacheKey` and expire at the end of
/// their anchored window `[window_start, window_start + width)` where `width =
/// min(exp_secs - ttl_secs, ttl_secs)`, so a fresh `200` reuses one sign per
/// `(list, window, format, encoding)` per replica.
/// Concurrent misses for the same key coalesce onto one in-flight build; capacity
/// eviction can cause another sign of an unchanged, still-valid entry. Content
/// changes, signer/key rotation, and certificate renewal all change the key and
/// so immediately miss and re-sign.
#[derive(Clone, Debug)]
pub struct TokenBytesCache {
    inner: MokaCache<TokenCacheKey, CachedToken>,
}

/// The byte weight of a cached entry: its raw signed-token byte length. This is
/// what bounds memory — a count would ignore that lists range from a few hundred
/// bytes to over 1 MiB.
fn entry_weight(_key: &TokenCacheKey, value: &CachedToken) -> u32 {
    value.bytes.len() as u32
}

/// Per-entry expiry policy: each entry expires at the end of its anchored
/// validity window, independent of any global TTL. The lookup guard already
/// treats past-window entries as misses; this policy only governs when moka
/// frees the entry's memory. Reads do not extend the expiry.
///
/// The window end is `window_start + min(exp_secs - ttl_secs, ttl_secs)`, the
/// same width used by `token_window` (see
/// `handlers::status_list::utils::conditional::token_window`). A token anchored
/// to `[window_start, window_start + width)` is never read after the window
/// rolls at `window_start + width`, so expiring there (rather than at
/// `window_start + exp_secs`) means a closed window's bytes are freed promptly
/// instead of lingering for the rest of `exp_secs`.
#[derive(Debug, Clone, Copy, Default)]
struct EntryExpiry;

impl Expiry<TokenCacheKey, CachedToken> for EntryExpiry {
    fn expire_after_create(
        &self,
        key: &TokenCacheKey,
        value: &CachedToken,
        _created_at: Instant,
    ) -> Option<Duration> {
        let exp = i64::try_from(key.token_exp_secs).unwrap_or(i64::MAX);
        let ttl = i64::try_from(key.token_ttl_secs).unwrap_or(i64::MAX);
        let width = exp.saturating_sub(ttl).min(ttl).max(1);
        let window_end = key.window_start.saturating_add(width);
        let secs = (window_end - value.created_at_unix).max(1) as u64;
        Some(Duration::from_secs(secs))
    }
}

impl TokenBytesCache {
    /// Build an in-process signed-token bytes cache.
    ///
    /// `max_capacity_bytes` bounds the resident memory: entries are weighed by
    /// their byte size and the total weighted size is capped at this budget. A
    /// `0` budget disables the cache (entries are evicted immediately, so every
    /// request re-signs). Each entry additionally expires at the end of its own
    /// validity window, independent of the byte budget.
    pub(crate) fn new(max_capacity_bytes: u64) -> Self {
        if max_capacity_bytes == 0 {
            tracing::info!("Signed-token bytes cache disabled (capacity=0)");
        }
        let inner = MokaCache::builder()
            .weigher(entry_weight)
            .max_capacity(max_capacity_bytes)
            .expire_after(EntryExpiry)
            .build();
        let cache = Self { inner };
        // Register the cache so the observable size gauges read live
        // entry_count/weighted_size at scrape time.
        token_cache_metrics();
        set_size_gauge_cache(cache.clone());
        cache
    }

    /// Return cached bytes for `key`, only for an entry whose anchored window
    /// `[window_start, window_start + exp_secs)` still contains `now`. Past that
    /// bound the bytes are expired and must be re-signed.
    ///
    /// On a miss, `init` is invoked to build the token. Concurrent misses for
    /// the same key coalesce onto a single in-flight build; a request that
    /// arrives after the completed entry was evicted by capacity pressure is a
    /// fresh miss and re-runs `init`. Returns `Ok(None)` when the window is
    /// already closed (`init` is *not* called); the caller must re-sign with a
    /// fresh window. Returns `Ok(Some(_))` on a hit or a successful build, and
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
        E: Clone + Send + Sync + 'static,
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

        // Fast path: already cached.
        if let Some(cached) = self.inner.get(key).await {
            metrics
                .hits
                .add(1, &[KeyValue::new("cache", "token_bytes")]);
            return Ok(Some(cached));
        }

        // Slow path: build on miss, coalescing concurrent misses for the same
        // key onto one in-flight build.
        let value = self
            .inner
            .try_get_with_by_ref(key, {
                let init = init;
                async move { init().await }
            })
            .await
            .map_err(|err| match Arc::try_unwrap(err) {
                Ok(err) => err,
                Err(shared) => (*shared).clone(),
            })?;

        // This caller observed a miss (no cached value at arrival), so count it
        // as one. Coalesced waiters that joined an in-flight build are still
        // genuine misses — they did not find cached bytes when they arrived.
        metrics
            .misses
            .add(1, &[KeyValue::new("cache", "token_bytes")]);
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
        let cache = TokenBytesCache::new(100);
        let key = base_key(w);
        cache
            .insert(
                key.clone(),
                CachedToken {
                    bytes: Bytes::from(vec![1, 2, 3]),
                    encoding: None,
                    created_at_unix: 0,
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
        let cache = TokenBytesCache::new(100);
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
                                created_at_unix: 0,
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
    async fn get_or_build_coalesces_waiters_when_entry_evicted_mid_build() {
        // Regression guard: waiters that joined an in-flight build for the
        // target key must all share that one build even when the data entry is
        // evicted mid-build. The single-flight guarantee covers *concurrent*
        // misses joining one build; it does not cover a request that arrives
        // after the completed entry has been evicted (see
        // `sequential_request_re_signs_after_capacity_eviction`). The byte
        // budget (3) equals one entry's weight, so the single slot holds one
        // entry at a time.
        let cache = TokenBytesCache::new(3);

        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let target_key = TokenCacheKey {
            list_id: "target-list".to_string(),
            ..base_key(1000)
        };

        // Barrier so every target waiter reaches `get_or_build` at the same
        // instant, guaranteeing they all observe a miss and join the single
        // in-flight build.
        const N_WAITERS: usize = 16;
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(N_WAITERS));

        let mut handles = Vec::new();
        for _ in 0..N_WAITERS {
            let cache = cache.clone();
            let key = target_key.clone();
            let barrier = barrier.clone();
            let builds = builds.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let out = cache
                    .get_or_build(&key, 1000, 900, 1400, || {
                        let builds = builds.clone();
                        async move {
                            // Hold the build open long enough for the churn keys
                            // to occupy and evict the single data slot.
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(CachedToken {
                                bytes: Bytes::from(vec![7u8, 8, 9]),
                                encoding: None,
                                created_at_unix: 0,
                            })
                        }
                    })
                    .await
                    .expect("infallible");
                out.expect("window open, so Some")
            }));
        }

        // Churn the single-slot data cache while the target's build is in flight.
        for i in 0..64 {
            let cache = cache.clone();
            handles.push(tokio::spawn(async move {
                let k = TokenCacheKey {
                    list_id: format!("churn-{i}"),
                    ..base_key(1000)
                };
                let out = cache
                    .get_or_build(&k, 1000, 900, 1400, || async {
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        Ok::<_, std::convert::Infallible>(CachedToken {
                            bytes: Bytes::from(vec![1u8, 2, 3]),
                            encoding: None,
                            created_at_unix: 0,
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
            "all waiters for the target key must coalesce onto the single in-flight \
             build even when the data entry is evicted mid-build"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sequential_request_re_signs_after_capacity_eviction() {
        // The single-flight guarantee covers *concurrent* misses, not one sign
        // per key per window. Drive the target key out of a capacity-1 cache with
        // churn, confirm it was evicted, then request it again in the same open
        // window: it is a fresh miss and re-runs the builder — the accepted
        // tradeoff of bounding memory. Operators can avoid it by sizing
        // `max_capacity` above the number of live windows.
        let cache = TokenBytesCache::new(1);
        let key_a = TokenCacheKey {
            list_id: "list-a".to_string(),
            ..base_key(1000)
        };

        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // A: miss, runs builder (build #1), caches under capacity-1 slot.
        let a1 = cache
            .get_or_build(&key_a, 1000, 900, 1400, {
                let builds = builds.clone();
                || async move {
                    builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, std::convert::Infallible>(CachedToken {
                        bytes: Bytes::from(vec![1u8]),
                        encoding: None,
                        created_at_unix: 0,
                    })
                }
            })
            .await
            .expect("infallible")
            .expect("window open");
        assert_eq!(*a1.bytes, vec![1]);

        // Churn many distinct keys through the single slot to force A's eviction.
        // Moka evicts amortized, so enough inserts reliably drive A out.
        for i in 0..512 {
            let key = TokenCacheKey {
                list_id: format!("churn-{i}"),
                ..base_key(1000)
            };
            cache
                .get_or_build(&key, 1000, 900, 1400, || async {
                    Ok::<_, std::convert::Infallible>(CachedToken {
                        bytes: Bytes::from(vec![9u8]),
                        encoding: None,
                        created_at_unix: 0,
                    })
                })
                .await
                .expect("infallible")
                .expect("window open");
        }

        // A must have been evicted by capacity pressure, so it is now a miss.
        assert!(
            cache.get(&key_a, 1000, 900, 1400).await.is_none(),
            "capacity pressure must have evicted the still-valid A entry"
        );

        // A again in the same open window: fresh miss, runs the builder again.
        let a2 = cache
            .get_or_build(&key_a, 1000, 900, 1400, {
                let builds = builds.clone();
                || async move {
                    builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, std::convert::Infallible>(CachedToken {
                        bytes: Bytes::from(vec![3u8]),
                        encoding: None,
                        created_at_unix: 0,
                    })
                }
            })
            .await
            .expect("infallible")
            .expect("window open");
        assert_eq!(*a2.bytes, vec![3]);

        assert_eq!(
            builds.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "capacity eviction re-signs an unchanged token on a later request; \
             the single-flight guarantee covers concurrent misses only"
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

        let cache = TokenBytesCache::new(100);
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
                        created_at_unix: 0,
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
        // Size gauges must be exported too (entry count and resident bytes).
        for metric in [ENTRY_COUNT_METRIC, TOTAL_BYTES_METRIC] {
            let sample =
                format!(r#"{metric}{{cache="token_bytes",otel_scope_name="status-list-server"}}"#);
            assert!(
                body.contains(&sample),
                "missing metric series {sample}; body:\n{body}"
            );
        }
    }

    #[tokio::test]
    async fn cache_disabled_capacity_zero_never_serves() {
        // A zero byte budget preserves the "cache disabled" semantics: entries
        // are evicted immediately, so every lookup is a miss and every build
        // runs.
        let cache = TokenBytesCache::new(0);
        let key = base_key(1000);
        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        for _ in 0..3 {
            let out = cache
                .get_or_build(&key, 1000, 900, 1400, {
                    let builds = builds.clone();
                    || async move {
                        builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok::<_, std::convert::Infallible>(CachedToken {
                            bytes: Bytes::from(vec![7u8, 8, 9]),
                            encoding: None,
                            created_at_unix: 1300,
                        })
                    }
                })
                .await
                .expect("infallible");
            assert!(
                out.is_some(),
                "capacity-0 cache still returns a freshly built token"
            );
        }
        assert_eq!(
            builds.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "a capacity-0 cache never reuses an entry; every request re-signs"
        );
    }

    #[test]
    fn entry_weight_is_byte_length() {
        // The cache's `max_capacity` is a byte budget: each entry is weighed by
        // its signed-token byte length, so a large list consumes proportionally
        // more of the budget than a small one.
        let key = base_key(1000);
        let small = CachedToken {
            bytes: Bytes::from(vec![1u8, 2, 3]),
            encoding: None,
            created_at_unix: 1000,
        };
        assert_eq!(entry_weight(&key, &small), 3);

        let large = CachedToken {
            bytes: Bytes::from(vec![0u8; 2048]),
            encoding: None,
            created_at_unix: 1000,
        };
        assert_eq!(entry_weight(&key, &large), 2048);
    }

    #[tokio::test]
    async fn default_config_retains_representative_token() {
        // The built-in `token_bytes_cache.max_capacity` is a *byte* budget. A
        // representative signed token is a few hundred bytes, so the default
        // budget must retain and serve it — otherwise non-Helm deployments
        // (which use the built-in default) would re-sign every request.
        let defaults =
            crate::config::Config::load_from_overrides(&[]).expect("default config should load");
        let cache = TokenBytesCache::new(defaults.token_bytes_cache.max_capacity);
        let key = base_key(1000);
        cache
            .insert(
                key.clone(),
                CachedToken {
                    bytes: Bytes::from(vec![0u8; 512]),
                    encoding: None,
                    created_at_unix: 1000,
                },
            )
            .await;
        assert!(
            cache.get(&key, 1000, 900, 1400).await.is_some(),
            "default byte budget must retain and serve a representative token"
        );
    }

    #[test]
    fn entry_expiry_targets_window_end() {
        // Each entry expires at the end of its own anchored validity window,
        // independent of any global TTL. The window width is
        // `min(exp - ttl, ttl)`: `base_key(1000)` has `exp_secs = 900` and
        // `ttl_secs = 300`, so the width is `min(600, 300) = 300` and the window
        // `[1000, 1300)`. An entry created at 1200 must therefore live for
        // exactly 100 seconds, not the full `exp_secs` runway.
        let key = base_key(1000);
        let value = CachedToken {
            bytes: Bytes::from(vec![1u8]),
            encoding: None,
            created_at_unix: 1200,
        };
        let duration = EntryExpiry
            .expire_after_create(&key, &value, std::time::Instant::now())
            .expect("a window-end expiry is always set");
        assert_eq!(duration, Duration::from_secs(100));

        // A different ttl/exp pairing yields a different width and thus a
        // different expiry: exp=1200, ttl=600 -> width = min(600, 600) = 600,
        // window [1000, 1600), so an entry created at 1200 lives 400s.
        let key = TokenCacheKey {
            token_ttl_secs: 600,
            token_exp_secs: 1200,
            ..base_key(1000)
        };
        let value = CachedToken {
            bytes: Bytes::from(vec![1u8]),
            encoding: None,
            created_at_unix: 1200,
        };
        let duration = EntryExpiry
            .expire_after_create(&key, &value, std::time::Instant::now())
            .expect("a window-end expiry is always set");
        assert_eq!(duration, Duration::from_secs(400));
    }
}
