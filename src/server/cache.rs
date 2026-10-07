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

/// One cached signed representation: the **uncompressed** signed token bytes.
///
/// The bytes are stored as [`Bytes`] so a cache hit can be moved straight into
/// an Axum response body without copying the (potentially large) representation.
/// Encoding (gzip vs identity) is **not** part of the cache entry: it is derived
/// from these uncompressed bytes at serve time, so a single sign per
/// `(list, window, format)` serves every `Accept-Encoding` variant (ticket 564
/// review: "Cache and coalesce the uncompressed signed token independently of
/// encoding"). The optimistic-concurrency generation lives on the
/// [`TokenCacheKey`] (not the value), which is what generation-aware
/// invalidation reads.
///
/// `created_at_unix` is the wall-clock second the entry was built. The cache's
/// per-entry expiry ([`EntryExpiry`]) uses it to expire each entry at the end of
/// its own validity window, rather than on a fixed TTL.
#[derive(Debug, Clone)]
pub(crate) struct CachedToken {
    pub(crate) bytes: Bytes,
    pub(crate) created_at_unix: i64,
}

/// The typed identity of a cached signed representation.
///
/// Every field is a distinct cache-key dimension: the list and its content hash
/// pin the payload, the signer fingerprint pins the signing material, `version`
/// pins the optimistic-concurrency generation (so a token reinstated to an
/// earlier content state within the same window — where `content_hash` would
/// otherwise be identical — is still a distinct identity and never reuses the
/// stale bytes), `window_start` pins the token's validity window, and `format`
/// pins the JWT/CWT serialization. `token_exp_secs` is a per-process constant
/// retained so the per-entry expiry can free a closed window's bytes at the
/// exact instant its window rolls.
///
/// Encoding is deliberately **not** a key dimension: the uncompressed signed
/// bytes are shared across `Accept-Encoding` variants (gzip and identity are
/// derived from the same bytes at serve time), so one sign serves every encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TokenCacheKey {
    pub(crate) list_id: String,
    pub(crate) content_hash: String,
    pub(crate) signer_fingerprint: String,
    pub(crate) window_start: i64,
    pub(crate) version: u64,
    pub(crate) format: String,
    pub(crate) token_exp_secs: u64,
}

/// An in-memory cache of fully signed, serialised status-list token bytes.
///
/// Per replica and byte-bounded (`max_capacity_bytes`): each entry is weighed by
/// its byte size. Entries are keyed by `TokenCacheKey` — `(list, content_hash,
/// signer, window, version, format)` — and expire at the end of their anchored
/// window `[window_start, window_start + token_exp_secs)`. A fresh `200` reuses
/// one sign per `(list, window, format)` per replica, and every
/// `Accept-Encoding` variant (gzip / identity) is derived from the same
/// uncompressed bytes, so an encoding change never triggers a second sign.
/// Concurrent misses for the same key coalesce onto one in-flight build. Content
/// changes, signer/key rotation, and certificate renewal all change the key and
/// so immediately miss and re-sign; superseded list generations are actively
/// reclaimed via `TokenBytesCache::invalidate_superseded`.
///
/// Capacity policy (ticket 564 review): the "at most one sign per
/// `(list, window, format)`" guarantee is scoped to *concurrent misses* (single
/// flight) and *resident entries*. A byte-bounded cache must evict when over
/// budget, so a request that arrives after an unchanged, still-valid entry was
/// evicted by capacity pressure re-signs it — and, because the strong ETag is a
/// digest of the served bytes, also cannot certify a `304` without the resident
/// bytes. This is the agreed tradeoff of bounding memory; operators avoid the
/// re-sign by sizing `max_capacity` above the working set of live windows.
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
/// validity window, independent of any global TTL. This policy only governs when
/// moka frees the entry's memory; the serving path always anchors the request's
/// key to the current window, so a closed window's entry is never served. Reads
/// do not extend the expiry.
///
/// The window end is `window_start + token_exp_secs` — the same width used by
/// the handler's `token_window` (expiry-sized windows under the ticket 564
/// proposal). A token anchored to `[window_start, window_start + exp_secs)` is
/// never read after the window rolls at `window_start + exp_secs`, so expiring
/// there frees a closed window's bytes promptly. The width is derived directly
/// from the key's `token_exp_secs` here (rather than calling a handler-module
/// helper) so the cache stays independent of the status-list handler.
#[derive(Debug, Clone, Copy, Default)]
struct EntryExpiry;

impl Expiry<TokenCacheKey, CachedToken> for EntryExpiry {
    fn expire_after_create(
        &self,
        key: &TokenCacheKey,
        value: &CachedToken,
        _created_at: Instant,
    ) -> Option<Duration> {
        // Window width is `exp_secs` clamped to `>= 1` — the same formula the
        // handler's `token_window` uses (expiry-sized windows), so the cache
        // frees a closed window's bytes at exactly the instant the window rolls
        // over. Keeping the two in lockstep means an entry can never silently
        // outlive (or be freed before) the window it is anchored to.
        let width = i64::try_from(key.token_exp_secs).unwrap_or(i64::MAX).max(1);
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

    /// Return cached bytes for `key`, building them on a miss.
    ///
    /// The caller supplies `init` to build the token. Concurrent misses for the
    /// same key coalesce onto a single in-flight build; a request that arrives
    /// after the completed entry was evicted by capacity pressure is a fresh
    /// miss and re-runs `init` (the documented capacity tradeoff). There is no
    /// explicit window bound here: the caller always anchors `key.window_start`
    /// to the current request's window (which contains the token's expiry), and
    /// [`EntryExpiry`] frees each entry at the end of its own window, so bytes
    /// are never served past their validity window. Returns the built or cached
    /// bytes, or `Err(e)` if `init` fails (nothing is cached on error).
    ///
    /// The caller should call [`TokenBytesCache::invalidate_superseded`] with
    /// the record's current generation after building so superseded list
    /// generations are reclaimed (ticket 564 review).
    pub(crate) async fn get_or_build<F, Fut, E>(
        &self,
        key: &TokenCacheKey,
        init: F,
    ) -> Result<CachedToken, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<CachedToken, E>>,
        E: Clone + Send + Sync + 'static,
    {
        let metrics = token_cache_metrics();

        // Fast path: already cached.
        if let Some(cached) = self.inner.get(key).await {
            metrics
                .hits
                .add(1, &[KeyValue::new("cache", "token_bytes")]);
            return Ok(cached);
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
        Ok(value)
    }

    /// Reclaim every cached entry for `list_id` whose generation (`version`) is
    /// strictly older than `version` (ticket 564 review: "add generation-aware
    /// invalidation for superseded list entries").
    ///
    /// A content change bumps the optimistic-concurrency `version`, so the next
    /// read of a newer generation calls this and evicts the superseded bytes
    /// immediately rather than letting them linger until window expiry or
    /// capacity pressure. Because `version` is part of every cache key, a
    /// superseded entry is never *served* even if an older in-flight build
    /// re-inserts it after this call — it is a distinct key from the current
    /// generation's, and a later read of an equal-or-newer generation reclaims
    /// it again.
    pub(crate) async fn invalidate_superseded(&self, list_id: &str, version: u64) {
        // Collect every resident key for `list_id` with a strictly older
        // generation, then invalidate each by key. Moka's predicate-based
        // `invalidate_entries_if` requires the (disabled) `invalidation_closures`
        // feature, so we iterate the resident entries and invalidate individually.
        let stale_keys: Vec<TokenCacheKey> = self
            .inner
            .iter()
            .filter(|(k, _)| k.list_id == list_id && k.version < version)
            .map(|(k, _)| k.as_ref().clone())
            .collect();
        for key in stale_keys {
            self.inner.invalidate(&key).await;
        }
    }

    /// Look up cached bytes for `key`.
    ///
    /// Test helper: the serving path uses [`TokenBytesCache::get_or_build`].
    #[cfg(test)]
    pub(crate) async fn get(&self, key: &TokenCacheKey) -> Option<CachedToken> {
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
            version: 1,
            format: "jwt".to_string(),
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
                    created_at_unix: 0,
                },
            )
            .await;
        (cache, key)
    }

    #[tokio::test]
    async fn hit_within_window() {
        let (cache, key) = cached(1000).await;
        assert!(cache.get(&key).await.is_some());
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
                cache
                    .get_or_build(&key, || {
                        let builds = builds.clone();
                        async move {
                            builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(CachedToken {
                                bytes: Bytes::from(vec![7u8, 8, 9]),
                                created_at_unix: 0,
                            })
                        }
                    })
                    .await
                    .expect("infallible")
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
                cache
                    .get_or_build(&key, || {
                        let builds = builds.clone();
                        async move {
                            // Hold the build open long enough for the churn keys
                            // to occupy and evict the single data slot.
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(CachedToken {
                                bytes: Bytes::from(vec![7u8, 8, 9]),
                                created_at_unix: 0,
                            })
                        }
                    })
                    .await
                    .expect("infallible")
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
                cache
                    .get_or_build(&k, || async {
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        Ok::<_, std::convert::Infallible>(CachedToken {
                            bytes: Bytes::from(vec![1u8, 2, 3]),
                            created_at_unix: 0,
                        })
                    })
                    .await
                    .expect("infallible")
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
        // Agreed capacity policy (ticket 564 review): the "at most one sign per
        // (list, window, format)" guarantee is scoped to *concurrent misses*
        // (single flight) and *resident entries*. Drive the target key out of a
        // capacity-1 cache with churn, confirm it was evicted, then request it
        // again in the same open window: it is a fresh miss and re-runs the
        // builder — the documented tradeoff of bounding memory. With a strong
        // ETag (a digest of the served bytes) this also means the evicted entry
        // cannot certify a 304 without resident bytes. Operators avoid the
        // re-sign by sizing `max_capacity` above the working set of live windows.
        let cache = TokenBytesCache::new(1);
        let key_a = TokenCacheKey {
            list_id: "list-a".to_string(),
            ..base_key(1000)
        };

        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // A: miss, runs builder (build #1), caches under capacity-1 slot.
        let a1 = cache
            .get_or_build(&key_a, {
                let builds = builds.clone();
                || async move {
                    builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, std::convert::Infallible>(CachedToken {
                        bytes: Bytes::from(vec![1u8]),
                        created_at_unix: 0,
                    })
                }
            })
            .await
            .expect("infallible");
        assert_eq!(*a1.bytes, vec![1]);

        // Churn many distinct keys through the single slot to force A's eviction.
        // Moka evicts amortized, so enough inserts reliably drive A out.
        for i in 0..512 {
            let key = TokenCacheKey {
                list_id: format!("churn-{i}"),
                ..base_key(1000)
            };
            cache
                .get_or_build(&key, || async {
                    Ok::<_, std::convert::Infallible>(CachedToken {
                        bytes: Bytes::from(vec![9u8]),
                        created_at_unix: 0,
                    })
                })
                .await
                .expect("infallible");
        }

        // A must have been evicted by capacity pressure, so it is now a miss.
        assert!(
            cache.get(&key_a).await.is_none(),
            "capacity pressure must have evicted the still-valid A entry"
        );

        // A again in the same open window: fresh miss, runs the builder again.
        let a2 = cache
            .get_or_build(&key_a, {
                let builds = builds.clone();
                || async move {
                    builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, std::convert::Infallible>(CachedToken {
                        bytes: Bytes::from(vec![3u8]),
                        created_at_unix: 0,
                    })
                }
            })
            .await
            .expect("infallible");
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
        let other_list = TokenCacheKey {
            list_id: "list2".to_string(),
            ..base.clone()
        };
        let other_content = TokenCacheKey {
            content_hash: "other-content".to_string(),
            ..base.clone()
        };
        let other_version = TokenCacheKey {
            version: 2,
            ..base.clone()
        };
        let other_exp = TokenCacheKey {
            token_exp_secs: 1200,
            ..base.clone()
        };

        assert_ne!(base, other_window);
        assert_ne!(base, other_signer);
        assert_ne!(base, other_format);
        assert_ne!(base, other_list);
        assert_ne!(base, other_content, "content_hash must be in the key");
        assert_ne!(
            base, other_version,
            "version must be in the key (reinstated content within a window)"
        );
        assert_ne!(base, other_exp, "token_exp_secs must be in the key");
        assert_eq!(base, base_key(1000));

        // Encoding is deliberately NOT a key dimension (ticket 564 review): gzip
        // and identity are derived from the same uncompressed bytes at serve
        // time, so one sign serves every Accept-Encoding variant.
        assert_eq!(
            base,
            TokenCacheKey {
                window_start: 1000,
                ..base_key(1000)
            }
        );
    }

    #[tokio::test]
    async fn invalidate_superseded_reclaims_older_generations() {
        // Ticket 564 review: a content change bumps `version`; superseded list
        // generations must be actively reclaimed, not left to linger until
        // window expiry or capacity pressure. Reclaim must also not remove the
        // current generation.
        let cache = TokenBytesCache::new(100);
        let list = "list".to_string();

        let key_v1 = TokenCacheKey {
            version: 1,
            ..base_key(1000)
        };
        let key_v2 = TokenCacheKey {
            version: 2,
            ..base_key(1000)
        };
        let key_v3 = TokenCacheKey {
            version: 3,
            ..base_key(1000)
        };

        for (key, byte) in [(&key_v1, 1u8), (&key_v2, 2u8), (&key_v3, 3u8)] {
            cache
                .insert(
                    key.clone(),
                    CachedToken {
                        bytes: Bytes::from(vec![byte]),
                        created_at_unix: 0,
                    },
                )
                .await;
        }
        // A different list must never be touched.
        let other_list_key = TokenCacheKey {
            list_id: "other-list".to_string(),
            version: 1,
            ..base_key(1000)
        };
        cache
            .insert(
                other_list_key.clone(),
                CachedToken {
                    bytes: Bytes::from(vec![9u8]),
                    created_at_unix: 0,
                },
            )
            .await;

        // Supersede everything strictly older than v3.
        cache.invalidate_superseded(&list, 3).await;

        assert!(
            cache.get(&key_v1).await.is_none(),
            "v1 must be reclaimed as superseded"
        );
        assert!(
            cache.get(&key_v2).await.is_none(),
            "v2 must be reclaimed as superseded"
        );
        assert!(
            cache.get(&key_v3).await.is_some(),
            "the current generation must be retained"
        );
        assert!(
            cache.get(&other_list_key).await.is_some(),
            "a different list's entries must not be reclaimed"
        );
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
                        created_at_unix: 0,
                    },
                )
                .await;
            assert!(cache.get(&cache_key).await.is_some());
            assert!(cache.get(&cache_key).await.is_some()); // hit again
            assert!(cache.get(&base_key(1000)).await.is_none());
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
                .get_or_build(&key, {
                    let builds = builds.clone();
                    || async move {
                        builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok::<_, std::convert::Infallible>(CachedToken {
                            bytes: Bytes::from(vec![7u8, 8, 9]),
                            created_at_unix: 1300,
                        })
                    }
                })
                .await
                .expect("infallible");
            assert_eq!(
                out.bytes.as_ref(),
                &[7u8, 8, 9][..],
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
            created_at_unix: 1000,
        };
        assert_eq!(entry_weight(&key, &small), 3);

        let large = CachedToken {
            bytes: Bytes::from(vec![0u8; 2048]),
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
                    created_at_unix: 1000,
                },
            )
            .await;
        assert!(
            cache.get(&key).await.is_some(),
            "default byte budget must retain and serve a representative token"
        );
    }

    #[test]
    fn entry_expiry_targets_window_end() {
        // Each entry expires at the end of its own anchored validity window,
        // independent of any global TTL. Under the ticket 564 proposal the
        // window width is `exp_secs` (a window is a token's full lifetime):
        // `base_key(1000)` has `exp_secs = 900`, so the window is
        // `[1000, 1900)`. An entry created at 1200 must live for exactly 700
        // seconds, not the full 900s runway.
        let key = base_key(1000);
        let value = CachedToken {
            bytes: Bytes::from(vec![1u8]),
            created_at_unix: 1200,
        };
        let duration = EntryExpiry
            .expire_after_create(&key, &value, std::time::Instant::now())
            .expect("a window-end expiry is always set");
        assert_eq!(duration, Duration::from_secs(700));

        // A different exp yields a different width and thus a different expiry:
        // exp=1200 -> window [1000, 2200), so an entry created at 1200 lives
        // 1000s.
        let key = TokenCacheKey {
            token_exp_secs: 1200,
            ..base_key(1000)
        };
        let value = CachedToken {
            bytes: Bytes::from(vec![1u8]),
            created_at_unix: 1200,
        };
        let duration = EntryExpiry
            .expire_after_create(&key, &value, std::time::Instant::now())
            .expect("a window-end expiry is always set");
        assert_eq!(duration, Duration::from_secs(1000));
    }
}
