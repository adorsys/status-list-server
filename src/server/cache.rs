use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use dashmap::DashMap;
use moka::future::Cache as MokaCache;
use moka::policy::Expiry;
use opentelemetry::{
    metrics::{Counter, ObservableGauge},
    {KeyValue, global},
};

use crate::server::handlers::status_list::utils::etag::generate_token_etag;

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

/// A protected entry that is guaranteed to not be evicted by capacity pressure.
/// These are entries for the latest generation of a list that are still within
/// their validity window.
#[derive(Debug, Clone)]
struct ProtectedEntry {
    token: CachedToken,
    window_end: i64,
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
                        let cold_count = cache.cold.entry_count();
                        let protected_count = cache.protected.len() as u64;
                        observer.observe(
                            cold_count + protected_count,
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
                        let cold_bytes = cache.cold.weighted_size();
                        let protected_bytes: u64 = cache
                            .protected
                            .iter()
                            .map(|e| e.value().token.bytes.len() as u64)
                            .sum();
                        observer.observe(
                            cold_bytes + protected_bytes,
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

/// One cached signed representation: the **uncompressed** signed token bytes
/// plus pre-computed encoded variants and their ETags.
///
/// The bytes are stored as [`Bytes`] so a cache hit can be moved straight into
/// an Axum response body without copying the (potentially large) representation.
/// Encoding (gzip vs identity) is **not** part of the cache key: the uncompressed
/// signed bytes are shared across `Accept-Encoding` variants, so a single sign
/// per `(list, window, format)` serves every encoding. The encoded variants
/// (gzip for JWT) and their strong ETags are computed once at cache insertion
/// time and stored alongside the uncompressed bytes, so revalidation requests
/// (including 304) never need to re-compress.
///
/// `created_at_unix` is the wall-clock second the entry was built. The cache's
/// per-entry expiry ([`EntryExpiry`]) uses it to expire each entry at the end of
/// its own validity window, rather than on a fixed TTL.
#[derive(Debug, Clone)]
pub(crate) struct CachedToken {
    /// Uncompressed signed token bytes (identity encoding).
    pub(crate) bytes: Bytes,
    /// Strong ETag for the identity encoding (digest of `bytes`).
    pub(crate) identity_etag: String,
    /// Gzip-compressed bytes (only for JWT format; `None` for CWT).
    pub(crate) gzip_bytes: Option<Bytes>,
    /// Strong ETag for the gzip encoding (digest of `gzip_bytes`).
    pub(crate) gzip_etag: Option<String>,
    /// Wall-clock second the entry was built.
    pub(crate) created_at_unix: i64,
}

impl CachedToken {
    /// Build a `CachedToken` from uncompressed bytes, pre-computing the identity
    /// ETag and (for JWT) the gzip bytes and gzip ETag.
    pub(crate) fn new(bytes: Bytes, format: &str, created_at_unix: i64) -> Self {
        let identity_etag = generate_token_etag(&bytes);
        let (gzip_bytes, gzip_etag) = if format == "jwt" {
            let gzip_bytes = compress_gzip(&bytes);
            let gzip_etag = Some(generate_token_etag(&gzip_bytes));
            (Some(gzip_bytes), gzip_etag)
        } else {
            (None, None)
        };
        Self {
            bytes,
            identity_etag,
            gzip_bytes,
            gzip_etag,
            created_at_unix,
        }
    }
}

/// Compress bytes using gzip.
fn compress_gzip(bytes: &[u8]) -> Bytes {
    use std::io::Write as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    // Compression should never fail for valid input; if it does, fall back to
    // uncompressed (the caller will handle the error by not using gzip).
    if encoder.write_all(bytes).is_ok()
        && let Ok(compressed) = encoder.finish()
    {
        return Bytes::from(compressed);
    }
    // Fallback: return uncompressed (should not happen in practice).
    Bytes::from(bytes.to_vec())
}

/// The typed identity of a cached signed representation.
///
/// Every field is a distinct cache-key dimension: the list and its content hash
/// pin the payload, the signer fingerprint pins the signing material, `version`
/// pins the optimistic-concurrency generation (so a token reinstated to an
/// earlier content state within the same window — where `content_hash` would
/// otherwise be identical — is still a distinct identity and never reuses the
/// stale bytes), `window_start` pins the token's validity window, `format`
/// pins the JWT/CWT serialization, and `aggregation_uri` pins that claim, which
/// a failed issuer lookup leaves out. `token_exp_secs` is a per-process constant
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
    pub(crate) aggregation_uri: Option<String>,
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
/// Capacity guarantee (ticket 564): at most one signature per `(list, window,
/// format)` per replica, even under capacity pressure. This is achieved by a
/// two-tier cache: entries for the latest generation of a list that are still
/// within their validity window are stored in a protected tier that is never
/// evicted by capacity pressure. Only entries for superseded generations or
/// expired windows reside in the byte-bounded cold tier.
#[derive(Clone, Debug)]
pub struct TokenBytesCache {
    /// Cold tier: byte-bounded cache for superseded generations and expired
    /// windows. Entries here are subject to capacity-based eviction.
    cold: MokaCache<TokenCacheKey, CachedToken>,
    /// Protected tier: entries for the latest generation of each list that are
    /// still within their validity window. Never evicted by capacity pressure.
    /// Wrapped in Arc to ensure sharing across clones (DashMap::Clone creates
    /// independent copies).
    protected: Arc<DashMap<TokenCacheKey, ProtectedEntry>>,
    /// Tracks the latest known generation (version) for each list_id.
    /// Wrapped in Arc to ensure sharing across clones.
    latest_generation: Arc<DashMap<String, u64>>,
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

/// Compute the window end timestamp for a key.
fn window_end(key: &TokenCacheKey) -> i64 {
    let width = i64::try_from(key.token_exp_secs).unwrap_or(i64::MAX).max(1);
    key.window_start.saturating_add(width)
}

impl TokenBytesCache {
    /// Build an in-process signed-token bytes cache.
    ///
    /// `max_capacity_bytes` bounds the resident memory of the *cold* tier:
    /// entries are weighed by their byte size and the total weighted size is
    /// capped at this budget. A `0` budget disables the cold tier (entries are
    /// evicted immediately, so every request for a non-protected entry re-signs).
    /// The protected tier has no byte budget; it holds at most one entry per
    /// `(list, format)` for the latest generation within its window, which is
    /// bounded by the number of active lists. Each entry additionally expires at
    /// the end of its own validity window, independent of the byte budget.
    pub fn new(max_capacity_bytes: u64) -> Self {
        if max_capacity_bytes == 0 {
            tracing::info!("Signed-token bytes cache cold tier disabled (capacity=0)");
        }
        let cold = MokaCache::builder()
            .weigher(entry_weight)
            .max_capacity(max_capacity_bytes)
            .expire_after(EntryExpiry)
            .build();
        let cache = Self {
            cold,
            protected: Arc::new(DashMap::new()),
            latest_generation: Arc::new(DashMap::new()),
        };
        // Register the cache so the observable size gauges read live
        // entry_count/weighted_size at scrape time.
        token_cache_metrics();
        set_size_gauge_cache(cache.clone());
        cache
    }

    /// Return cached bytes for `key`, building them on a miss.
    ///
    /// The caller supplies `init` to build the token. Concurrent misses for the
    /// same key coalesce onto a single in-flight build. There is no explicit
    /// window bound here: the caller always anchors `key.window_start` to the
    /// current request's window (which contains the token's expiry), and
    /// [`EntryExpiry`] frees each entry at the end of its own window, so bytes
    /// are never served past their validity window. Returns the built or cached
    /// bytes, or `Err(e)` if `init` fails (nothing is cached on error).
    ///
    /// The caller should call [`TokenBytesCache::invalidate_superseded`] with
    /// the record's current generation after building so superseded list
    /// generations are reclaimed (ticket 564 review).
    ///
    /// The `now` parameter is the current Unix timestamp for time-sensitive
    /// operations (protected tier expiry checks). In production, pass the
    /// request's timestamp; in tests, pass the simulated time.
    pub(crate) async fn get_or_build<F, Fut, E>(
        &self,
        key: &TokenCacheKey,
        init: F,
        now: i64,
    ) -> Result<CachedToken, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<CachedToken, E>>,
        E: Clone + Send + Sync + 'static,
    {
        let metrics = token_cache_metrics();

        // Fast path: check protected tier first (latest generation, within window).
        if let Some(entry) = self.protected.get(key) {
            if entry.window_end > now {
                metrics
                    .hits
                    .add(1, &[KeyValue::new("cache", "token_bytes")]);
                return Ok(entry.token.clone());
            } else {
                // Window expired, demote to cold tier.
                let entry = self.protected.remove(key).map(|(_, v)| v).unwrap();
                self.cold.insert(key.clone(), entry.token).await;
            }
        }

        // Slow path: build on miss, coalescing concurrent misses for the same
        // key onto one in-flight build. We use the cold tier for coalescing,
        // then promote to protected tier if appropriate.
        let value = self
            .cold
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

        // After building, re-check the latest generation. If a newer generation
        // has been registered (e.g., via invalidate_superseded), this build is
        // stale and should not be cached. Invalidate it from the cold tier.
        let window_end = window_end(key);
        let mut latest_gen = self
            .latest_generation
            .entry(key.list_id.clone())
            .or_insert(0);
        if key.version < *latest_gen {
            // Stale generation: remove from cold tier and don't promote.
            self.cold.invalidate(key).await;
        } else if key.version >= *latest_gen && window_end > now {
            // Current generation and within window: promote to protected tier.
            *latest_gen = key.version;
            self.protected.insert(
                key.clone(),
                ProtectedEntry {
                    token: value.clone(),
                    window_end,
                },
            );
        }
        // Else: current generation but window expired - leave in cold tier only.
        Ok(value)
    }

    /// Insert a built token into the appropriate tier.
    ///
    /// If the entry is for the latest generation of its list and its window has
    /// not expired, it goes to the protected tier. Otherwise it goes to the cold
    /// tier.
    #[cfg(test)]
    async fn insert_tiered(&self, key: TokenCacheKey, value: CachedToken, now: i64) {
        let window_end = window_end(&key);

        // Atomically check and update the latest generation for this list.
        let mut is_latest = false;
        let mut latest_gen = self
            .latest_generation
            .entry(key.list_id.clone())
            .or_insert(0);
        if key.version >= *latest_gen {
            *latest_gen = key.version;
            is_latest = true;
        }

        if is_latest && window_end > now {
            // Demote any existing protected entry for this list/format/window
            // with an older version (should not happen due to version check, but
            // defensive).
            self.protected.retain(|k, _| {
                !(k.list_id == key.list_id
                    && k.format == key.format
                    && k.window_start == key.window_start
                    && k.version < key.version)
            });

            self.protected.insert(
                key,
                ProtectedEntry {
                    token: value,
                    window_end,
                },
            );
        } else {
            self.cold.insert(key, value).await;
        }
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
    pub(crate) async fn invalidate_superseded(&self, list_id: &str, version: u64, now: i64) {
        // Update the latest generation tracker.
        let mut latest_gen = self
            .latest_generation
            .entry(list_id.to_string())
            .or_insert(0);
        if version > *latest_gen {
            *latest_gen = version;
        }

        // Remove from protected tier.
        self.protected
            .retain(|k, _| !(k.list_id == list_id && k.version < version));

        // Remove from cold tier by iterating.
        let stale_keys: Vec<TokenCacheKey> = self
            .cold
            .iter()
            .filter(|(k, _)| k.list_id == list_id && k.version < version)
            .map(|(k, _)| k.as_ref().clone())
            .collect();
        for key in stale_keys {
            self.cold.invalidate(&key).await;
        }

        // Also demote any protected entries for this list that have expired.
        let expired_keys: Vec<TokenCacheKey> = self
            .protected
            .iter()
            .filter(|entry| entry.value().window_end <= now && entry.key().list_id == list_id)
            .map(|entry| entry.key().clone())
            .collect();
        for key in expired_keys {
            if let Some((_, entry)) = self.protected.remove(&key) {
                self.cold.insert(key, entry.token).await;
            }
        }
    }

    /// Look up cached bytes for `key`.
    ///
    /// Test helper: the serving path uses [`TokenBytesCache::get_or_build`].
    #[cfg(test)]
    pub(crate) async fn get(&self, key: &TokenCacheKey, now: i64) -> Option<CachedToken> {
        if let Some(entry) = self.protected.get(key) {
            if entry.window_end > now {
                let metrics = token_cache_metrics();
                metrics
                    .hits
                    .add(1, &[KeyValue::new("cache", "token_bytes")]);
                return Some(entry.token.clone());
            } else {
                let entry = self.protected.remove(key).map(|(_, v)| v).unwrap();
                self.cold.insert(key.clone(), entry.token).await;
            }
        }

        let cached = self.cold.get(key).await;
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
    pub(crate) async fn insert(&self, key: TokenCacheKey, value: CachedToken, now: i64) {
        self.insert_tiered(key, value, now).await;
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

    /// A test window start far in the future so entries don't expire during tests.
    const TEST_WINDOW_START: i64 = 10_000_000_000;

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
            aggregation_uri: None,
            token_exp_secs: 900,
        }
    }

    async fn cached(w: i64) -> (TokenBytesCache, TokenCacheKey) {
        let cache = TokenBytesCache::new(100);
        let key = base_key(w);
        cache
            .insert(
                key.clone(),
                CachedToken::new(Bytes::from(vec![1, 2, 3]), &key.format, w),
                w,
            )
            .await;
        (cache, key)
    }

    #[tokio::test]
    async fn hit_within_window() {
        let (cache, key) = cached(TEST_WINDOW_START).await;
        assert!(cache.get(&key, TEST_WINDOW_START).await.is_some());
    }

    #[tokio::test]
    async fn get_or_build_single_flights_concurrent_misses() {
        // At most one signing operation per (list, window, format) per replica.
        // N concurrent misses for the same key must run the builder exactly once
        // and share the resulting bytes.
        let cache = TokenBytesCache::new(100);
        let key = base_key(TEST_WINDOW_START);

        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let key = key.clone();
            let builds = builds.clone();
            let format = key.format.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_build(
                        &key,
                        || {
                            let builds = builds.clone();
                            let format = format.clone();
                            async move {
                                builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                Ok::<_, std::convert::Infallible>(CachedToken::new(
                                    Bytes::from(vec![7u8, 8, 9]),
                                    &format,
                                    TEST_WINDOW_START,
                                ))
                            }
                        },
                        TEST_WINDOW_START,
                    )
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
            ..base_key(TEST_WINDOW_START)
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
            let format = key.format.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                cache
                    .get_or_build(
                        &key,
                        || {
                            let builds = builds.clone();
                            let format = format.clone();
                            async move {
                                // Hold the build open long enough for the churn keys
                                // to occupy and evict the single data slot.
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                Ok::<_, std::convert::Infallible>(CachedToken::new(
                                    Bytes::from(vec![7u8, 8, 9]),
                                    &format,
                                    TEST_WINDOW_START,
                                ))
                            }
                        },
                        TEST_WINDOW_START,
                    )
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
                    ..base_key(TEST_WINDOW_START)
                };
                let format = k.format.clone();
                cache
                    .get_or_build(
                        &k,
                        || async {
                            let format = format.clone();
                            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                            Ok::<_, std::convert::Infallible>(CachedToken::new(
                                Bytes::from(vec![1u8, 2, 3]),
                                &format,
                                TEST_WINDOW_START,
                            ))
                        },
                        TEST_WINDOW_START,
                    )
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
    async fn protected_tier_prevents_re_sign_after_capacity_pressure() {
        // Capacity guarantee (ticket 564): at most one sign per (list, window,
        // format) even under capacity pressure. The protected tier holds entries
        // for the latest generation within their window and never evicts them.
        // Drive the cold tier to capacity with churn, then verify the protected
        // entry is still served without re-signing.
        let cache = TokenBytesCache::new(1);
        let key_a = TokenCacheKey {
            list_id: "list-a".to_string(),
            ..base_key(TEST_WINDOW_START)
        };

        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // A: miss, runs builder (build #1), goes to protected tier (latest gen, within window).
        let format_a = key_a.format.clone();
        let a1 = cache
            .get_or_build(
                &key_a,
                {
                    let builds = builds.clone();
                    let format = format_a.clone();
                    || async move {
                        builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok::<_, std::convert::Infallible>(CachedToken::new(
                            Bytes::from(vec![1u8]),
                            &format,
                            TEST_WINDOW_START,
                        ))
                    }
                },
                TEST_WINDOW_START,
            )
            .await
            .expect("infallible");
        assert_eq!(*a1.bytes, vec![1]);

        // Churn many distinct keys through the cold tier to saturate capacity.
        // These are different list_ids, so they go to cold tier.
        for i in 0..512 {
            let key = TokenCacheKey {
                list_id: format!("churn-{i}"),
                ..base_key(TEST_WINDOW_START)
            };
            let format = key.format.clone();
            cache
                .get_or_build(
                    &key,
                    || async {
                        let format = format.clone();
                        Ok::<_, std::convert::Infallible>(CachedToken::new(
                            Bytes::from(vec![9u8]),
                            &format,
                            TEST_WINDOW_START,
                        ))
                    },
                    TEST_WINDOW_START,
                )
                .await
                .expect("infallible");
        }

        // A must still be in protected tier, served without re-signing.
        let a2 = cache
            .get(&key_a, TEST_WINDOW_START)
            .await
            .expect("protected entry must be present");
        assert_eq!(*a2.bytes, vec![1]);

        // A again via get_or_build: still a hit, no re-sign.
        let a3 = cache
            .get_or_build(
                &key_a,
                {
                    let builds = builds.clone();
                    let format = format_a.clone();
                    || async move {
                        builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok::<_, std::convert::Infallible>(CachedToken::new(
                            Bytes::from(vec![3u8]),
                            &format,
                            TEST_WINDOW_START,
                        ))
                    }
                },
                TEST_WINDOW_START,
            )
            .await
            .expect("infallible");
        assert_eq!(*a3.bytes, vec![1]);

        assert_eq!(
            builds.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "protected tier must prevent re-signing an unchanged token under capacity pressure"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stale_generation_build_discarded_after_invalidation() {
        // Generation invalidation guarantee (ticket 564): an older in-flight build
        // that completes after a newer generation's invalidation must not remain
        // cached. The cache tracks the latest generation per list and discards
        // stale builds.
        let cache = TokenBytesCache::new(100);
        let list_id = "test-list".to_string();

        let key_v1 = TokenCacheKey {
            list_id: list_id.clone(),
            version: 1,
            ..base_key(TEST_WINDOW_START)
        };
        let key_v2 = TokenCacheKey {
            list_id: list_id.clone(),
            version: 2,
            ..base_key(TEST_WINDOW_START)
        };

        let builds_v1 = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let builds_v2 = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Start a slow build for v1 (simulating an in-flight build that will
        // complete after invalidation).
        let format_v1 = key_v1.format.clone();
        let cache_clone = cache.clone();
        let key_v1_clone = key_v1.clone();
        let builds_v1_clone = builds_v1.clone();
        let slow_build = tokio::spawn(async move {
            cache_clone
                .get_or_build(
                    &key_v1_clone,
                    || async move {
                        // Slow build to allow invalidation to happen first.
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        builds_v1_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok::<_, std::convert::Infallible>(CachedToken::new(
                            Bytes::from(vec![1u8]),
                            &format_v1,
                            TEST_WINDOW_START,
                        ))
                    },
                    TEST_WINDOW_START,
                )
                .await
        });

        // Wait a bit for the slow build to start, then publish v2 and invalidate v1.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Fast build for v2.
        let format_v2 = key_v2.format.clone();
        let builds_v2_clone = builds_v2.clone();
        let v2_result = cache
            .get_or_build(
                &key_v2,
                || async move {
                    builds_v2_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, std::convert::Infallible>(CachedToken::new(
                        Bytes::from(vec![2u8]),
                        &format_v2,
                        TEST_WINDOW_START,
                    ))
                },
                TEST_WINDOW_START,
            )
            .await
            .expect("infallible");
        assert_eq!(*v2_result.bytes, vec![2]);

        // Invalidate v1 (simulating a content update that bumps version to 2).
        cache
            .invalidate_superseded(&list_id, 2, TEST_WINDOW_START)
            .await;

        // Wait for the slow v1 build to complete.
        slow_build
            .await
            .expect("slow build task")
            .expect("infallible");

        // Give moka a moment to process the invalidation.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // The v1 build should have run (it was already in flight) but its result
        // should be discarded and not cached.
        assert_eq!(
            builds_v1.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "v1 build runs because it was already in flight"
        );
        assert_eq!(
            builds_v2.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "v2 build runs once"
        );

        // v1 should not be in cache (discarded as stale).
        assert!(
            cache.get(&key_v1, TEST_WINDOW_START).await.is_none(),
            "stale v1 build must not remain cached after invalidation"
        );

        // v2 should be in protected tier.
        let v2_cached = cache
            .get(&key_v2, TEST_WINDOW_START)
            .await
            .expect("v2 must be cached");
        assert_eq!(*v2_cached.bytes, vec![2]);
    }

    #[tokio::test]
    async fn key_dimensions_are_distinct() {
        let base = base_key(TEST_WINDOW_START);
        let other_window = TokenCacheKey {
            window_start: TEST_WINDOW_START + 1,
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
        let other_aggregation_uri = TokenCacheKey {
            aggregation_uri: Some("https://example.com/api/v1/aggregation/a".to_string()),
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
        assert_ne!(
            base, other_aggregation_uri,
            "aggregation_uri must be in the key"
        );
        assert_eq!(base, base_key(TEST_WINDOW_START));

        // Encoding is deliberately NOT a key dimension (ticket 564 review): gzip
        // and identity are derived from the same uncompressed bytes at serve
        // time, so one sign serves every Accept-Encoding variant.
        assert_eq!(
            base,
            TokenCacheKey {
                window_start: TEST_WINDOW_START,
                ..base_key(TEST_WINDOW_START)
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
            ..base_key(TEST_WINDOW_START)
        };
        let key_v2 = TokenCacheKey {
            version: 2,
            ..base_key(TEST_WINDOW_START)
        };
        let key_v3 = TokenCacheKey {
            version: 3,
            ..base_key(TEST_WINDOW_START)
        };

        for (key, byte) in [(&key_v1, 1u8), (&key_v2, 2u8), (&key_v3, 3u8)] {
            cache
                .insert(
                    key.clone(),
                    CachedToken::new(Bytes::from(vec![byte]), &key.format, TEST_WINDOW_START),
                    TEST_WINDOW_START,
                )
                .await;
        }
        // A different list must never be touched.
        let other_list_key = TokenCacheKey {
            list_id: "other-list".to_string(),
            version: 1,
            ..base_key(TEST_WINDOW_START)
        };
        cache
            .insert(
                other_list_key.clone(),
                CachedToken::new(
                    Bytes::from(vec![9u8]),
                    &other_list_key.format,
                    TEST_WINDOW_START,
                ),
                TEST_WINDOW_START,
            )
            .await;

        // Supersede everything strictly older than v3.
        cache
            .invalidate_superseded(&list, 3, TEST_WINDOW_START)
            .await;

        assert!(
            cache.get(&key_v1, TEST_WINDOW_START).await.is_none(),
            "v1 must be reclaimed as superseded"
        );
        assert!(
            cache.get(&key_v2, TEST_WINDOW_START).await.is_none(),
            "v2 must be reclaimed as superseded"
        );
        assert!(
            cache.get(&key_v3, TEST_WINDOW_START).await.is_some(),
            "the current generation must be retained"
        );
        assert!(
            cache
                .get(&other_list_key, TEST_WINDOW_START)
                .await
                .is_some(),
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
            ..base_key(TEST_WINDOW_START)
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            cache
                .insert(
                    cache_key.clone(),
                    CachedToken::new(Bytes::from(vec![1]), &cache_key.format, TEST_WINDOW_START),
                    TEST_WINDOW_START,
                )
                .await;
            assert!(cache.get(&cache_key, TEST_WINDOW_START).await.is_some());
            assert!(cache.get(&cache_key, TEST_WINDOW_START).await.is_some()); // hit again
            assert!(
                cache
                    .get(&base_key(TEST_WINDOW_START), TEST_WINDOW_START)
                    .await
                    .is_none()
            );
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
    async fn cache_disabled_capacity_zero_protected_tier_still_works() {
        // A zero byte budget disables the cold tier, but the protected tier
        // still retains entries for the latest generation within their window.
        // This ensures the capacity guarantee (at most one sign per list/window/
        // format) holds even when the cold tier is disabled.
        let cache = TokenBytesCache::new(0);
        let key = base_key(TEST_WINDOW_START);
        let format = key.format.clone();
        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // First request: miss, builds, goes to protected tier.
        let out1 = cache
            .get_or_build(
                &key,
                {
                    let builds = builds.clone();
                    let format = format.clone();
                    || async move {
                        builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok::<_, std::convert::Infallible>(CachedToken::new(
                            Bytes::from(vec![7u8, 8, 9]),
                            &format,
                            TEST_WINDOW_START,
                        ))
                    }
                },
                TEST_WINDOW_START,
            )
            .await
            .expect("infallible");
        assert_eq!(out1.bytes.as_ref(), &[7u8, 8, 9][..]);

        // Second request: hit in protected tier, no re-sign.
        let out2 = cache
            .get_or_build(
                &key,
                {
                    let builds = builds.clone();
                    let format = format.clone();
                    || async move {
                        builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok::<_, std::convert::Infallible>(CachedToken::new(
                            Bytes::from(vec![1u8, 2, 3]),
                            &format,
                            TEST_WINDOW_START,
                        ))
                    }
                },
                TEST_WINDOW_START,
            )
            .await
            .expect("infallible");
        assert_eq!(out2.bytes.as_ref(), &[7u8, 8, 9][..]);

        // Third request: still a hit.
        let out3 = cache
            .get(&key, TEST_WINDOW_START)
            .await
            .expect("protected entry must be present");
        assert_eq!(out3.bytes.as_ref(), &[7u8, 8, 9][..]);

        assert_eq!(
            builds.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "protected tier must prevent re-signing even with cold tier disabled"
        );
    }

    #[test]
    fn entry_weight_is_byte_length() {
        // The cache's `max_capacity` is a byte budget: each entry is weighed by
        // its signed-token byte length, so a large list consumes proportionally
        // more of the budget than a small one.
        let key = base_key(TEST_WINDOW_START);
        let small = CachedToken::new(Bytes::from(vec![1u8, 2, 3]), &key.format, TEST_WINDOW_START);
        assert_eq!(entry_weight(&key, &small), 3);

        let large = CachedToken::new(Bytes::from(vec![0u8; 2048]), &key.format, TEST_WINDOW_START);
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
        let key = base_key(TEST_WINDOW_START);
        cache
            .insert(
                key.clone(),
                CachedToken::new(Bytes::from(vec![0u8; 512]), &key.format, TEST_WINDOW_START),
                TEST_WINDOW_START,
            )
            .await;
        assert!(
            cache.get(&key, TEST_WINDOW_START).await.is_some(),
            "default byte budget must retain and serve a representative token"
        );
    }

    #[test]
    fn entry_expiry_targets_window_end() {
        // Each entry expires at the end of its own anchored validity window,
        // independent of any global TTL. Under the ticket 564 proposal the
        // window width is `exp_secs` (a window is a token's full lifetime):
        // `base_key(TEST_WINDOW_START)` has `exp_secs = 900`, so the window is
        // `[TEST_WINDOW_START, TEST_WINDOW_START + 900)`. An entry created at
        // TEST_WINDOW_START + 200 must live for exactly 700 seconds, not the
        // full 900s runway.
        let key = base_key(TEST_WINDOW_START);
        let value = CachedToken::new(Bytes::from(vec![1u8]), &key.format, TEST_WINDOW_START + 200);
        let duration = EntryExpiry
            .expire_after_create(&key, &value, std::time::Instant::now())
            .expect("a window-end expiry is always set");
        assert_eq!(duration, Duration::from_secs(700));

        // A different exp yields a different width and thus a different expiry:
        // exp=1200 -> window [TEST_WINDOW_START, TEST_WINDOW_START + 1200), so
        // an entry created at TEST_WINDOW_START + 200 lives 1000s.
        let key = TokenCacheKey {
            token_exp_secs: 1200,
            ..base_key(TEST_WINDOW_START)
        };
        let value = CachedToken::new(Bytes::from(vec![1u8]), &key.format, TEST_WINDOW_START + 200);
        let duration = EntryExpiry
            .expire_after_create(&key, &value, std::time::Instant::now())
            .expect("a window-end expiry is always set");
        assert_eq!(duration, Duration::from_secs(1000));
    }
}
