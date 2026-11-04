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

use crate::server::handlers::status_list::utils::conditional::window_width;
use crate::server::handlers::status_list::utils::etag::generate_token_etag;

const HIT_METRIC: &str = "token_bytes_cache_hits";
const MISS_METRIC: &str = "token_bytes_cache_misses";
const ENTRY_COUNT_METRIC: &str = "token_bytes_cache_entries";
const TOTAL_BYTES_METRIC: &str = "token_bytes_cache_size";

/// Resolved through `cached_instruments` so a new meter provider never leaves no-op handles.
#[derive(Clone)]
struct TokenCacheMetrics {
    hits: Counter<u64>,
    misses: Counter<u64>,
    // Held only to keep the gauges registered; they're read via callbacks.
    #[allow(dead_code)]
    entry_count: ObservableGauge<u64>,
    #[allow(dead_code)]
    total_bytes: ObservableGauge<u64>,
}

/// Latest generation inside its window; capacity pressure never evicts it.
#[derive(Debug, Clone)]
struct ProtectedEntry {
    token: CachedToken,
    window_end: i64,
}

/// One slot is enough: production builds a single cache per replica.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TokenEncoding {
    Identity,
    Gzip,
}

/// Encoded variants are computed once at insert, so a 304 never re-compresses.
#[derive(Debug, Clone)]
pub(crate) struct CachedToken {
    pub(crate) bytes: Bytes,
    pub(crate) identity_etag: String,
    /// JWT only; CWT is never gzipped.
    pub(crate) gzip_bytes: Option<Bytes>,
    pub(crate) gzip_etag: Option<String>,
    pub(crate) created_at_unix: i64,
}

impl CachedToken {
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

fn compress_gzip(bytes: &[u8]) -> Bytes {
    use std::io::Write as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    // Writing into a Vec can't fail; if it ever did, the plain bytes would be served as gzip.
    if encoder.write_all(bytes).is_ok()
        && let Ok(compressed) = encoder.finish()
    {
        return Bytes::from(compressed);
    }
    Bytes::from(bytes.to_vec())
}

/// `version` keeps an A -> B -> A revert inside one window from reusing stale bytes.
/// Encoding isn't a field: gzip and identity come from the same signed bytes.
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

/// Per-replica cache of signed tokens, at most one sign per (list, window, format).
/// Live entries sit in a protected tier that capacity pressure never evicts.
#[derive(Clone, Debug)]
pub struct TokenBytesCache {
    /// Superseded generations and closed windows; evictable.
    cold: MokaCache<TokenCacheKey, CachedToken>,
    /// Arc because cloning a DashMap copies it, and clones must share state.
    protected: Arc<DashMap<TokenCacheKey, ProtectedEntry>>,
    latest_generation: Arc<DashMap<String, u64>>,
}

/// Weigh by bytes, not count: lists range from a few hundred bytes to over 1 MiB.
fn entry_weight(_key: &TokenCacheKey, value: &CachedToken) -> u32 {
    value.bytes.len() as u32
}

/// Each entry expires when its window closes; reads don't extend it.
#[derive(Debug, Clone, Copy, Default)]
struct EntryExpiry;

impl Expiry<TokenCacheKey, CachedToken> for EntryExpiry {
    fn expire_after_create(
        &self,
        key: &TokenCacheKey,
        value: &CachedToken,
        _created_at: Instant,
    ) -> Option<Duration> {
        let secs = (window_end(key) - value.created_at_unix).max(1) as u64;
        Some(Duration::from_secs(secs))
    }
}

fn window_end(key: &TokenCacheKey) -> i64 {
    key.window_start
        .saturating_add(window_width(key.token_exp_secs))
}

impl TokenBytesCache {
    /// The byte budget only covers the cold tier; 0 disables it.
    /// The protected tier is bounded by the number of active lists instead.
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
        token_cache_metrics();
        set_size_gauge_cache(cache.clone());
        cache
    }

    /// Concurrent misses share one build; nothing is cached if `init` fails.
    /// Call `invalidate_superseded` afterwards so older generations get reclaimed.
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

        if let Some(entry) = self.protected.get(key) {
            if entry.window_end > now {
                metrics
                    .hits
                    .add(1, &[KeyValue::new("cache", "token_bytes")]);
                return Ok(entry.token.clone());
            } else {
                let entry = self.protected.remove(key).map(|(_, v)| v).unwrap();
                self.cold.insert(key.clone(), entry.token).await;
            }
        }

        // Build through the cold tier so moka coalesces concurrent misses.
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

        // Waiters that joined an in-flight build still count as misses.
        metrics
            .misses
            .add(1, &[KeyValue::new("cache", "token_bytes")]);

        // A newer generation may have landed while we built; don't keep stale bytes.
        let window_end = window_end(key);
        let mut latest_gen = self
            .latest_generation
            .entry(key.list_id.clone())
            .or_insert(0);
        if key.version < *latest_gen {
            self.cold.invalidate(key).await;
        } else if key.version >= *latest_gen && window_end > now {
            *latest_gen = key.version;
            self.protected.insert(
                key.clone(),
                ProtectedEntry {
                    token: value.clone(),
                    window_end,
                },
            );
        }
        Ok(value)
    }

    #[cfg(test)]
    async fn insert_tiered(&self, key: TokenCacheKey, value: CachedToken, now: i64) {
        let window_end = window_end(&key);

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

    /// Safe to race with an older build: its key has the old version, so it's never served.
    pub(crate) async fn invalidate_superseded(&self, list_id: &str, version: u64, now: i64) {
        let mut latest_gen = self
            .latest_generation
            .entry(list_id.to_string())
            .or_insert(0);
        if version > *latest_gen {
            *latest_gen = version;
        }

        self.protected
            .retain(|k, _| !(k.list_id == list_id && k.version < version));

        let stale_keys: Vec<TokenCacheKey> = self
            .cold
            .iter()
            .filter(|(k, _)| k.list_id == list_id && k.version < version)
            .map(|(k, _)| k.as_ref().clone())
            .collect();
        for key in stale_keys {
            self.cold.invalidate(&key).await;
        }

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

    const TEST_WINDOW_START: i64 = 10_000_000_000;

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
        let cache = TokenBytesCache::new(3);

        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let target_key = TokenCacheKey {
            list_id: "target-list".to_string(),
            ..base_key(TEST_WINDOW_START)
        };

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
        let cache = TokenBytesCache::new(1);
        let key_a = TokenCacheKey {
            list_id: "list-a".to_string(),
            ..base_key(TEST_WINDOW_START)
        };

        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

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

        let a2 = cache
            .get(&key_a, TEST_WINDOW_START)
            .await
            .expect("protected entry must be present");
        assert_eq!(*a2.bytes, vec![1]);

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

        let format_v1 = key_v1.format.clone();
        let cache_clone = cache.clone();
        let key_v1_clone = key_v1.clone();
        let builds_v1_clone = builds_v1.clone();
        let slow_build = tokio::spawn(async move {
            cache_clone
                .get_or_build(
                    &key_v1_clone,
                    || async move {
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

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

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

        cache
            .invalidate_superseded(&list_id, 2, TEST_WINDOW_START)
            .await;

        slow_build
            .await
            .expect("slow build task")
            .expect("infallible");

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

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

        assert!(
            cache.get(&key_v1, TEST_WINDOW_START).await.is_none(),
            "stale v1 build must not remain cached after invalidation"
        );

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
            assert!(cache.get(&cache_key, TEST_WINDOW_START).await.is_some());
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
        let cache = TokenBytesCache::new(0);
        let key = base_key(TEST_WINDOW_START);
        let format = key.format.clone();
        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

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
        let key = base_key(TEST_WINDOW_START);
        let small = CachedToken::new(Bytes::from(vec![1u8, 2, 3]), &key.format, TEST_WINDOW_START);
        assert_eq!(entry_weight(&key, &small), 3);

        let large = CachedToken::new(Bytes::from(vec![0u8; 2048]), &key.format, TEST_WINDOW_START);
        assert_eq!(entry_weight(&key, &large), 2048);
    }

    #[tokio::test]
    async fn default_config_retains_representative_token() {
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
        let key = base_key(TEST_WINDOW_START);
        let value = CachedToken::new(Bytes::from(vec![1u8]), &key.format, TEST_WINDOW_START + 200);
        let duration = EntryExpiry
            .expire_after_create(&key, &value, std::time::Instant::now())
            .expect("a window-end expiry is always set");
        assert_eq!(duration, Duration::from_secs(700));

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
