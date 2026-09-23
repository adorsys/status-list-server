use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache as MokaCache;
use opentelemetry::{
    metrics::Counter,
    {KeyValue, global},
};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenEncoding {
    Identity,
    Gzip,
}

/// One cached signed representation: the served opaque bytes plus the
/// `Content-Encoding` they were produced with (feeds the response header).
#[derive(Debug, Clone)]
pub(crate) struct CachedToken {
    pub(crate) bytes: Arc<Vec<u8>>,
    pub(crate) encoding: Option<&'static str>,
}

/// An in-memory cache of fully signed, serialised status-list token bytes.
///
/// Entries are keyed by `(list content hash, window_start, format, gzip)` and
/// are valid for exactly the anchored token window `[window_start,
/// window_start + exp_secs)`. Because `iat` is anchored to `window_start`, the
/// bytes are identical for every request in the same window, so the cache lets
/// a fresh `200` reuse a single sign per `(list, window, format)` per replica.
///
/// Content changes and list identity are covered by the key: a changed list has
/// a different content hash (immediate miss), and `list_id` keeps otherwise
/// identical `(content, window, format)` values from different lists distinct.
/// Expiry is covered by the window bound checked at lookup time plus moka's
/// `time_to_live`, so no eager invalidation is needed.
///
/// Per-replica by design: ETag consistency across replicas is out of scope and
/// would require a shared store (see the ticket's open questions).
#[derive(Clone, Debug)]
pub struct TokenBytesCache {
    inner: MokaCache<String, CachedToken>,
}

impl TokenBytesCache {
    /// Build an in-process signed-token bytes cache.
    ///
    /// `ttl_secs` bounds how long an entry may be retained by moka in addition
    /// to its window-based validity; `max_capacity` bounds memory for large
    /// lists. Both are floor-clamped to 1 so moka's builder never misbehaves.
    pub(crate) fn new(ttl_secs: u64, max_capacity: u64) -> Self {
        let inner = MokaCache::builder()
            .time_to_live(Duration::from_secs(ttl_secs.max(1)))
            .max_capacity(max_capacity.max(1))
            .build();
        Self { inner }
    }

    /// Look up cached bytes for `key`, only returning a hit for an entry whose
    /// anchored window `[window_start, window_start + exp_secs)` still contains
    /// `now`. Past that bound the bytes are expired and must be re-signed.
    pub(crate) async fn get(
        &self,
        key: &str,
        window_start: i64,
        exp_secs: i64,
        now: i64,
    ) -> Option<CachedToken> {
        // Guard the window bound explicitly so a closed window never serves
        // bytes beyond their `exp` even before moka's own TTL fires.
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

    pub(crate) async fn insert(&self, key: String, value: CachedToken) {
        self.inner.insert(key, value).await;
    }
}

/// Build the composite cache key for a live status-list token.
///
/// The content hash is the SHA-256 over the representation-driving fields of
/// `record` (same inputs the ETag used to hash), so any content change produces
/// a different key and thus a fresh sign.
pub(crate) fn token_bytes_cache_key(
    list_id: &str,
    content_hash: &str,
    window_start: i64,
    format: &str,
    encoding: TokenEncoding,
) -> String {
    let gzip = match encoding {
        TokenEncoding::Identity => 0,
        TokenEncoding::Gzip => 1,
    };
    format!("{list_id}\u{1f}{content_hash}\u{1f}{window_start}\u{1f}{format}\u{1f}{gzip}")
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

    async fn cached(w: i64) -> (TokenBytesCache, String) {
        let cache = TokenBytesCache::new(300, 100);
        let key = token_bytes_cache_key("list", "hash", w, "jwt", TokenEncoding::Identity);
        cache
            .insert(
                key.clone(),
                CachedToken {
                    bytes: Arc::new(vec![1, 2, 3]),
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
    async fn key_dimensions_are_distinct() {
        let base = token_bytes_cache_key("l", "h", 1000, "jwt", TokenEncoding::Identity);
        let other_window = token_bytes_cache_key("l", "h", 1001, "jwt", TokenEncoding::Identity);
        let other_format = token_bytes_cache_key("l", "h", 1000, "cwt", TokenEncoding::Identity);
        let other_gzip = token_bytes_cache_key("l", "h", 1000, "jwt", TokenEncoding::Gzip);
        let other_list = token_bytes_cache_key("l2", "h", 1000, "jwt", TokenEncoding::Identity);
        assert_ne!(base, other_window);
        assert_ne!(base, other_format);
        assert_ne!(base, other_gzip);
        assert_ne!(base, other_list);
        assert_eq!(
            base,
            token_bytes_cache_key("l", "h", 1000, "jwt", TokenEncoding::Identity)
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

        let cache = TokenBytesCache::new(300, 100);
        let key = token_bytes_cache_key("l", "h", 1000, "jwt", TokenEncoding::Identity);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            cache
                .insert(
                    key.clone(),
                    CachedToken {
                        bytes: Arc::new(vec![1]),
                        encoding: None,
                    },
                )
                .await;
            assert!(cache.get(&key, 1000, 900, 1400).await.is_some());
            assert!(cache.get(&key, 1000, 900, 1400).await.is_some()); // hit again
            assert!(cache.get("missing", 1000, 900, 1400).await.is_none());
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
