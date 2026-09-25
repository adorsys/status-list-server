use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache as MokaCache;
use moka::sync::Cache as MokaSyncCache;
use opentelemetry::{
    metrics::Counter,
    {KeyValue, global},
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::domain::ports::SigningMaterial;

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
/// Entries are keyed by `(list content hash, signer fingerprint, window_start,
/// format, gzip)` and are valid for exactly the anchored token window
/// `[window_start, window_start + exp_secs)`. Because `iat` is anchored to
/// `window_start`, the bytes are identical for every request in the same window,
/// so the cache lets a fresh `200` reuse a single sign per `(list, window,
/// format)` per replica.
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
    inner: MokaCache<String, CachedToken>,
    /// Per-key in-flight locks that serialize the expensive re-sign path so that
    /// concurrent misses for the same key build the token only once (single
    /// flight). Steady-state hits take the lock-free fast path in
    /// [`TokenBytesCache::get_or_build`], so this only ever contends during a
    /// genuine miss.
    inflight: MokaSyncCache<String, Arc<Mutex<()>>>,
}

impl TokenBytesCache {
    /// Build an in-process signed-token bytes cache.
    ///
    /// `ttl_secs` bounds how long an entry may be retained by moka in addition
    /// to its window-based validity; `max_capacity` bounds memory for large
    /// lists. A `ttl_secs` of `0` preserves the "cache disabled" semantics used
    /// elsewhere in this codebase (`MokaStatusListCache`): entries expire
    /// immediately and every request re-signs. Callers should set `ttl_secs` to
    /// at least `token_exp_secs` so an entry is not evicted in the middle of a
    /// validity window (a shorter value only means more re-signs).
    pub(crate) fn new(ttl_secs: u64, max_capacity: u64) -> Self {
        if ttl_secs == 0 {
            tracing::info!("Signed-token bytes cache disabled (TTL=0)");
        }
        let inner = MokaCache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(max_capacity)
            .build();
        let inflight = MokaSyncCache::builder().max_capacity(max_capacity).build();
        Self { inner, inflight }
    }

    /// Return cached bytes for `key`, only for an entry whose anchored window
    /// `[window_start, window_start + exp_secs)` still contains `now`. Past that
    /// bound the bytes are expired and must be re-signed.
    ///
    /// Unlike a plain lookup, a miss is not simply reported: `init` is invoked
    /// to build the token, deduplicated through a per-key in-flight lock so at
    /// most one builder runs per `key` under concurrency (the #564 "single sign
    /// per window per replica" guarantee). Callers that are not interested in
    /// building should use `get` instead.
    ///
    /// Returns `Ok(None)` when the window is already closed (the bytes are not
    /// cached and `init` is *not* called); the caller must re-sign with a fresh
    /// window. Returns `Ok(Some(_))` on a hit or a successful build, and
    /// `Err(e)` if `init` fails (nothing is cached on error).
    pub(crate) async fn get_or_build<F, Fut, E>(
        &self,
        key: &str,
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
        // exactly once. moka's sync cache bounds the number of live lock entries.
        let lock = self
            .inflight
            .get_with(key.to_string(), || Arc::new(Mutex::new(())));
        let _guard = lock.lock().await;

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
        self.inner.insert(key.to_string(), value.clone()).await;
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
        key: &str,
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
    pub(crate) async fn insert(&self, key: String, value: CachedToken) {
        self.inner.insert(key, value).await;
    }
}

/// Build the composite cache key for a live status-list token.
///
/// The content hash is the SHA-256 over the representation-driving fields of
/// `record`; the signer fingerprint is derived from the current signing
/// material (key PEM + certificate chain) so rotating the signing key or
/// renewing the certificate produces a different key and forces a fresh sign.
/// `aggregation_uri` and `token_ttl_secs` are folded in too because both are
/// embedded in the signed token bytes, so a config change to either (not just a
/// record content change) must also invalidate cached bytes.
#[allow(clippy::too_many_arguments)] // each parameter is a distinct cache-key dimension
pub(crate) fn token_bytes_cache_key(
    list_id: &str,
    content_hash: &str,
    signer_fingerprint: &str,
    window_start: i64,
    format: &str,
    encoding: TokenEncoding,
    aggregation_uri: &str,
    token_ttl_secs: u64,
    token_exp_secs: u64,
) -> String {
    let gzip = match encoding {
        TokenEncoding::Identity => 0,
        TokenEncoding::Gzip => 1,
    };
    format!(
        "{list_id}\u{1f}{content_hash}\u{1f}{signer_fingerprint}\u{1f}{window_start}\u{1f}{format}\u{1f}{gzip}\u{1f}{aggregation_uri}\u{1f}{token_ttl_secs}\u{1f}{token_exp_secs}"
    )
}

/// A stable digest of the exact signing material (private key PEM and the
/// certificate chain) that produced a token's signature.
///
/// Every provider serves `SigningMaterial` from an in-memory atomic snapshot that
/// is swapped atomically on rotation/renewal, so computing this on the hot path is
/// a cheap in-memory hash, not a key-load or network call. It changes whenever the
/// key or its certificate changes, which is what makes the signed-bytes cache
/// self-invalidating on rotation.
pub(crate) fn signer_fingerprint(material: &SigningMaterial) -> String {
    let mut hasher = Sha256::new();
    hasher.update(material.signing_key.algorithm().to_string().as_bytes());
    hasher.update(material.signing_key.public_key_bytes());
    if let Some(chain) = &material.certificate_chain {
        for part in chain {
            hasher.update(part.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
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
        let key = key(
            "list",
            "hash",
            "signer",
            w,
            "jwt",
            TokenEncoding::Identity,
            "",
            300,
            900,
        );
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

    /// Test helper filling the aggregation/ttl/exp key dimensions with defaults.
    #[allow(clippy::too_many_arguments)]
    fn key(
        list_id: &str,
        content_hash: &str,
        signer: &str,
        w: i64,
        format: &str,
        encoding: TokenEncoding,
        aggregation_uri: &str,
        ttl: u64,
        exp: u64,
    ) -> String {
        token_bytes_cache_key(
            list_id,
            content_hash,
            signer,
            w,
            format,
            encoding,
            aggregation_uri,
            ttl,
            exp,
        )
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
        // #564 criterion #2: at most one signing operation per (list, window,
        // format) per replica. N concurrent misses for the same key must run the
        // builder exactly once and share the resulting bytes.
        let cache = TokenBytesCache::new(300, 100);
        let key_str = key(
            "list",
            "hash",
            "signer",
            1000,
            "jwt",
            TokenEncoding::Identity,
            "",
            300,
            900,
        );

        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let key_str = key_str.clone();
            let builds = builds.clone();
            handles.push(tokio::spawn(async move {
                let out = cache
                    .get_or_build(&key_str, 1000, 900, 1400, || {
                        let builds = builds.clone();
                        async move {
                            builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(CachedToken {
                                bytes: Arc::new(vec![7u8, 8, 9]),
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

    #[tokio::test]
    async fn key_dimensions_are_distinct() {
        let b = &("list", "hash", "signer", 1000i64, "jwt");
        let base = key(
            b.0,
            b.1,
            b.2,
            b.3,
            b.4,
            TokenEncoding::Identity,
            "",
            300,
            900,
        );
        let other_window = key(
            b.0,
            b.1,
            b.2,
            1001,
            b.4,
            TokenEncoding::Identity,
            "",
            300,
            900,
        );
        let other_signer = key(
            b.0,
            b.1,
            "signer2",
            1000,
            b.4,
            TokenEncoding::Identity,
            "",
            300,
            900,
        );
        let other_format = key(
            b.0,
            b.1,
            b.2,
            1000,
            "cwt",
            TokenEncoding::Identity,
            "",
            300,
            900,
        );
        let other_gzip = key(
            b.0,
            b.1,
            b.2,
            1000,
            "jwt",
            TokenEncoding::Gzip,
            "",
            300,
            900,
        );
        let other_list = key(
            "list2",
            b.1,
            b.2,
            1000,
            "jwt",
            TokenEncoding::Identity,
            "",
            300,
            900,
        );
        let other_aggregation = key(
            b.0,
            b.1,
            b.2,
            1000,
            "jwt",
            TokenEncoding::Identity,
            "https://agg",
            300,
            900,
        );
        let other_ttl = key(
            b.0,
            b.1,
            b.2,
            1000,
            "jwt",
            TokenEncoding::Identity,
            "",
            600,
            900,
        );
        let other_exp = key(
            b.0,
            b.1,
            b.2,
            1000,
            "jwt",
            TokenEncoding::Identity,
            "",
            300,
            1200,
        );

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
        assert_eq!(
            base,
            key(
                b.0,
                b.1,
                b.2,
                1000,
                b.4,
                TokenEncoding::Identity,
                "",
                300,
                900
            )
        );
    }

    #[test]
    fn signer_fingerprint_changes_when_material_changes() {
        let key_a: Arc<dyn crate::domain::ports::TokenSigner> = Arc::new(
            crate::utils::crypto::SigningKey::generate(
                crate::domain::models::token::SigningAlgorithm::Es256,
            )
            .unwrap(),
        );
        let key_b: Arc<dyn crate::domain::ports::TokenSigner> = Arc::new(
            crate::utils::crypto::SigningKey::generate(
                crate::domain::models::token::SigningAlgorithm::Es256,
            )
            .unwrap(),
        );

        let material_a = SigningMaterial::new(Some(vec!["cert-a".to_string()]), Arc::clone(&key_a));
        let material_b = SigningMaterial::new(Some(vec!["cert-a".to_string()]), Arc::clone(&key_b));
        let material_c = SigningMaterial::new(None, Arc::clone(&key_a));

        let fp_a = signer_fingerprint(&material_a);
        let fp_b = signer_fingerprint(&material_b);
        let fp_c = signer_fingerprint(&material_c);
        assert_eq!(fp_a, signer_fingerprint(&material_a), "deterministic");
        assert_ne!(fp_a, fp_b, "key rotation must change the fingerprint");
        assert_ne!(fp_a, fp_c, "certificate change must change the fingerprint");
        assert_eq!(fp_a.len(), 64, "sha-256 hex digest");
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
        let key = key(
            "l",
            "h",
            "s",
            1000,
            "jwt",
            TokenEncoding::Identity,
            "",
            300,
            900,
        );
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
