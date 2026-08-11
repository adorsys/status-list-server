//! Construction and lifecycle of the rate-limit tiers.
//!
//! Route composition lives in [`crate::startup`]; everything about *how* the
//! limiters are built, bounded, observed and rendered lives here.

use std::hash::Hash;
use std::sync::{Arc, Weak};
use std::time::Duration;

use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, Response, StatusCode, header},
};
use color_eyre::eyre::eyre;
use governor::{
    clock::QuantaInstant,
    middleware::{NoOpMiddleware, RateLimitingMiddleware},
};
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Meter, ObservableGauge},
};
use tokio::task::JoinHandle;
use tower_governor::{
    GovernorLayer,
    errors::GovernorError,
    governor::{GovernorConfig, GovernorConfigBuilder, SharedRateLimiter},
    key_extractor::KeyExtractor,
};

use super::{SecureIpKeyExtractor, VerifiedIssuerKeyExtractor};
use crate::config::RateLimitConfig;
use crate::server::error::ErrorResponse;

/// Governor middleware that attaches `x-ratelimit-*` headers to *successful*
/// responses, as opposed to [`NoOpMiddleware`] which attaches none.
type RateLimitHeaders = governor::middleware::StateInformationMiddleware;

/// Names the tier that rejected a request, so clients can branch on it without
/// parsing `error_description`.
static X_RATELIMIT_TIER: HeaderName = HeaderName::from_static("x-ratelimit-tier");

/// A tier that reports its budget to clients. Only ever the innermost limiter
/// on a route  -  see [`GovernorPolicies`].
type ReportingIpGovernor = Arc<GovernorConfig<SecureIpKeyExtractor, RateLimitHeaders>>;
/// A tier that does not report its budget, because another tier on the same
/// route already does.
type SilentIpGovernor = Arc<GovernorConfig<SecureIpKeyExtractor, NoOpMiddleware>>;
type IssuerGovernor = Arc<GovernorConfig<VerifiedIssuerKeyExtractor, RateLimitHeaders>>;

/// The rate-limit tiers, ordered by the strength of the identity they key on.
///
/// Only [`GovernorPolicies::issuer`] is keyed on something unforgeable without
/// credential theft. The IP-keyed tiers are a coarse gate on anonymous traffic:
/// they are best-effort by nature, which is precisely why nothing
/// security-critical is allowed to depend on them alone.
///
/// # Which tier reports `x-ratelimit-*`
///
/// At most one limiter per route may carry [`RateLimitHeaders`].
/// `StateInformationMiddleware` merges its headers with
/// `HeaderMap::extend`, which *appends* rather than replaces, so two reporting
/// tiers on one route emit two `x-ratelimit-limit` and two
/// `x-ratelimit-remaining` values describing different budgets. The write
/// routes therefore report from [`Self::issuer`]  -  the tier whose budget a
/// legitimate authenticated caller actually spends  -  and [`Self::write_gate`]
/// stays silent. `retry-after` is unaffected: it is attached on rejection by
/// both middlewares, so a client throttled by the gate still learns how long to
/// wait.
pub struct GovernorPolicies {
    /// Issuer registration  -  unauthenticated by design.
    ///
    /// Note that this tier keys on the *derived* client IP, so under a
    /// misconfigured `client_ip_source` it becomes client-influenced. That is a
    /// deliberate trade for topology-correctness, but it means a wrong
    /// `client_ip_source` widens beyond throttling accuracy: it also weakens
    /// the gate on credential registration.
    pub credentials: ReportingIpGovernor,
    /// Coarse gate in front of the auth middleware on the write routes.
    ///
    /// Keying writes on the verified issuer means auth  -  and therefore a
    /// credential lookup  -  has to run *before* the per-issuer limiter. This
    /// tier bounds that: anonymous traffic cannot drive unbounded credential
    /// lookups. It has its own budget rather than borrowing another tier's, so
    /// that tuning reads or issuer writes cannot silently retune it.
    pub write_gate: SilentIpGovernor,
    /// Authenticated writes, keyed on the verified credential issuer.
    pub issuer: IssuerGovernor,
    /// Public reads.
    pub reads: ReportingIpGovernor,
}

/// Background bucket eviction plus the instruments observing it.
///
/// Owning the [`JoinHandle`] means the sweep stops when the server is dropped,
/// instead of outliving it  -  which matters because `HttpServer::new` can be
/// called more than once in a process.
///
/// The bucket gauge cannot be unregistered from an OpenTelemetry meter, so
/// instead its callback holds a [`Weak`] reference to the tier handles owned
/// here. When this struct drops, the callback stops observing rather than
/// reporting stale numbers from a limiter nothing is serving any more.
pub struct RateLimitRuntime {
    eviction_task: JoinHandle<()>,
    tiers: Arc<Vec<TierHandle>>,
    _buckets_gauge: ObservableGauge<u64>,
}

impl Drop for RateLimitRuntime {
    fn drop(&mut self) {
        self.eviction_task.abort();
        // Dropping the last strong reference is what silences the gauge
        // callback; asserted so the coupling cannot be broken silently.
        debug_assert_eq!(
            Arc::strong_count(&self.tiers),
            1,
            "the gauge callback must hold only a Weak reference"
        );
    }
}

/// Type-erased access to one tier's limiter.
///
/// Erased because the tiers differ in their middleware type, and because a
/// single sweep task over all of them is both simpler and kinder than four
/// timers waking on the same interval.
struct TierHandle {
    tier: &'static str,
    live: Box<dyn Fn() -> usize + Send + Sync>,
    /// Runs one eviction pass and returns the resulting bucket count.
    sweep: Box<dyn Fn() -> usize + Send + Sync>,
}

impl TierHandle {
    fn new<Key, M>(tier: &'static str, limiter: SharedRateLimiter<Key, M>) -> Self
    where
        Key: Hash + Eq + Clone + Send + Sync + 'static,
        M: RateLimitingMiddleware<QuantaInstant> + Send + Sync + 'static,
    {
        let for_len = limiter.clone();
        Self {
            tier,
            live: Box::new(move || for_len.len()),
            sweep: Box::new(move || {
                let before = limiter.len();
                limiter.retain_recent();
                let after = limiter.len();
                if should_shrink(before, after) {
                    limiter.shrink_to_fit();
                }
                after
            }),
        }
    }
}

/// Whether a sweep freed enough to be worth reclaiming the map's capacity.
///
/// `retain_recent` removes entries but leaves capacity at its high-water mark,
/// and `shrink_to_fit` reallocates. Shrinking on every tick would make a
/// steady-state limiter pay for a reallocation forever, so it is done only when
/// the sweep removed more than half of what remains.
///
/// Split out so the boundary is testable without timing a real sweep.
fn should_shrink(before: usize, after: usize) -> bool {
    before.saturating_sub(after) > after / 2
}

impl GovernorPolicies {
    /// The [`Meter`] is used by the IP extractors to report when the configured
    /// client-IP source could not be used; see `rate_limit_ip_source_fallback`.
    pub fn build(config: &RateLimitConfig, meter: &Meter) -> color_eyre::Result<Self> {
        // `Config::load` refuses to build without this; the error path here
        // only guards against a `RateLimitConfig` constructed some other way.
        let source = config.client_ip_source.ok_or_else(|| {
            eyre!("rate_limit.client_ip_source is unset; the client IP source must be configured")
        })?;

        // Parsed once here rather than per request; `validate` has already
        // rejected an empty set for a header source and a non-empty one for
        // `connect_info`.
        let trusted_proxies: Arc<[ipnet::IpNet]> = Arc::from(config.parse_trusted_proxies()?);
        let key = |tier| {
            SecureIpKeyExtractor::new(
                source,
                config.trusted_hops,
                Arc::clone(&trusted_proxies),
                tier,
                meter,
            )
        };

        let reporting = |tier: &'static str,
                         burst: u32,
                         period_secs: u64|
         -> color_eyre::Result<ReportingIpGovernor> {
            GovernorConfigBuilder::default()
                .burst_size(burst)
                .period(Duration::from_secs(period_secs))
                .key_extractor(key(tier))
                .use_headers()
                .finish()
                .map(Arc::new)
                .ok_or_else(|| eyre!("{tier} governor requires a non-zero burst_size and period"))
        };

        Ok(Self {
            credentials: reporting(
                "credentials",
                config.credentials_burst_size,
                config.credentials_period_secs,
            )?,
            reads: reporting("reads", config.reads_burst_size, config.reads_period_secs)?,
            // Silent on purpose: the issuer tier reports on these routes.
            write_gate: Arc::new(
                GovernorConfigBuilder::default()
                    .burst_size(config.write_gate_burst_size)
                    .period(Duration::from_secs(config.write_gate_period_secs))
                    .key_extractor(key("write_gate"))
                    .finish()
                    .ok_or_else(|| {
                        eyre!("write_gate governor requires a non-zero burst_size and period")
                    })?,
            ),
            issuer: Arc::new(
                GovernorConfigBuilder::default()
                    .burst_size(config.issuer_burst_size)
                    .period(Duration::from_secs(config.issuer_period_secs))
                    .key_extractor(VerifiedIssuerKeyExtractor)
                    .use_headers()
                    .finish()
                    .ok_or_else(|| {
                        eyre!("issuer governor requires a non-zero burst_size and period")
                    })?,
            ),
        })
    }

    fn tier_handles(&self) -> Vec<TierHandle> {
        vec![
            TierHandle::new("credentials", self.credentials.limiter().clone()),
            TierHandle::new("write_gate", self.write_gate.limiter().clone()),
            TierHandle::new("issuer", self.issuer.limiter().clone()),
            TierHandle::new("reads", self.reads.limiter().clone()),
        ]
    }

    /// Starts the eviction sweep and registers the bucket-count gauge.
    ///
    /// The [`Meter`] is passed in rather than looked up from the OpenTelemetry
    /// global, so that tests can observe these instruments through their own
    /// provider without racing on process-wide state.
    pub fn spawn_runtime(&self, config: &RateLimitConfig, meter: &Meter) -> RateLimitRuntime {
        let tiers = Arc::new(self.tier_handles());
        let interval = Duration::from_secs(config.bucket_eviction_interval_secs);
        let max_buckets = config.max_buckets;

        let eviction_task = {
            let tiers = Arc::downgrade(&tiers);
            tokio::spawn(async move {
                let mut timer = tokio::time::interval(interval);
                timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    timer.tick().await;
                    // Stops as soon as the owning runtime is gone, so a task
                    // that outlives its abort still does nothing.
                    let Some(tiers) = tiers.upgrade() else {
                        return;
                    };
                    // `retain_recent` walks every bucket and takes DashMap
                    // shard locks that the request path also needs, so a sweep
                    // over a large tier is a blocking CPU operation, not an
                    // await point. Running it inline would stall every other
                    // task on this worker thread; `spawn_blocking` moves it to
                    // the blocking pool, and one tier per call keeps any single
                    // unit of work small.
                    for index in 0..tiers.len() {
                        let tiers = Arc::clone(&tiers);
                        let swept = tokio::task::spawn_blocking(move || {
                            sweep_tier(&tiers[index], max_buckets)
                        })
                        .await;
                        if let Err(error) = swept {
                            tracing::warn!(%error, "rate-limit eviction sweep failed");
                        }
                    }
                }
            })
        };

        let observed: Weak<Vec<TierHandle>> = Arc::downgrade(&tiers);
        let buckets_gauge = meter
            .u64_observable_gauge("rate_limit_buckets")
            .with_description("Live rate-limit buckets held by each limiter tier.")
            .with_callback(move |observer| {
                // Absent once the owning runtime has been dropped.
                let Some(tiers) = observed.upgrade() else {
                    return;
                };
                for handle in tiers.iter() {
                    observer.observe(
                        (handle.live)() as u64,
                        &[KeyValue::new("tier", handle.tier)],
                    );
                }
            })
            .build();

        RateLimitRuntime {
            eviction_task,
            tiers,
            _buckets_gauge: buckets_gauge,
        }
    }
}

/// Drops buckets that have returned to their starting state, and alerts if the
/// tier is still above its ceiling afterwards.
///
/// `max_buckets` is a ceiling to alert on, not a hard cap  -  `governor` offers no
/// admission control. The real bound on the key space is structural: the issuer
/// tier can only be keyed by credentials that verified against the store, and
/// the IP tiers bucket IPv6 clients by /64. This sweep is memory hygiene on top
/// of that, and the log line is the signal that the structural bound is not
/// holding.
/// Returns the post-sweep bucket count, and whether it breached the ceiling —
/// returned rather than only logged so the boundary can be asserted in a test.
fn sweep_tier(handle: &TierHandle, max_buckets: usize) -> SweepOutcome {
    let live = (handle.sweep)();
    let over_ceiling = live > max_buckets;
    if over_ceiling {
        tracing::error!(
            tier = handle.tier,
            live,
            max_buckets,
            "rate-limit bucket count is above the configured ceiling after eviction; \
             the key space may not be bounded as expected"
        );
    }
    SweepOutcome { live, over_ceiling }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SweepOutcome {
    live: usize,
    over_ceiling: bool,
}

/// Counters for the ways the limiter can affect a request.
#[derive(Clone)]
pub struct RateLimitMetrics {
    rejected: Counter<u64>,
    key_extraction_failed: Counter<u64>,
}

impl RateLimitMetrics {
    /// The [`Meter`] is injected rather than resolved from the OpenTelemetry
    /// global so that these counters are observable in tests without touching
    /// process-wide state.
    pub fn new(meter: &Meter) -> Self {
        Self {
            rejected: meter
                .u64_counter("rate_limit_rejected")
                .with_description("Requests rejected because a rate-limit tier was exhausted.")
                .build(),
            key_extraction_failed: meter
                .u64_counter("rate_limit_key_extraction_failed")
                .with_description("Requests for which no rate-limit key could be derived.")
                .build(),
        }
    }

    fn handle(&self, tier: &'static str, error: GovernorError) -> Response<Body> {
        let attributes = [KeyValue::new("tier", tier)];
        match error {
            GovernorError::TooManyRequests { wait_time, headers } => {
                self.rejected.add(1, &attributes);
                let mut response = json_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limited",
                    format!("Rate limit exceeded for the {tier} tier. Retry in {wait_time}s."),
                );
                // The tier is contractual: a client needs to distinguish "you
                // personally are writing too fast" from "this source IP is",
                // and `error_description` is documented as human-readable and
                // not part of the contract. A header carries it in a place
                // clients may branch on.
                response
                    .headers_mut()
                    .insert(&X_RATELIMIT_TIER, HeaderValue::from_static(tier));
                // Carries `retry-after`, and `x-ratelimit-*` for reporting tiers.
                if let Some(headers) = headers {
                    response.headers_mut().extend(headers);
                }
                response
            }
            GovernorError::UnableToExtractKey => {
                self.key_extraction_failed.add(1, &attributes);
                // Never the client's fault: either `ConnectInfo` is missing
                // because the server was not served with connect info, or a
                // middleware ordering change has hidden the verified issuer.
                tracing::error!(
                    tier,
                    "rate limiter could not derive a key; check that the server is served \
                     with ConnectInfo and that the auth middleware still runs outside the \
                     issuer tier"
                );
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "rate_limit_unavailable",
                    "The rate limiter could not identify the caller.".to_string(),
                )
            }
            // Reserved for custom key extractors. Split on the status class:
            // a 4xx is the caller's problem and belongs on the rejection
            // counter, while a 5xx is ours and is an extraction failure by
            // another name - conflating them would hide a broken deployment
            // inside a metric operators read as "clients being throttled".
            GovernorError::Other { code, msg, headers } => {
                let client_fault = code.is_client_error();
                if client_fault {
                    self.rejected.add(1, &attributes);
                } else {
                    self.key_extraction_failed.add(1, &attributes);
                    tracing::error!(
                        tier,
                        status = code.as_u16(),
                        "rate limiter returned a server-side error"
                    );
                }
                let mut response = json_error(
                    code,
                    if client_fault {
                        "rate_limited"
                    } else {
                        "rate_limit_unavailable"
                    },
                    msg.unwrap_or_else(|| "Request rejected by the rate limiter.".to_string()),
                );
                response
                    .headers_mut()
                    .insert(&X_RATELIMIT_TIER, HeaderValue::from_static(tier));
                if let Some(headers) = headers {
                    response.headers_mut().extend(headers);
                }
                response
            }
        }
    }
}

/// Renders a limiter rejection in the same JSON shape as the rest of the API,
/// rather than `tower-governor`'s plain-text default.
fn json_error(status: StatusCode, error: &'static str, description: String) -> Response<Body> {
    let payload = ErrorResponse {
        error: error.into(),
        error_description: Some(description),
    };
    let body =
        serde_json::to_vec(&payload).unwrap_or_else(|_| br#"{"error":"rate_limited"}"#.to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        // A limiter decision is specific to one caller at one instant. A shared
        // cache that stored it would serve a 429 to unthrottled clients, and a
        // 500 from a key-extraction failure is never cacheable either.
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .expect("rate-limit error response is statically valid")
}

/// Wraps a tier in its middleware layer, tagging rejections with the tier name
/// so a client can tell a per-issuer limit from a per-IP one.
pub fn governor_layer<K, M>(
    config: Arc<GovernorConfig<K, M>>,
    tier: &'static str,
    metrics: &RateLimitMetrics,
) -> GovernorLayer<K, M, Body>
where
    K: KeyExtractor,
    M: RateLimitingMiddleware<QuantaInstant>,
{
    let metrics = metrics.clone();
    GovernorLayer::new(config).error_handler(move |error| metrics.handle(tier, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientIpSource;
    use crate::server::rate_limit::RateLimitKey;
    use std::net::{IpAddr, Ipv4Addr};

    fn meter() -> Meter {
        opentelemetry::global::meter("rate-limit-runtime-test")
    }

    fn config(burst: u32) -> RateLimitConfig {
        RateLimitConfig::for_test(ClientIpSource::ConnectInfo, 0, burst, burst)
    }

    fn ip(last: u8) -> RateLimitKey {
        RateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)))
    }

    #[tokio::test]
    async fn the_eviction_task_is_cancelled_when_the_runtime_is_dropped() {
        let policies = GovernorPolicies::build(&config(10), &meter()).unwrap();
        let meter = opentelemetry::global::meter("test");
        let runtime = policies.spawn_runtime(&config(10), &meter);

        let handle = runtime.eviction_task.abort_handle();
        assert!(!handle.is_finished());

        drop(runtime);
        // `abort` is asynchronous; yield so the runtime can process it.
        tokio::task::yield_now().await;
        assert!(
            handle.is_finished(),
            "dropping the runtime must stop the eviction task"
        );
    }

    /// A limiter with a sub-second replenish interval, so that a bucket becomes
    /// indistinguishable from fresh within the lifetime of a test. The config
    /// surface is in whole seconds, so this is built directly.
    fn fast_limiter() -> SharedRateLimiter<RateLimitKey, NoOpMiddleware> {
        let quota = governor::Quota::with_period(Duration::from_millis(40))
            .expect("non-zero period")
            .allow_burst(std::num::NonZeroU32::new(1).expect("non-zero burst"));
        Arc::new(governor::RateLimiter::keyed(quota))
    }

    /// The behaviour eviction exists for: a bucket that has fully replenished
    /// is actually removed. Without this, `retain_recent` could silently become
    /// a no-op and the only symptom would be slow memory growth.
    #[tokio::test]
    async fn sweeping_removes_buckets_that_have_replenished() {
        let limiter = fast_limiter();
        let handle = TierHandle::new("test", limiter.clone());

        assert!(limiter.check_key(&ip(1)).is_ok());
        assert!(limiter.check_key(&ip(2)).is_ok());
        assert_eq!(limiter.len(), 2);

        // A used bucket's theoretical arrival time sits one replenish interval
        // in the future, and `retain_recent` drops keys older than one interval
        // in the past — so a bucket is collectable about two intervals after
        // use. Waited generously to keep the test robust on a loaded CI box.
        tokio::time::sleep(Duration::from_millis(400)).await;

        assert_eq!(
            (handle.sweep)(),
            0,
            "replenished buckets must actually be removed"
        );
        assert_eq!(limiter.len(), 0);
    }

    /// A bucket with an outstanding debt must survive a sweep, or a caller
    /// could clear their own throttle by waiting for the eviction timer.
    #[tokio::test]
    async fn sweeping_keeps_buckets_that_have_not_replenished() {
        let policies = GovernorPolicies::build(&config(1), &meter()).unwrap();
        let limiter = policies.reads.limiter();

        assert!(limiter.check_key(&ip(1)).is_ok());
        assert!(limiter.check_key(&ip(2)).is_ok());

        let handle = TierHandle::new("reads", limiter.clone());
        assert_eq!((handle.sweep)(), 2);
        assert!(
            limiter.check_key(&ip(1)).is_err(),
            "a swept-but-retained bucket must still be throttling"
        );
    }

    #[tokio::test]
    async fn each_tier_gets_an_independent_limiter() {
        let policies = GovernorPolicies::build(&config(10), &meter()).unwrap();
        assert!(policies.reads.limiter().check_key(&ip(1)).is_ok());
        assert_eq!(policies.reads.limiter().len(), 1);
        assert_eq!(
            policies.write_gate.limiter().len(),
            0,
            "tiers must not share bucket state"
        );
        assert_eq!(policies.credentials.limiter().len(), 0);
        assert_eq!(policies.issuer.limiter().len(), 0);
    }

    #[test]
    fn build_rejects_a_zero_burst_size() {
        let mut cfg = config(10);
        cfg.issuer_burst_size = 0;
        assert!(GovernorPolicies::build(&cfg, &meter()).is_err());

        let mut cfg = config(10);
        cfg.write_gate_burst_size = 0;
        assert!(GovernorPolicies::build(&cfg, &meter()).is_err());
    }

    #[test]
    fn build_rejects_an_unset_client_ip_source() {
        let mut cfg = config(10);
        cfg.client_ip_source = None;
        assert!(GovernorPolicies::build(&cfg, &meter()).is_err());
    }

    /// The ceiling is an alerting threshold, so the comparison is `>`: sitting
    /// exactly at `max_buckets` is not a breach. An off-by-one here would make
    /// the alert fire constantly on a correctly-sized deployment.
    #[test]
    fn the_bucket_ceiling_is_breached_only_above_it() {
        let limiter = fast_limiter();
        for last in 1..=3u8 {
            assert!(limiter.check_key(&ip(last)).is_ok());
        }
        let handle = TierHandle::new("test", limiter.clone());

        assert_eq!(
            sweep_tier(&handle, 3),
            SweepOutcome {
                live: 3,
                over_ceiling: false
            },
            "exactly at the ceiling is not a breach"
        );
        assert_eq!(
            sweep_tier(&handle, 2),
            SweepOutcome {
                live: 3,
                over_ceiling: true
            },
            "one above the ceiling is"
        );
    }

    /// Reclaiming capacity reallocates, so it must not happen on every sweep of
    /// a steady-state limiter — only when a sweep actually freed a meaningful
    /// share of the map.
    #[test]
    fn capacity_is_reclaimed_only_after_a_substantial_sweep() {
        // (before, after, expected)
        let cases = [
            (100, 100, false), // nothing removed
            (100, 99, false),  // a trickle
            (100, 67, false),  // 33 removed, just under half of the 67 left
            (100, 66, true),   // 34 removed, just over half of the 66 left
            (100, 0, true),    // everything removed
            (0, 0, false),     // empty limiter must not churn
        ];
        for (before, after, expected) in cases {
            assert_eq!(
                should_shrink(before, after),
                expected,
                "should_shrink({before}, {after})"
            );
        }
    }

    /// `before < after` cannot happen from a sweep, but the arithmetic must not
    /// panic if concurrent traffic grows the map mid-sweep.
    #[test]
    fn shrink_decision_survives_a_growing_map() {
        assert!(!should_shrink(0, 10));
        assert!(!should_shrink(5, usize::MAX));
    }

    #[test]
    fn limiter_responses_are_not_cacheable() {
        let response = json_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "x".into());
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }
}
