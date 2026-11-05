//! Rate limiting.
//!
//! Every limit keyed on an address uses `ClientAddress`: the public and admin
//! limiters, and [`AuthFailureGate`], which wraps `auth` on the management
//! listener. The gate admits a coarse number of requests before `auth` resolves
//! a key or verifies a signature, and counts rejected authentications.
//! [`IssuerRateLimiter`] runs after `auth`, keyed on the verified issuer, so a
//! forged `iss` cannot reach a bucket. State is per replica.
//!
//! The client address is the peer, unless `rightmost_x_forwarded_for` is set
//! and the peer is a trusted proxy: then it is the rightmost `X-Forwarded-For`
//! entry that is not a trusted proxy, which a client cannot choose. IPv6
//! addresses are keyed by their /64.

use std::{
    hash::Hash,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{
    DefaultKeyedRateLimiter, Quota, RateLimiter,
    clock::{Clock, DefaultClock},
};
use ipnet::IpNet;
use tower_governor::{GovernorError, key_extractor::KeyExtractor};

use crate::config::ClientIpSource;
use crate::domain::models::credential::Issuer;
use crate::domain::models::tier::{IssuerTier, TierLimits, Tiers};
use crate::server::{
    AppState,
    auth::{AuthenticatedIssuer, errors::AuthenticationRejected},
    error::ApiError,
};

/// How often idle buckets are dropped. Gate keys come from client addresses
/// and issuer keys include hosted issuers, so neither key set is bounded.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Drops idle buckets every [`PRUNE_INTERVAL`] until `limiter` is dropped.
fn spawn_pruner<T: Send + Sync + 'static>(limiter: &Arc<T>, prune: impl Fn(&T) + Send + 'static) {
    let limiter = Arc::downgrade(limiter);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PRUNE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let Some(limiter) = limiter.upgrade() else {
                break;
            };
            prune(&limiter);
        }
    });
}

fn prune<K: Clone + Eq + Hash>(limiter: &DefaultKeyedRateLimiter<K>, name: &'static str) {
    limiter.retain_recent();
    limiter.shrink_to_fit();
    crate::utils::metrics::record_rate_limiter_keys(name, limiter.len());
}

pub(crate) fn spawn_governor_pruner(
    limiter: &Arc<DefaultKeyedRateLimiter<IpAddr>>,
    name: &'static str,
) {
    spawn_pruner(limiter, move |limiter| prune(limiter, name));
}

#[derive(Debug)]
pub(crate) struct ClientAddress {
    source: ClientIpSource,
    trusted_proxies: Vec<IpNet>,
    /// Warn once, not per request.
    warned_untrusted_forwarding: AtomicBool,
}

impl ClientAddress {
    pub(crate) fn new(source: ClientIpSource, trusted_proxies: Vec<IpNet>) -> Self {
        Self {
            source,
            trusted_proxies,
            warned_untrusted_forwarding: AtomicBool::new(false),
        }
    }

    pub(crate) fn key(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        match self.client_ip(peer, headers) {
            // A single IPv6 subscriber usually holds a whole /64.
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64))),
            ip => ip,
        }
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|net| net.contains(&ip))
    }

    fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = peer.to_canonical();
        let forwarded = headers.get_all("x-forwarded-for");
        if self.source == ClientIpSource::ConnectInfo || !self.is_trusted(peer) {
            if forwarded.iter().next().is_some()
                && !self
                    .warned_untrusted_forwarding
                    .swap(true, Ordering::Relaxed)
            {
                tracing::warn!(
                    peer = %peer,
                    "ignoring X-Forwarded-For from a peer outside rate_limit.trusted_proxies; \
                     rate limits key on the peer address"
                );
            }
            return peer;
        }
        let hops = forwarded
            .iter()
            .rev()
            .flat_map(|value| value.to_str().unwrap_or("").rsplit(','))
            .map(str::trim);
        let mut client = peer;
        for hop in hops {
            // Nothing left of an unreadable hop is vouched for.
            let Ok(ip) = hop.parse::<IpAddr>().map(|ip| ip.to_canonical()) else {
                break;
            };
            client = ip;
            if !self.is_trusted(ip) {
                break;
            }
        }
        client
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ClientKeyExtractor(pub(crate) Arc<ClientAddress>);

impl KeyExtractor for ClientKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, request: &axum::http::Request<T>) -> Result<IpAddr, GovernorError> {
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| self.0.key(addr.ip(), request.headers()))
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Two budgets per client address. Admission is spent by every request before
/// `auth` runs, bounding key lookups and signature checks; it is sized above a
/// standard issuer's own budget. Failures are spent only by rejected
/// authentications, so a client sending bad tokens cannot lock out a verified
/// issuer behind the same address; a rejection past that budget is answered
/// with `429` instead of `401`.
#[derive(Debug)]
pub struct AuthFailureGate {
    admission: DefaultKeyedRateLimiter<IpAddr>,
    limiter: DefaultKeyedRateLimiter<IpAddr>,
    clock: DefaultClock,
    client: Arc<ClientAddress>,
}

impl AuthFailureGate {
    pub(crate) fn new(admission: Quota, failures: Quota, client: Arc<ClientAddress>) -> Self {
        Self {
            admission: RateLimiter::keyed(admission),
            limiter: RateLimiter::keyed(failures),
            clock: DefaultClock::default(),
            client,
        }
    }

    /// Spends one admission token of `ip`; `Err` carries the wait once spent.
    fn admit(&self, ip: IpAddr) -> Result<(), Duration> {
        Self::spend(&self.admission, &self.clock, ip)
    }

    /// Spends one failure token of `ip`; `Err` carries the wait once spent.
    fn record_failure(&self, ip: IpAddr) -> Result<(), Duration> {
        Self::spend(&self.limiter, &self.clock, ip)
    }

    fn spend(
        limiter: &DefaultKeyedRateLimiter<IpAddr>,
        clock: &DefaultClock,
        ip: IpAddr,
    ) -> Result<(), Duration> {
        limiter
            .check_key(&ip)
            .map_err(|not_until| not_until.wait_time_from(clock.now()))
    }

    pub fn spawn_pruner(gate: &Arc<Self>) {
        spawn_pruner(gate, |gate| {
            prune(&gate.admission, "management_admission");
            prune(&gate.limiter, "management_auth_failures");
        });
    }
}

/// Must wrap `auth`, which marks its rejections with [`AuthenticationRejected`].
pub async fn auth_failure_gate(
    State(gate): State<Arc<AuthFailureGate>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(peer) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
    else {
        return governor_error_response(GovernorError::UnableToExtractKey);
    };
    let ip = gate.client.key(peer, request.headers());
    if let Err(wait) = gate.admit(ip) {
        return ApiError::too_many_requests(wait, "Too many requests from this address")
            .into_response();
    }
    let response = next.run(request).await;
    if response
        .extensions()
        .get::<AuthenticationRejected>()
        .is_some()
        && let Err(wait) = gate.record_failure(ip)
    {
        return ApiError::too_many_requests(
            wait,
            "Too many failed authentications from this address",
        )
        .into_response();
    }
    response
}

/// One bucket per issuer and tier, pruned once idle.
#[derive(Debug)]
pub struct IssuerRateLimiter {
    standard: DefaultKeyedRateLimiter<Issuer>,
    sandbox: DefaultKeyedRateLimiter<Issuer>,
    clock: DefaultClock,
}

impl IssuerRateLimiter {
    pub fn new(tiers: &Tiers) -> Self {
        Self {
            standard: RateLimiter::keyed(request_quota(&tiers.standard)),
            sandbox: RateLimiter::keyed(request_quota(&tiers.sandbox)),
            clock: DefaultClock::default(),
        }
    }

    fn limiter(&self, tier: IssuerTier) -> &DefaultKeyedRateLimiter<Issuer> {
        match tier {
            IssuerTier::Standard => &self.standard,
            IssuerTier::Sandbox => &self.sandbox,
        }
    }

    pub fn check(&self, issuer: &Issuer, tier: IssuerTier) -> Result<(), Duration> {
        self.limiter(tier)
            .check_key(issuer)
            .map_err(|not_until| not_until.wait_time_from(self.clock.now()))
    }

    pub fn spawn_pruner(limiter: &Arc<Self>) {
        spawn_pruner(limiter, |limiter| {
            prune(&limiter.standard, "issuer_standard");
            prune(&limiter.sandbox, "issuer_sandbox");
        });
    }
}

fn request_quota(limits: &TierLimits) -> Quota {
    Quota::with_period(limits.write_period)
        .expect("tier write period is validated as non-zero")
        .allow_burst(limits.write_burst_size)
}

/// Must run inside `auth`, so an unauthenticated request never reaches a bucket.
pub async fn issuer_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(principal) = request.extensions().get::<AuthenticatedIssuer>() else {
        return ApiError::internal("issuer rate limit ran without an authenticated issuer")
            .into_response();
    };
    if let Err(wait) = state
        .issuer_rate_limiter
        .check(principal.issuer(), principal.tier())
    {
        crate::utils::metrics::record_issuer_rate_limited(principal.as_ref(), principal.tier());
        return ApiError::too_many_requests(wait, "The issuer's request budget is spent")
            .into_response();
    }
    next.run(request).await
}

pub fn governor_error_response(error: GovernorError) -> Response {
    match error {
        // `tower_governor` truncates the wait; round up so `Retry-After` suffices.
        GovernorError::TooManyRequests { wait_time, .. } => ApiError::too_many_requests(
            Duration::from_secs(wait_time.saturating_add(1)),
            "Too many requests from this address",
        )
        .into_response(),
        GovernorError::UnableToExtractKey => {
            ApiError::internal("rate limiter could not determine the client address")
                .into_response()
        }
        GovernorError::Other { code, msg, .. } => ApiError::internal(format!(
            "rate limiter failed with {code}: {}",
            msg.as_deref().unwrap_or("no detail")
        ))
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    fn address(source: ClientIpSource, trusted: &[&str]) -> ClientAddress {
        ClientAddress::new(
            source,
            trusted.iter().map(|net| net.parse().unwrap()).collect(),
        )
    }

    fn behind(trusted: &[&str]) -> ClientAddress {
        address(ClientIpSource::RightmostXForwardedFor, trusted)
    }

    fn client(address: &ClientAddress, peer: &str, forwarded: &[&str]) -> IpAddr {
        let mut headers = HeaderMap::new();
        for value in forwarded {
            headers.append("x-forwarded-for", value.parse().unwrap());
        }
        address.key(ip(peer), &headers)
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn forwarding_headers_from_an_untrusted_peer_are_ignored() {
        let address = behind(&[]);
        assert_eq!(
            client(&address, "198.51.100.4", &["203.0.113.5"]),
            ip("198.51.100.4")
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.5".parse().unwrap());
        headers.insert("forwarded", "for=203.0.113.5".parse().unwrap());
        assert_eq!(
            address.key(ip("198.51.100.4"), &headers),
            ip("198.51.100.4")
        );
    }

    #[test]
    fn connect_info_keys_on_the_peer_even_when_it_is_listed() {
        let address = address(ClientIpSource::ConnectInfo, &["10.0.0.0/8"]);
        assert_eq!(
            client(&address, "10.0.0.2", &["203.0.113.5"]),
            ip("10.0.0.2")
        );
    }

    #[test]
    fn behind_trusted_proxies_the_rightmost_untrusted_hop_is_the_client() {
        let address = behind(&["10.0.0.0/8"]);
        assert_eq!(
            client(&address, "10.0.0.2", &["203.0.113.5"]),
            ip("203.0.113.5")
        );
        // A client-supplied entry left of the one the proxy appended is ignored.
        assert_eq!(
            client(&address, "10.0.0.2", &["192.0.2.1, 203.0.113.5"]),
            ip("203.0.113.5")
        );
        // Trusted hops are skipped, across repeated headers too.
        assert_eq!(
            client(
                &address,
                "10.0.0.2",
                &["192.0.2.1, 203.0.113.5", "10.1.1.1"]
            ),
            ip("203.0.113.5")
        );
        assert_eq!(client(&address, "10.0.0.2", &[]), ip("10.0.0.2"));
    }

    #[test]
    fn every_header_line_is_one_list_read_from_the_right() {
        let address = behind(&["10.0.0.0/8"]);
        assert_eq!(
            client(&address, "10.0.0.2", &["198.51.100.7", "203.0.113.5"]),
            ip("203.0.113.5")
        );
        assert_eq!(
            client(
                &address,
                "10.0.0.2",
                &["203.0.113.5", "10.2.2.2", "10.3.3.3, 10.4.4.4"]
            ),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn an_unreadable_hop_falls_back_to_the_nearest_trusted_address() {
        let address = behind(&["10.0.0.0/8"]);
        assert_eq!(
            client(&address, "10.0.0.2", &["203.0.113.5, not-an-ip, 10.9.9.9"]),
            ip("10.9.9.9")
        );
        assert_eq!(client(&address, "10.0.0.2", &["unknown"]), ip("10.0.0.2"));
    }

    #[test]
    fn whitespace_is_trimmed_and_a_blank_hop_is_unreadable() {
        let address = behind(&["10.0.0.0/8"]);
        assert_eq!(
            client(&address, "10.0.0.2", &[" 203.0.113.5 ,\t10.1.1.1 "]),
            ip("203.0.113.5")
        );
        for forwarded in ["203.0.113.5, ", ",,", ""] {
            assert_eq!(
                client(&address, "10.0.0.2", &[forwarded]),
                ip("10.0.0.2"),
                "{forwarded:?}"
            );
        }
    }

    #[test]
    fn a_hop_with_a_port_is_unreadable() {
        let address = behind(&["10.0.0.0/8"]);
        for forwarded in [
            "203.0.113.5:443",
            "[2001:db8::1]:443",
            "203.0.113.5, 10.1.1.1:8080",
        ] {
            assert_eq!(
                client(&address, "10.0.0.2", &[forwarded]),
                ip("10.0.0.2"),
                "{forwarded:?}"
            );
        }
    }

    #[test]
    fn a_header_line_that_is_not_text_is_unreadable() {
        let address = behind(&["10.0.0.0/8"]);
        let opaque = axum::http::HeaderValue::from_bytes(b"203.0.113.9\xff").unwrap();
        let forwarded = |lines: [&axum::http::HeaderValue; 2]| {
            let mut headers = HeaderMap::new();
            for line in lines {
                headers.append("x-forwarded-for", line.clone());
            }
            address.key(ip("10.0.0.2"), &headers)
        };
        let client = axum::http::HeaderValue::from_static("203.0.113.5");

        assert_eq!(forwarded([&client, &opaque]), ip("10.0.0.2"));
        assert_eq!(forwarded([&opaque, &client]), ip("203.0.113.5"));
    }

    #[test]
    fn an_all_trusted_chain_keys_on_its_first_hop() {
        let address = behind(&["10.0.0.0/8"]);
        assert_eq!(
            client(&address, "10.0.0.2", &["10.3.0.1, 10.2.0.1"]),
            ip("10.3.0.1")
        );
    }

    #[test]
    fn ipv4_mapped_addresses_are_matched_and_keyed_as_ipv4() {
        let address = behind(&["10.0.0.0/8"]);
        assert_eq!(
            client(&address, "::ffff:10.0.0.2", &["203.0.113.5"]),
            ip("203.0.113.5")
        );
        assert_eq!(
            client(&address, "::ffff:198.51.100.4", &[]),
            ip("198.51.100.4")
        );
        assert_eq!(
            client(&address, "10.0.0.2", &["::ffff:203.0.113.5"]),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn ipv6_clients_share_a_key_per_slash_64() {
        let direct = behind(&[]);
        for peer in ["2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff"] {
            assert_eq!(client(&direct, peer, &[]), ip("2001:db8:1:2::"), "{peer}");
        }
        assert_eq!(
            client(&direct, "2001:db8:1:3::1", &[]),
            ip("2001:db8:1:3::")
        );

        let proxied = behind(&["fd00::/8"]);
        assert_eq!(
            client(&proxied, "fd00::2", &["2001:db8:1:2::7"]),
            ip("2001:db8:1:2::")
        );
    }

    #[test]
    fn trust_is_decided_on_the_full_address() {
        let address = behind(&["2001:db8::1/128"]);
        assert_eq!(
            client(&address, "2001:db8::2", &["203.0.113.5"]),
            ip("2001:db8::")
        );
        assert_eq!(
            client(&address, "2001:db8::1", &["203.0.113.5"]),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn pruning_drops_idle_keys_from_the_key_gauge() {
        use crate::config::{TelemetryConfig, TelemetryEnvironment};
        use crate::utils::metrics::{metrics_handler, metrics_test_lock, setup_metrics};

        let _guard = metrics_test_lock();
        let registry = prometheus::Registry::new();
        let _provider = setup_metrics(
            &registry,
            &TelemetryConfig {
                environment: TelemetryEnvironment::Development,
                otlp_endpoint: "http://localhost:4317".to_string(),
                sampler_ratio: 1.0,
                enabled: false,
            },
            opentelemetry_sdk::Resource::builder()
                .with_service_name("status-list-server-test")
                .build(),
        )
        .expect("metrics setup");
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        let keys = || {
            runtime
                .block_on(metrics_handler(registry.clone()))
                .lines()
                .find(|line| {
                    line.starts_with("rate_limiter_keys{") && line.contains("limiter=\"test\"")
                })
                .and_then(|line| line.rsplit(' ').next().map(str::to_owned))
        };
        let limiter: DefaultKeyedRateLimiter<IpAddr> =
            RateLimiter::keyed(Quota::with_period(Duration::from_millis(250)).unwrap());
        for peer in ["203.0.113.1", "203.0.113.2"] {
            assert!(limiter.check_key(&ip(peer)).is_ok());
        }

        prune(&limiter, "test");
        assert_eq!(keys().as_deref(), Some("2"));
        std::thread::sleep(Duration::from_millis(600));
        prune(&limiter, "test");
        assert_eq!(keys().as_deref(), Some("0"));
    }

    fn tiers(standard_burst: u32, sandbox_burst: u32) -> Tiers {
        let limits = |burst| TierLimits {
            max_lists: 10,
            max_status_index: 100,
            max_statuses_per_request: 10,
            max_keys: 2,
            write_burst_size: NonZeroU32::new(burst).unwrap(),
            write_period: Duration::from_secs(60),
        };
        Tiers {
            standard: limits(standard_burst),
            sandbox: limits(sandbox_burst),
        }
    }

    #[test]
    fn issuers_have_independent_buckets() {
        let limiter = IssuerRateLimiter::new(&tiers(1, 1));
        let a = Issuer("issuer-a".into());
        let b = Issuer("issuer-b".into());

        assert!(limiter.check(&a, IssuerTier::Standard).is_ok());
        let wait = limiter.check(&a, IssuerTier::Standard).unwrap_err();
        assert!(wait > Duration::ZERO && wait <= Duration::from_secs(60));
        assert!(limiter.check(&b, IssuerTier::Standard).is_ok());
    }

    #[test]
    fn each_tier_uses_its_own_burst() {
        let limiter = IssuerRateLimiter::new(&tiers(3, 1));
        let standard = Issuer("standard".into());
        let sandbox = Issuer("sandbox".into());

        for _ in 0..3 {
            assert!(limiter.check(&standard, IssuerTier::Standard).is_ok());
        }
        assert!(limiter.check(&standard, IssuerTier::Standard).is_err());
        assert!(limiter.check(&sandbox, IssuerTier::Sandbox).is_ok());
        assert!(limiter.check(&sandbox, IssuerTier::Sandbox).is_err());
    }
}
