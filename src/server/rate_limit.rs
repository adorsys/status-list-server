//! Rate limiting on the management listener.
//!
//! [`AuthFailureGate`] wraps `auth`, keyed on the client address, and counts
//! rejected authentications only. [`IssuerRateLimiter`] runs after `auth`,
//! keyed on the verified issuer, so a forged `iss` cannot reach a bucket.
//! State is per replica.
//!
//! The client address is the peer, unless the peer is a trusted proxy: then it
//! is the rightmost `X-Forwarded-For` entry that is not a trusted proxy, which
//! a client cannot choose.

use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
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
use tower_governor::GovernorError;

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
fn spawn_pruner<T: Send + Sync + 'static>(limiter: &Arc<T>, prune: fn(&T)) {
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

/// Budget of rejected authentications per client address. A request that
/// authenticates spends nothing and is never refused here, so a client sending
/// bad tokens cannot lock out a verified issuer behind the same address. A
/// rejection past the budget is answered with `429` instead of `401`.
#[derive(Debug)]
pub struct AuthFailureGate {
    limiter: DefaultKeyedRateLimiter<IpAddr>,
    clock: DefaultClock,
    trusted_proxies: Vec<IpNet>,
    /// Warn once, not per request.
    warned_untrusted_forwarding: AtomicBool,
}

impl AuthFailureGate {
    /// `None` when `burst` or `period` is zero.
    pub(crate) fn new(burst: u32, period: Duration, trusted_proxies: Vec<IpNet>) -> Option<Self> {
        let quota = Quota::with_period(period)?.allow_burst(NonZeroU32::new(burst)?);
        Some(Self {
            limiter: RateLimiter::keyed(quota),
            clock: DefaultClock::default(),
            trusted_proxies,
            warned_untrusted_forwarding: AtomicBool::new(false),
        })
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|net| net.contains(&ip))
    }

    fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = peer.to_canonical();
        let forwarded = headers.get_all("x-forwarded-for");
        if !self.is_trusted(peer) {
            if forwarded.iter().next().is_some()
                && !self
                    .warned_untrusted_forwarding
                    .swap(true, Ordering::Relaxed)
            {
                tracing::warn!(
                    peer = %peer,
                    "ignoring X-Forwarded-For from a peer outside rate_limit.trusted_proxies; \
                     the management authentication gate keys on the peer address"
                );
            }
            return peer;
        }
        let hops: Vec<&str> = forwarded
            .iter()
            .flat_map(|value| value.to_str().unwrap_or("").split(','))
            .map(str::trim)
            .collect();
        let mut client = peer;
        for hop in hops.iter().rev() {
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

    /// Spends one token of `ip`'s budget; `Err` carries the wait once spent.
    fn record_failure(&self, ip: IpAddr) -> Result<(), Duration> {
        self.limiter
            .check_key(&ip)
            .map_err(|not_until| not_until.wait_time_from(self.clock.now()))
    }

    pub fn spawn_pruner(gate: &Arc<Self>) {
        spawn_pruner(gate, |gate| {
            gate.limiter.retain_recent();
            gate.limiter.shrink_to_fit();
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
    let ip = gate.client_ip(peer, request.headers());
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
            for tier in [&limiter.standard, &limiter.sandbox] {
                tier.retain_recent();
                tier.shrink_to_fit();
            }
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

    fn gate(trusted: &[&str]) -> AuthFailureGate {
        AuthFailureGate::new(
            1,
            Duration::from_secs(60),
            trusted.iter().map(|net| net.parse().unwrap()).collect(),
        )
        .unwrap()
    }

    fn client(gate: &AuthFailureGate, peer: &str, forwarded: &[&str]) -> IpAddr {
        let mut headers = HeaderMap::new();
        for value in forwarded {
            headers.append("x-forwarded-for", value.parse().unwrap());
        }
        gate.client_ip(peer.parse().unwrap(), &headers)
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn forwarding_headers_from_an_untrusted_peer_are_ignored() {
        let gate = gate(&[]);
        assert_eq!(
            client(&gate, "198.51.100.4", &["203.0.113.5"]),
            ip("198.51.100.4")
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.5".parse().unwrap());
        headers.insert("forwarded", "for=203.0.113.5".parse().unwrap());
        assert_eq!(
            gate.client_ip(ip("198.51.100.4"), &headers),
            ip("198.51.100.4")
        );
    }

    #[test]
    fn behind_trusted_proxies_the_rightmost_untrusted_hop_is_the_client() {
        let gate = gate(&["10.0.0.0/8"]);
        assert_eq!(
            client(&gate, "10.0.0.2", &["203.0.113.5"]),
            ip("203.0.113.5")
        );
        // A client-supplied entry left of the one the proxy appended is ignored.
        assert_eq!(
            client(&gate, "10.0.0.2", &["192.0.2.1, 203.0.113.5"]),
            ip("203.0.113.5")
        );
        // Trusted hops are skipped, across repeated headers too.
        assert_eq!(
            client(&gate, "10.0.0.2", &["192.0.2.1, 203.0.113.5", "10.1.1.1"]),
            ip("203.0.113.5")
        );
        assert_eq!(client(&gate, "10.0.0.2", &[]), ip("10.0.0.2"));
    }

    #[test]
    fn an_unreadable_hop_falls_back_to_the_nearest_trusted_address() {
        let gate = gate(&["10.0.0.0/8"]);
        assert_eq!(
            client(&gate, "10.0.0.2", &["203.0.113.5, not-an-ip, 10.9.9.9"]),
            ip("10.9.9.9")
        );
        assert_eq!(client(&gate, "10.0.0.2", &["unknown"]), ip("10.0.0.2"));
    }

    #[test]
    fn an_all_trusted_chain_keys_on_its_first_hop() {
        let gate = gate(&["10.0.0.0/8"]);
        assert_eq!(
            client(&gate, "10.0.0.2", &["10.3.0.1, 10.2.0.1"]),
            ip("10.3.0.1")
        );
    }

    #[test]
    fn ipv4_mapped_peers_are_matched_and_keyed_as_ipv4() {
        let gate = gate(&["10.0.0.0/8"]);
        assert_eq!(
            client(&gate, "::ffff:10.0.0.2", &["203.0.113.5"]),
            ip("203.0.113.5")
        );
        assert_eq!(
            client(&gate, "::ffff:198.51.100.4", &[]),
            ip("198.51.100.4")
        );
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
