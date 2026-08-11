//! Rate-limit key extraction.
//!
//! Two extractors, matching the two kinds of traffic the server sees:
//!
//! * [`VerifiedIssuerKeyExtractor`] keys authenticated writes on the issuer
//!   that the auth middleware has already **cryptographically verified**. It
//!   must therefore be layered *inside* the auth middleware  -  see
//!   [`crate::startup::api_v1_routes`]. Reading the `iss` claim out of an
//!   unverified token instead would let any client mint a fresh bucket per
//!   request simply by changing the claim, which is the same bypass that
//!   spoofed `X-Forwarded-For` used to give.
//! * [`SecureIpKeyExtractor`] keys unauthenticated traffic on a client IP
//!   derived through an explicitly configured [`ClientIpSource`]. There is no
//!   "smart" fallback chain: guessing which header to trust is what made the
//!   original key forgeable.
//!
//! Both produce a [`RateLimitKey`], whose variants keep the identity domains in
//! separate namespaces.
//!
//! # Why not `axum-client-ip`
//!
//! Issue #262 suggested wrapping [`axum-client-ip`], which solves the same
//! extraction problem and is maintained specifically for redistributable
//! binaries. It was not adopted, for two reasons: this server needs the client
//! IP *only* as a rate-limit key  -  never as request data  -  so the surface
//! actually used is the ~80 lines below, and `KeyExtractor` has to be
//! implemented here regardless; and a rate limiter is a place where the
//! precise fallback behaviour on a malformed or short header chain is a
//! security decision this crate should state explicitly rather than inherit.
//!
//! That trade is worth revisiting. The bugs this module has had  -  first-line
//! -only parsing, a fail-open short chain, IPv4-mapped collapse  -  are all ones
//! `axum-client-ip` already handles, and it also covers RFC 7239 `Forwarded:`,
//! which is unsupported here.
//!
//! [`axum-client-ip`]: https://github.com/imbolc/axum-client-ip

pub mod runtime;

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, Request};
use ipnet::IpNet;
use opentelemetry::{KeyValue, metrics::Counter};
use tower_governor::{errors::GovernorError, key_extractor::KeyExtractor};

use crate::config::ClientIpSource;
use crate::server::auth::VerifiedIssuer;

static X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// IPv6 clients are keyed on a network prefix rather than a single address.
///
/// A single residential allocation is typically a /64 or larger, so keying on
/// the full address would let one subscriber mint effectively unlimited
/// distinct  -  and entirely *unforged*  -  buckets.
const IPV6_BUCKET_PREFIX_BITS: u32 = 64;

/// A rate-limit bucket key.
///
/// The variants exist so that the identity domains cannot collide. Without
/// them an issuer registered under the name `"10.0.0.1"` would share a bucket
/// with the client at that address and -- since issuer registration is open --
/// could be used to exhaust a chosen victim's bucket on purpose.
///
/// Issuer keys are not length-bounded here. They are bounded where they enter
/// the system, by `MAX_ISSUER_LEN` at registration. Bounding at the boundary
/// rather than at the key means one length rule instead of two, and no hashed
/// variant that a chosen issuer name could be crafted to collide with.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RateLimitKey {
    /// A verified credential issuer.
    Issuer(Box<str>),
    /// A client address, bucketed by [`bucket_ip`].
    Ip(IpAddr),
}

/// Reduces an address to the unit that gets its own bucket: the address itself
/// for IPv4, the /64 network for IPv6.
///
/// IPv4-mapped addresses (`::ffff:a.b.c.d`) are unwrapped to the IPv4 address
/// they carry *before* any masking. A dual-stack listener (`APP_SERVER__HOST=::`)
/// delivers every IPv4 client in that form, and masking one to a /64 would
/// leave `::` -- collapsing every IPv4 client on the internet into a single
/// shared bucket. Unwrapping also keeps a client's key identical whether it
/// arrives over a dual-stack or an IPv4-only listener.
///
/// `to_ipv4_mapped` is deliberately used rather than `to_ipv4`: the latter also
/// converts the deprecated IPv4-*compatible* range, which would rewrite `::1`
/// (IPv6 loopback) to `0.0.0.1`.
fn bucket_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mask = !0u128 << (128 - IPV6_BUCKET_PREFIX_BITS);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        },
    }
}

fn peer_ip<T>(req: &Request<T>) -> Option<IpAddr> {
    req.extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|addr| addr.ip())
}

/// Parses one `X-Forwarded-For` / `X-Real-IP` entry.
///
/// Proxies emit several shapes for the same address: bare (`203.0.113.7`,
/// `2001:db8::1`), with a port (`203.0.113.7:443`), and bracketed for IPv6
/// (`[2001:db8::1]:443`). Accepting only the bare form would make a legitimate
/// IPv6 hop unparseable, which silently collapses the tier into a single
/// shared bucket.
fn parse_forwarded_ip(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // `[2001:db8::1]` / `[2001:db8::1]:443`
    if let Some(rest) = raw.strip_prefix('[') {
        return rest.split_once(']')?.0.parse().ok();
    }
    // Bare address first: an unbracketed IPv6 literal must not be mistaken for
    // a `host:port` pair.
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }
    raw.parse::<SocketAddr>().ok().map(|addr| addr.ip())
}

/// All `X-Forwarded-For` entries, left to right.
///
/// A repeated list-valued header field is semantically identical to one
/// comma-joined field (RFC 9110 Section 5.3), and proxies differ on which they emit.
/// Reading only `HeaderMap::get`  -  i.e. the *first* line  -  would let a client
/// send its own `X-Forwarded-For` ahead of the proxy's and have the "rightmost"
/// entry be a value it chose.
///
/// Returned as a double-ended iterator rather than a `Vec` so that the caller
/// can walk in from the right without allocating on every request.
fn forwarded_for_entries(headers: &HeaderMap) -> impl DoubleEndedIterator<Item = &str> {
    headers
        .get_all(&X_FORWARDED_FOR)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
}

/// Reads the client IP by counting `trusted_hops` entries in from the right.
///
/// Fails  -  deliberately, rather than falling back to an entry further left  -
/// when the chain is shorter than the configured number of hops or the selected
/// entry is unparseable. Entries to the left are *less* trustworthy, so reaching
/// for one on failure would turn a misconfiguration into a bypass. The caller
/// falls back to the peer IP, which is coarse but unforgeable.
///
/// The emptiness check is separate from `nth_back` so that "no header at all"
/// and "header too short for `trusted_hops`" are distinguishable. An empty
/// iterator returns `None` for every index, so without it both would report
/// [`FallbackReason::ChainTooShort`]  -  and the most likely misconfiguration,
/// selecting this source on a deployment that has no proxy in front of it,
/// would point an operator at `trusted_hops`, the one setting that cannot fix a
/// header which is not there.
///
/// `nth_back` counts from the right directly, so no index arithmetic is
/// performed on `trusted_hops` and no value of it  -  including `usize::MAX`  -
/// can overflow or produce an out-of-range access.
fn rightmost_forwarded_for(
    headers: &HeaderMap,
    trusted_hops: usize,
) -> Result<IpAddr, FallbackReason> {
    if forwarded_for_entries(headers).next().is_none() {
        return Err(FallbackReason::HeaderAbsent);
    }
    let entry = forwarded_for_entries(headers)
        .nth_back(trusted_hops)
        .ok_or(FallbackReason::ChainTooShort)?;
    parse_forwarded_ip(entry).ok_or(FallbackReason::Unparseable)
}

/// Reads `X-Real-IP`, taking the **last** occurrence.
///
/// A client that sends its own `X-Real-IP` puts it ahead of the proxy's, so the
/// first value is the attacker-controlled one. The value is a single address by
/// definition; it is never split on commas, because taking the leftmost element
/// of an injected list is exactly the pattern this module exists to remove.
fn x_real_ip(headers: &HeaderMap) -> Result<IpAddr, FallbackReason> {
    let mut values = headers.get_all(&X_REAL_IP).iter();
    let value = values.next().ok_or(FallbackReason::HeaderAbsent)?;

    // `X-Real-IP` is single-valued by definition. More than one means either a
    // client injected its own or two proxies both wrote it, and there is no
    // rule that says which to believe. Guessing would be exactly the leftmost/
    // rightmost coin-flip this module exists to remove, so report it and let
    // the caller fall back to the unforgeable peer address.
    if values.next().is_some() {
        return Err(FallbackReason::Unparseable);
    }

    value
        .to_str()
        .ok()
        .and_then(parse_forwarded_ip)
        .ok_or(FallbackReason::Unparseable)
}

/// Why the configured client-IP source could not be used, forcing a fall back
/// to the peer address.
///
/// Every one of these means the tier is keying more coarsely than the operator
/// intended  -  behind a proxy, usually onto a single shared bucket. It is a
/// silent condition otherwise, hence the counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FallbackReason {
    /// The request did not arrive from a declared trusted proxy, so its
    /// forwarding headers are only assertions by the caller.
    UntrustedPeer,
    /// The configured header was not present at all.
    HeaderAbsent,
    /// The selected entry was not an address (obfuscated identifier, junk).
    Unparseable,
    /// Fewer `X-Forwarded-For` entries than `trusted_hops` requires.
    ChainTooShort,
}

impl FallbackReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::UntrustedPeer => "untrusted_peer",
            Self::HeaderAbsent => "header_absent",
            Self::Unparseable => "unparseable",
            Self::ChainTooShort => "chain_too_short",
        }
    }
}

/// Keys authenticated write traffic on the verified credential issuer.
///
/// Unforgeable without credential theft, and unaffected by network topology.
///
/// # Layering
///
/// This **must** sit inside the auth middleware, which is what publishes
/// [`VerifiedIssuer`]. Placed outside it, the extension is absent and every
/// request fails key extraction. `startup::tests` pins the ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedIssuerKeyExtractor;

impl KeyExtractor for VerifiedIssuerKeyExtractor {
    type Key = RateLimitKey;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        req.extensions()
            .get::<VerifiedIssuer>()
            .map(|issuer| RateLimitKey::Issuer(issuer.as_str().into()))
            // No peer-IP fallback: reaching this extractor means auth passed,
            // so a missing extension is a layering bug in this crate, not
            // something to paper over with a weaker key.
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Keys unauthenticated traffic on a client IP from an explicitly configured
/// source, honoured only when the request arrives from a declared proxy.
///
/// `X-Forwarded-For` and `X-Real-IP` are client-supplied. Reading them is safe
/// only if something in front of this server overwrote them, so the peer
/// address is checked against `trusted_proxies` first. A request from anywhere
/// else has its headers ignored entirely and is keyed on its own address --
/// coarse, but unforgeable. That check is what makes a header source a trust
/// boundary rather than an invitation.
///
/// Every fallback is invisible in the response, so each one increments
/// `rate_limit_ip_source_fallback{tier, reason}`. A steady stream of
/// `untrusted_peer` means the deployment does not match the configuration and
/// the header source is doing nothing.
#[derive(Debug, Clone)]
pub struct SecureIpKeyExtractor {
    source: ClientIpSource,
    trusted_hops: usize,
    /// Peers whose forwarding headers are honoured. Always empty for
    /// [`ClientIpSource::ConnectInfo`], which reads no headers.
    trusted_proxies: Arc<[IpNet]>,
    tier: &'static str,
    fallbacks: Option<Counter<u64>>,
}

impl SecureIpKeyExtractor {
    /// Builds an extractor that reports fallbacks to `meter`.
    pub fn new(
        source: ClientIpSource,
        trusted_hops: usize,
        trusted_proxies: Arc<[IpNet]>,
        tier: &'static str,
        meter: &opentelemetry::metrics::Meter,
    ) -> Self {
        Self {
            source,
            trusted_hops,
            trusted_proxies,
            tier,
            fallbacks: Some(
                meter
                    .u64_counter("rate_limit_ip_source_fallback")
                    .with_description(
                        "Requests where the configured client IP source could not be used \
                         and the peer address was keyed instead.",
                    )
                    .build(),
            ),
        }
    }

    /// Builds an extractor without instrumentation, for tests that only care
    /// about which address is selected.
    #[cfg(test)]
    fn uninstrumented(source: ClientIpSource, trusted_hops: usize) -> Self {
        Self {
            source,
            trusted_hops,
            trusted_proxies: tests::trusted_proxies(),
            tier: "test",
            fallbacks: None,
        }
    }

    fn record_fallback(&self, reason: FallbackReason) {
        if let Some(counter) = &self.fallbacks {
            counter.add(
                1,
                &[
                    KeyValue::new("tier", self.tier),
                    KeyValue::new("reason", reason.as_str()),
                ],
            );
        }
    }

    /// Whether this request came from a peer whose forwarding headers we honour.
    ///
    /// A missing `ConnectInfo` counts as untrusted: if the peer cannot be
    /// established, it cannot be shown to be a proxy.
    fn peer_is_trusted<T>(&self, req: &Request<T>) -> bool {
        peer_ip(req).is_some_and(|peer| {
            self.trusted_proxies
                .iter()
                .any(|network| network.contains(&peer))
        })
    }

    fn client_ip<T>(&self, req: &Request<T>) -> Option<IpAddr> {
        let derived = match self.source {
            // Nothing to fall back from: the connection address is the source.
            ClientIpSource::ConnectInfo => return peer_ip(req),
            _ if !self.peer_is_trusted(req) => Err(FallbackReason::UntrustedPeer),
            ClientIpSource::RightmostXForwardedFor => {
                rightmost_forwarded_for(req.headers(), self.trusted_hops)
            }
            ClientIpSource::XRealIp => x_real_ip(req.headers()),
        };

        match derived {
            Ok(ip) => Some(ip),
            Err(reason) => {
                self.record_fallback(reason);
                peer_ip(req)
            }
        }
    }
}

impl KeyExtractor for SecureIpKeyExtractor {
    type Key = RateLimitKey;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        self.client_ip(req)
            .map(|ip| RateLimitKey::Ip(bucket_ip(ip)))
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request as HttpRequest;
    use std::net::Ipv4Addr;

    /// Builds a request. `xff` entries are added as **separate header lines**
    /// so that multi-line `X-Forwarded-For`  -  the case that defeats naive
    /// `HeaderMap::get` parsing  -  is reachable from tests.
    fn request(xff: &[&str], connect_info: Option<IpAddr>) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder();
        for line in xff {
            builder = builder.header(&X_FORWARDED_FOR, *line);
        }
        if let Some(ip) = connect_info {
            builder = builder.extension(ConnectInfo(SocketAddr::new(ip, 4444)));
        }
        builder.body(Body::empty()).unwrap()
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// The proxy range the extractor tests treat as trusted. `10.0.0.1`, used
    /// as the peer throughout, sits inside it; `203.0.113.x` and friends do not.
    pub(super) fn trusted_proxies() -> Arc<[IpNet]> {
        Arc::from(vec!["10.0.0.0/8".parse::<IpNet>().unwrap()])
    }

    fn xff_extractor(trusted_hops: usize) -> SecureIpKeyExtractor {
        SecureIpKeyExtractor::uninstrumented(ClientIpSource::RightmostXForwardedFor, trusted_hops)
    }

    // ---- key namespacing -------------------------------------------------

    #[test]
    fn issuer_and_ip_keys_never_collide() {
        assert_ne!(
            RateLimitKey::Issuer("10.0.0.1".into()),
            RateLimitKey::Ip(ipv4(10, 0, 0, 1)),
            "an issuer named after an IP must not share that IP's bucket"
        );
    }

    // ---- verified issuer extractor ---------------------------------------

    fn issuer_request(issuer: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .extension(VerifiedIssuer::new(issuer))
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn verified_issuer_extractor_keys_on_the_extension() {
        assert_eq!(
            VerifiedIssuerKeyExtractor
                .extract(&issuer_request("issuer-a"))
                .unwrap(),
            RateLimitKey::Issuer("issuer-a".into())
        );
    }

    #[test]
    fn distinct_issuers_get_distinct_buckets() {
        let key_of = |iss: &str| {
            VerifiedIssuerKeyExtractor
                .extract(&issuer_request(iss))
                .unwrap()
        };
        assert_ne!(key_of("issuer-a"), key_of("issuer-b"));
    }

    /// The extension is only ever published by verified auth, so an
    /// `Authorization` header on its own must not produce a key. This is the
    /// unit-level statement of "a forged token cannot mint a bucket".
    #[test]
    fn unverified_authorization_header_yields_no_key() {
        let forged = HttpRequest::builder()
            .header(
                axum::http::header::AUTHORIZATION,
                "Bearer eyJhbGciOiJub25lIn0.eyJpc3MiOiJhbnl0aGluZy1hdC1hbGwifQ.sig",
            )
            .extension(ConnectInfo(SocketAddr::new(ipv4(10, 0, 0, 1), 4444)))
            .body(Body::empty())
            .unwrap();
        assert!(
            matches!(
                VerifiedIssuerKeyExtractor.extract(&forged),
                Err(GovernorError::UnableToExtractKey)
            ),
            "an unverified token must not be able to select a bucket"
        );
    }

    // ---- IP bucketing ----------------------------------------------------

    fn v6(s: &str) -> IpAddr {
        s.parse().expect("valid IPv6 literal")
    }

    /// Every address class the server can plausibly observe, so that a class
    /// with special masking behaviour cannot be added without a decision here.
    /// The IPv4-mapped rows are the important ones: a dual-stack listener
    /// reports IPv4 clients that way, and masking one to a /64 would leave `::`
    /// and put every IPv4 client on the internet in one bucket.
    #[test]
    fn bucket_ip_handles_every_address_class() {
        let cases: &[(&str, IpAddr, &str)] = &[
            (
                "IPv4",
                ipv4(203, 0, 113, 7),
                "keyed exactly; a /32 is already one host",
            ),
            (
                "IPv4-mapped",
                v6("::ffff:203.0.113.7"),
                "unwrapped to the IPv4 address it carries",
            ),
            (
                "IPv4-mapped, different host",
                v6("::ffff:198.51.100.42"),
                "must not share a bucket with other mapped addresses",
            ),
            (
                "IPv6 global unicast",
                v6("2001:db8::1"),
                "masked to its /64",
            ),
            ("IPv6 loopback", v6("::1"), "must not become 0.0.0.1"),
            (
                "IPv6 link-local",
                v6("fe80::1"),
                "masked to its /64 like any other v6",
            ),
        ];

        let expected: &[IpAddr] = &[
            ipv4(203, 0, 113, 7),
            ipv4(203, 0, 113, 7),
            ipv4(198, 51, 100, 42),
            v6("2001:db8::"),
            v6("::"),
            v6("fe80::"),
        ];

        for ((label, input, why), want) in cases.iter().zip(expected) {
            assert_eq!(bucket_ip(*input), *want, "{label}: {why}");
        }
    }

    /// The specific regression: mapped addresses must stay distinct from each
    /// other rather than all collapsing onto `::`.
    #[test]
    fn ipv4_mapped_addresses_do_not_share_one_bucket() {
        let keys: Vec<_> = [
            "::ffff:203.0.113.7",
            "::ffff:198.51.100.42",
            "::ffff:8.8.8.8",
        ]
        .into_iter()
        .map(|s| bucket_ip(v6(s)))
        .collect();
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    /// A client must land in the same bucket whether it reached an IPv4-only
    /// listener or a dual-stack one.
    #[test]
    fn a_client_keys_identically_over_ipv4_and_dual_stack_listeners() {
        let extractor = SecureIpKeyExtractor::uninstrumented(ClientIpSource::ConnectInfo, 0);
        let direct = request(&[], Some(ipv4(203, 0, 113, 7)));
        let dual_stack = request(&[], Some(v6("::ffff:203.0.113.7")));
        assert_eq!(
            extractor.extract(&direct).unwrap(),
            extractor.extract(&dual_stack).unwrap()
        );
    }

    #[test]
    fn ipv6_addresses_in_one_slash_64_share_a_bucket() {
        assert_eq!(
            bucket_ip(v6("2001:db8::1")),
            bucket_ip(v6("2001:db8::dead:beef:0:2"))
        );
        assert_eq!(bucket_ip(v6("2001:db8::1")), v6("2001:db8::"));
    }

    #[test]
    fn distinct_ipv6_slash_64s_keep_distinct_buckets() {
        assert_ne!(
            bucket_ip(v6("2001:db8:0:1::1")),
            bucket_ip(v6("2001:db8:0:2::1"))
        );
    }

    #[test]
    fn ipv6_bucketing_applies_to_extracted_keys() {
        let req = request(&[], Some(v6("2001:db8::99")));
        let extractor = SecureIpKeyExtractor::uninstrumented(ClientIpSource::ConnectInfo, 0);
        assert_eq!(
            extractor.extract(&req).unwrap(),
            RateLimitKey::Ip(v6("2001:db8::"))
        );
    }

    // ---- entry parsing ---------------------------------------------------

    #[test]
    fn forwarded_entries_parse_in_every_shape_proxies_emit() {
        for (raw, expected) in [
            ("203.0.113.7", ipv4(203, 0, 113, 7)),
            ("203.0.113.7:443", ipv4(203, 0, 113, 7)),
            ("2001:db8::1", v6("2001:db8::1")),
            ("[2001:db8::1]", v6("2001:db8::1")),
            ("[2001:db8::1]:443", v6("2001:db8::1")),
        ] {
            assert_eq!(parse_forwarded_ip(raw), Some(expected), "parsing {raw}");
        }
    }

    #[test]
    fn obfuscated_and_junk_entries_do_not_parse() {
        for raw in ["_hidden", "unknown", "", "   ", "not-an-ip"] {
            assert_eq!(parse_forwarded_ip(raw), None, "{raw:?} should not parse");
        }
    }

    // ---- rightmost XFF ---------------------------------------------------

    #[test]
    fn trusted_hops_zero_reads_the_rightmost_entry() {
        let req = request(&["1.1.1.1, 203.0.113.7"], Some(ipv4(10, 0, 0, 1)));
        assert_eq!(
            xff_extractor(0).extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(203, 0, 113, 7))
        );
    }

    #[test]
    fn trusted_hops_one_skips_the_innermost_proxy() {
        let req = request(&["1.1.1.1, 203.0.113.7, 10.0.0.1"], Some(ipv4(10, 0, 0, 1)));
        assert_eq!(
            xff_extractor(1).extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(203, 0, 113, 7))
        );
    }

    /// The core invariant from the issue, at the extractor level: with the
    /// trust boundary configured correctly, what the client puts in
    /// `X-Forwarded-For` cannot change which bucket it lands in.
    #[test]
    fn spoofed_left_hand_entries_do_not_change_the_bucket() {
        let proxy = ipv4(10, 0, 0, 1);
        let keys: Vec<_> = [
            vec!["1.1.1.1, 10.0.0.1"],
            vec!["2.2.2.2, 10.0.0.1"],
            vec!["9.9.9.9, 8.8.8.8, 7.7.7.7, 10.0.0.1"],
        ]
        .into_iter()
        .map(|lines| {
            xff_extractor(0)
                .extract(&request(&lines, Some(proxy)))
                .unwrap()
        })
        .collect();

        assert!(
            keys.windows(2).all(|w| w[0] == w[1]),
            "spoofed entries changed the bucket: {keys:?}"
        );
        assert_eq!(keys[0], RateLimitKey::Ip(proxy));
    }

    /// Regression test for the multi-line bypass: a client sends its own
    /// `X-Forwarded-For`, the proxy appends a second header line. Reading only
    /// the first line would make the "rightmost" entry `9.9.9.9`.
    #[test]
    fn a_client_supplied_xff_line_cannot_shadow_the_proxys_line() {
        let req = request(
            &["9.9.9.9", "203.0.113.7, 10.0.0.1"],
            Some(ipv4(10, 0, 0, 1)),
        );
        assert_eq!(
            xff_extractor(0).extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(10, 0, 0, 1)),
            "entries must be read across all header lines, in order"
        );
    }

    #[test]
    fn multi_line_entries_are_ordered_for_trusted_hops_too() {
        let req = request(
            &["9.9.9.9", "203.0.113.7, 10.0.0.1"],
            Some(ipv4(10, 0, 0, 1)),
        );
        assert_eq!(
            xff_extractor(1).extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(203, 0, 113, 7))
        );
    }

    /// A chain shorter than the configured hop count must not silently fall
    /// back to the leftmost  -  i.e. the fully client-controlled  -  entry.
    #[test]
    fn a_chain_shorter_than_trusted_hops_falls_back_to_the_peer() {
        let req = request(&["9.9.9.9"], Some(ipv4(10, 0, 0, 1)));
        assert_eq!(
            xff_extractor(1).extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(10, 0, 0, 1)),
            "a short chain must fall back to the unforgeable peer address"
        );
    }

    /// `trusted_hops` is bounded by config validation, but the extractor must
    /// not depend on that: an extreme value has to degrade to the peer address,
    /// not overflow or index out of range.
    #[test]
    fn an_extreme_trusted_hops_degrades_to_the_peer_address() {
        for hops in [usize::MAX, usize::MAX - 1, 10_000] {
            let req = request(&["9.9.9.9, 10.0.0.1"], Some(ipv4(10, 0, 0, 1)));
            assert_eq!(
                xff_extractor(hops).extract(&req).unwrap(),
                RateLimitKey::Ip(ipv4(10, 0, 0, 1)),
                "trusted_hops={hops} must not panic or read a client-supplied entry"
            );
        }
    }

    #[test]
    fn an_unparseable_selected_entry_falls_back_to_the_peer() {
        let req = request(&["203.0.113.7, _hidden"], Some(ipv4(10, 0, 0, 1)));
        assert_eq!(
            xff_extractor(0).extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(10, 0, 0, 1)),
            "must not reach further left for a parseable value"
        );
    }

    #[test]
    fn a_missing_xff_falls_back_to_the_peer() {
        let req = request(&[], Some(ipv4(10, 0, 0, 1)));
        assert_eq!(
            xff_extractor(0).extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(10, 0, 0, 1))
        );
    }

    // ---- trusted-proxy gating --------------------------------------------

    /// The mirror of `spoofed_left_hand_entries_do_not_change_the_bucket`, and
    /// the case that matters most: when the request did **not** come from a
    /// declared proxy, the header is only an assertion by the caller. It must
    /// be ignored entirely, so a spoofed request lands in the same bucket as an
    /// unspoofed one from the same address.
    #[test]
    fn headers_from_an_untrusted_peer_cannot_change_the_bucket() {
        let extractor = xff_extractor(0);
        // 203.0.113.9 is outside the trusted 10.0.0.0/8 range.
        let untrusted = ipv4(203, 0, 113, 9);

        let plain = extractor.extract(&request(&[], Some(untrusted))).unwrap();
        let spoofed = extractor
            .extract(&request(&["1.1.1.1, 2.2.2.2"], Some(untrusted)))
            .unwrap();
        let spoofed_differently = extractor
            .extract(&request(&["9.9.9.9"], Some(untrusted)))
            .unwrap();

        assert_eq!(plain, RateLimitKey::Ip(untrusted));
        assert_eq!(plain, spoofed);
        assert_eq!(plain, spoofed_differently);
    }

    /// Same for `x_real_ip`: the header is honoured only behind a declared proxy.
    #[test]
    fn x_real_ip_from_an_untrusted_peer_is_ignored() {
        let extractor = SecureIpKeyExtractor::uninstrumented(ClientIpSource::XRealIp, 0);
        let untrusted = ipv4(203, 0, 113, 9);
        let req = real_ip_request(&["198.51.100.5"], untrusted);
        assert_eq!(
            extractor.extract(&req).unwrap(),
            RateLimitKey::Ip(untrusted),
            "an unproxied caller must not be able to assert its own address"
        );
    }

    /// Rotating the header from an untrusted peer must not grow the key space -
    /// this is the memory-exhaustion half of the original issue.
    #[test]
    fn rotating_headers_from_an_untrusted_peer_yield_one_key() {
        let extractor = xff_extractor(0);
        let untrusted = ipv4(203, 0, 113, 9);
        let keys: std::collections::HashSet<_> = (0..50)
            .map(|i| {
                let spoof = format!("198.51.100.{i}");
                extractor
                    .extract(&request(&[spoof.as_str()], Some(untrusted)))
                    .unwrap()
            })
            .collect();
        assert_eq!(keys.len(), 1, "50 spoofed headers produced {keys:?}");
    }

    /// The trusted path still works: from a declared proxy the header is read.
    #[test]
    fn headers_from_a_trusted_peer_are_honoured() {
        let extractor = xff_extractor(0);
        let req = request(&["1.1.1.1, 198.51.100.5"], Some(ipv4(10, 0, 0, 1)));
        assert_eq!(
            extractor.extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(198, 51, 100, 5))
        );
    }

    /// A request with no connection info cannot be shown to come from a proxy,
    /// so its headers are not honoured either.
    #[test]
    fn headers_without_connect_info_are_not_honoured() {
        let extractor = xff_extractor(0);
        assert!(matches!(
            extractor.extract(&request(&["1.1.1.1"], None)),
            Err(GovernorError::UnableToExtractKey)
        ));
    }

    // ---- fallback reasons ------------------------------------------------
    //
    // Every fallback below produces the same key (the peer address) and the
    // same response, so `rate_limit_ip_source_fallback{reason}` is the only
    // thing that distinguishes them. These assert the label, not the key.

    fn headers_with(xff: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in xff {
            headers.append(&X_FORWARDED_FOR, line.parse().unwrap());
        }
        headers
    }

    /// The likeliest misconfiguration: `rightmost_x_forwarded_for` selected on a
    /// deployment with no proxy in front of it. Reporting `chain_too_short`
    /// here would send an operator to tune `trusted_hops`, which cannot fix a
    /// header that is not being set at all.
    #[test]
    fn no_forwarded_header_reports_header_absent_not_chain_too_short() {
        assert_eq!(
            rightmost_forwarded_for(&headers_with(&[]), 0),
            Err(FallbackReason::HeaderAbsent)
        );
        // Also with a non-zero hop count, where the temptation to blame
        // `trusted_hops` is strongest.
        assert_eq!(
            rightmost_forwarded_for(&headers_with(&[]), 2),
            Err(FallbackReason::HeaderAbsent)
        );
    }

    /// A header that *is* present but has fewer entries than `trusted_hops`
    /// requires is the case where tuning `trusted_hops` is the right advice.
    #[test]
    fn a_short_chain_reports_chain_too_short() {
        assert_eq!(
            rightmost_forwarded_for(&headers_with(&["203.0.113.7"]), 1),
            Err(FallbackReason::ChainTooShort)
        );
    }

    #[test]
    fn an_unparseable_entry_reports_unparseable() {
        assert_eq!(
            rightmost_forwarded_for(&headers_with(&["203.0.113.7, _hidden"]), 0),
            Err(FallbackReason::Unparseable)
        );
    }

    /// The three failures must stay distinguishable; if any two collapsed, the
    /// metric would keep working while pointing at the wrong remedy.
    #[test]
    fn the_forwarded_fallback_reasons_are_all_reachable_and_distinct() {
        let observed = [
            rightmost_forwarded_for(&headers_with(&[]), 0),
            rightmost_forwarded_for(&headers_with(&["203.0.113.7"]), 1),
            rightmost_forwarded_for(&headers_with(&["_hidden"]), 0),
        ];
        assert_eq!(
            observed,
            [
                Err(FallbackReason::HeaderAbsent),
                Err(FallbackReason::ChainTooShort),
                Err(FallbackReason::Unparseable),
            ]
        );
    }

    #[test]
    fn x_real_ip_fallback_reasons_are_distinct() {
        let mut absent = HeaderMap::new();
        assert_eq!(x_real_ip(&absent), Err(FallbackReason::HeaderAbsent));

        absent.append(&X_REAL_IP, "_hidden".parse().unwrap());
        assert_eq!(x_real_ip(&absent), Err(FallbackReason::Unparseable));
    }

    #[test]
    fn every_fallback_reason_has_a_distinct_label() {
        let labels = [
            FallbackReason::HeaderAbsent.as_str(),
            FallbackReason::ChainTooShort.as_str(),
            FallbackReason::Unparseable.as_str(),
        ];
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len(), "labels must be distinct");
    }

    // ---- X-Real-IP -------------------------------------------------------

    fn real_ip_request(values: &[&str], connect_info: IpAddr) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder();
        for value in values {
            builder = builder.header(&X_REAL_IP, *value);
        }
        builder
            .extension(ConnectInfo(SocketAddr::new(connect_info, 4444)))
            .body(Body::empty())
            .unwrap()
    }

    /// `X-Real-IP` is single-valued. Two of them means a client injected one or
    /// two proxies both wrote it, and nothing says which to believe. Picking
    /// either is the coin-flip this module exists to remove, so the header is
    /// discarded and the unforgeable peer address is used.
    #[test]
    fn multiple_x_real_ip_values_are_not_guessed_between() {
        let req = real_ip_request(&["9.9.9.9", "203.0.113.7"], ipv4(10, 0, 0, 1));
        let extractor = SecureIpKeyExtractor::uninstrumented(ClientIpSource::XRealIp, 0);
        assert_eq!(
            extractor.extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(10, 0, 0, 1))
        );

        let mut headers = HeaderMap::new();
        headers.append(&X_REAL_IP, "9.9.9.9".parse().unwrap());
        headers.append(&X_REAL_IP, "203.0.113.7".parse().unwrap());
        assert_eq!(x_real_ip(&headers), Err(FallbackReason::Unparseable));
    }

    #[test]
    fn a_single_x_real_ip_value_is_honoured() {
        let req = real_ip_request(&["203.0.113.7"], ipv4(10, 0, 0, 1));
        let extractor = SecureIpKeyExtractor::uninstrumented(ClientIpSource::XRealIp, 0);
        assert_eq!(
            extractor.extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(203, 0, 113, 7))
        );
    }

    #[test]
    fn x_real_ip_is_not_split_on_commas() {
        let req = real_ip_request(&["9.9.9.9, 203.0.113.7"], ipv4(10, 0, 0, 1));
        let extractor = SecureIpKeyExtractor::uninstrumented(ClientIpSource::XRealIp, 0);
        assert_eq!(
            extractor.extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(10, 0, 0, 1)),
            "an injected list is not a valid X-Real-IP; fall back rather than take the leftmost"
        );
    }

    #[test]
    fn x_real_ip_ignores_forwarded_for_entirely() {
        let mut builder = HttpRequest::builder();
        builder = builder.header(&X_FORWARDED_FOR, "9.9.9.9");
        let req = builder
            .extension(ConnectInfo(SocketAddr::new(ipv4(10, 0, 0, 1), 4444)))
            .body(Body::empty())
            .unwrap();
        let extractor = SecureIpKeyExtractor::uninstrumented(ClientIpSource::XRealIp, 0);
        assert_eq!(
            extractor.extract(&req).unwrap(),
            RateLimitKey::Ip(ipv4(10, 0, 0, 1))
        );
    }

    // ---- ConnectInfo -----------------------------------------------------

    #[test]
    fn connect_info_source_ignores_forwarding_headers_entirely() {
        let extractor = SecureIpKeyExtractor::uninstrumented(ClientIpSource::ConnectInfo, 0);
        let spoofed = request(&["9.9.9.9"], Some(ipv4(10, 0, 0, 1)));
        let plain = request(&[], Some(ipv4(10, 0, 0, 1)));
        assert_eq!(
            extractor.extract(&spoofed).unwrap(),
            extractor.extract(&plain).unwrap()
        );
    }

    #[test]
    fn missing_connect_info_is_an_extraction_failure() {
        let req = request(&[], None);
        let extractor = SecureIpKeyExtractor::uninstrumented(ClientIpSource::ConnectInfo, 0);
        assert!(matches!(
            extractor.extract(&req),
            Err(GovernorError::UnableToExtractKey)
        ));
    }
}
