use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::http::{HeaderMap, HeaderName, Request, header};
use tower_governor::{errors::GovernorError, key_extractor::KeyExtractor};

use crate::config::ClientIpSource;

static X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

fn extract_issuer_from_jwt(headers: &HeaderMap) -> Option<String> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))?;

    let mut parts = token.split('.');
    parts.next()?;
    let payload = parts.next()?;
    let decoded = base64url::decode(payload).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    value.get("iss")?.as_str().map(|s| s.to_string())
}

fn peer_ip<T>(req: &Request<T>) -> Option<IpAddr> {
    req.extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|addr| addr.ip())
}

fn normalize_ipv6(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            ))
        }
        IpAddr::V4(_) => ip,
    }
}

/// Key extractor that reads the `iss` claim from a Bearer JWT without
/// verification.
///
/// **Deprecated**: No longer used in production. Rate limiting on write
/// endpoints now uses `SmartIpKeyExtractor` (IP-based via trusted proxy
/// headers or peer IP), so JWT claim forgery no longer changes the write
/// rate-limit key. Deployments behind ingress must configure trusted proxy
/// headers via ingress-nginx ConfigMap settings (e.g., `use-forwarded-headers`,
/// `set-real-ip-from`) since `configuration-snippet` annotations are disabled
/// by default in production (allow-snippet-annotations: false). The type
/// and its tests are retained for unit-test coverage of the extraction logic.
///
/// Falls back to the peer IP when the token is absent or malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuerKeyExtractor;

impl KeyExtractor for IssuerKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        if let Some(issuer) = extract_issuer_from_jwt(req.headers()) {
            return Ok(issuer);
        }
        peer_ip(req)
            .map(|ip| ip.to_string())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Keys on `iss` claim for authenticated requests, falling back to peer IP
/// for unauthenticated requests. This is used for the write (strict) tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedKeyExtractor;

impl KeyExtractor for AuthenticatedKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        if let Some(issuer) = extract_issuer_from_jwt(req.headers()) {
            return Ok(issuer);
        }
        peer_ip(req)
            .map(|ip| ip.to_string())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Keys on client IP using a configurable source. Supports direct connection,
/// rightmost `X-Forwarded-For` IP (with configurable trust hops), and `X-Real-IP`.
#[derive(Debug, Clone)]
pub struct SecureIpKeyExtractor {
    source: ClientIpSource,
}

impl SecureIpKeyExtractor {
    pub fn new(source: ClientIpSource) -> Self {
        Self { source }
    }

    fn extract_ip<T>(&self, req: &Request<T>) -> Option<IpAddr> {
        match self.source {
            ClientIpSource::ConnectInfo => req
                .extensions()
                .get::<axum::extract::ConnectInfo<SocketAddr>>()
                .map(|ci| ci.ip()),
            ClientIpSource::RightmostXForwardedFor { trusted_hops } => {
                extract_rightmost_x_forwarded_for(req, trusted_hops).or_else(|| peer_ip(req))
            }
            ClientIpSource::XRealIp => extract_x_real_ip(req).or_else(|| peer_ip(req)),
        }
    }
}

fn extract_x_real_ip<T>(req: &Request<T>) -> Option<IpAddr> {
    req.headers()
        .get(&X_REAL_IP)?
        .to_str()
        .ok()?
        .split(',')
        .next()?
        .trim()
        .parse()
        .ok()
}

fn extract_rightmost_x_forwarded_for<T>(req: &Request<T>, trusted_hops: usize) -> Option<IpAddr> {
    let header_value = req.headers().get(&X_FORWARDED_FOR)?.to_str().ok()?;

    let ips: Vec<&str> = header_value.split(',').map(|s| s.trim()).collect();
    if ips.is_empty() {
        return None;
    }

    let idx = if trusted_hops >= ips.len() {
        0
    } else {
        ips.len() - 1 - trusted_hops
    };

    ips.get(idx)?.parse().ok()
}

impl KeyExtractor for SecureIpKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let ip = self
            .extract_ip(req)
            .ok_or(GovernorError::UnableToExtractKey)?;
        let normalized = normalize_ipv6(ip);
        Ok(normalized.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request as HttpRequest;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn make_request(headers: HeaderMap, ext: Option<ConnectInfo<SocketAddr>>) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder();
        for (name, value) in headers.iter() {
            builder = builder.header(name, value);
        }
        if let Some(ci) = ext {
            builder = builder.extension(ci);
        }
        builder.body(Body::empty()).unwrap()
    }

    fn dummy_jwt(iss: &str) -> String {
        let header = base64url::encode(br#"{"alg":"ES256"}"#);
        let payload_json = format!(r#"{{"iss":"{iss}","exp":9999999999}}"#);
        let payload = base64url::encode(payload_json.as_bytes());
        format!("{header}.{payload}.signature")
    }

    #[test]
    fn test_extract_issuer_from_valid_jwt() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", dummy_jwt("issuer-123"))
                .parse()
                .unwrap(),
        );
        let req = make_request(headers, None);
        let key = IssuerKeyExtractor.extract(&req).unwrap();
        assert_eq!(key, "issuer-123");
    }

    #[test]
    fn test_falls_back_to_peer_ip_when_no_auth_header() {
        let headers = HeaderMap::new();
        let ci = ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));
        let req = make_request(headers, Some(ci));
        let key = IssuerKeyExtractor.extract(&req).unwrap();
        assert_eq!(key, "10.0.0.1");
    }

    #[test]
    fn test_falls_back_to_peer_ip_when_malformed_jwt() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer not-a-jwt".parse().unwrap());
        let ci = ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8080,
        ));
        let req = make_request(headers, Some(ci));
        let key = IssuerKeyExtractor.extract(&req).unwrap();
        assert_eq!(key, "10.0.0.2");
    }

    #[test]
    fn test_returns_error_when_no_token_and_no_peer_ip() {
        let headers = HeaderMap::new();
        let req = make_request(headers, None);
        let result = IssuerKeyExtractor.extract(&req);
        assert!(matches!(result, Err(GovernorError::UnableToExtractKey)));
    }

    #[test]
    fn test_different_issuers_produce_different_keys() {
        let mut headers1 = HeaderMap::new();
        headers1.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", dummy_jwt("issuer-a")).parse().unwrap(),
        );
        let req1 = make_request(headers1, None);

        let mut headers2 = HeaderMap::new();
        headers2.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", dummy_jwt("issuer-b")).parse().unwrap(),
        );
        let req2 = make_request(headers2, None);

        let key1 = IssuerKeyExtractor.extract(&req1).unwrap();
        let key2 = IssuerKeyExtractor.extract(&req2).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_authenticated_key_extractor_with_jwt() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", dummy_jwt("issuer-456"))
                .parse()
                .unwrap(),
        );
        let req = make_request(headers, None);
        let key = AuthenticatedKeyExtractor.extract(&req).unwrap();
        assert_eq!(key, "issuer-456");
    }

    #[test]
    fn test_authenticated_falls_back_to_peer_ip() {
        let headers = HeaderMap::new();
        let ci = ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));
        let req = make_request(headers, Some(ci));
        let key = AuthenticatedKeyExtractor.extract(&req).unwrap();
        assert_eq!(key, "10.0.0.1");
    }

    #[test]
    fn test_normalize_ipv6_to_64_prefix() {
        let ip = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
        ));
        let normalized = normalize_ipv6(ip);
        let expected = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        ));
        assert_eq!(normalized, expected);
    }

    #[test]
    fn test_normalize_ipv4_unchanged() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let normalized = normalize_ipv6(ip);
        assert_eq!(normalized, ip);
    }

    #[test]
    fn test_secure_ip_connect_info() {
        let headers = HeaderMap::new();
        let ci = ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));
        let req = make_request(headers, Some(ci));
        let extractor = SecureIpKeyExtractor::new(ClientIpSource::ConnectInfo);
        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "10.0.0.1");
    }

    #[test]
    fn test_secure_ip_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(X_REAL_IP.clone(), "1.2.3.4".parse().unwrap());
        let ci = ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));
        let req = make_request(headers, Some(ci));
        let extractor = SecureIpKeyExtractor::new(ClientIpSource::XRealIp);
        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "1.2.3.4");
    }

    #[test]
    fn test_secure_ip_rightmost_xff() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR.clone(), "1.1.1.1, 2.2.2.2".parse().unwrap());
        let ci = ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));
        let req = make_request(headers, Some(ci));
        let extractor =
            SecureIpKeyExtractor::new(ClientIpSource::RightmostXForwardedFor { trusted_hops: 0 });
        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "2.2.2.2");
    }

    #[test]
    fn test_secure_ip_rightmost_xff_with_trusted_hops() {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR.clone(),
            "1.1.1.1, 2.2.2.2, 3.3.3.3".parse().unwrap(),
        );
        let ci = ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));
        let req = make_request(headers, Some(ci));
        let extractor =
            SecureIpKeyExtractor::new(ClientIpSource::RightmostXForwardedFor { trusted_hops: 1 });
        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "2.2.2.2");
    }

    #[test]
    fn test_secure_ip_spoofed_xff_shared_bucket() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR.clone(), "3.3.3.3".parse().unwrap());
        let req = make_request(headers, None);
        let extractor =
            SecureIpKeyExtractor::new(ClientIpSource::RightmostXForwardedFor { trusted_hops: 0 });
        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "3.3.3.3");
    }

    #[test]
    fn test_rightmost_xff_trusted_hops_zero_extracts_rightmost() {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR.clone(),
            "1.2.3.4, 10.0.0.1".parse().unwrap(),
        );
        let ci = ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080));
        let req = make_request(headers, Some(ci));

        let extractor =
            SecureIpKeyExtractor::new(ClientIpSource::RightmostXForwardedFor { trusted_hops: 0 });
        let key = extractor.extract(&req).unwrap();
        assert_eq!(
            key, "10.0.0.1",
            "trusted_hops=0 extracts the rightmost XFF value"
        );
    }

    #[test]
    fn test_rightmost_xff_trusted_hops_one_skips_rightmost() {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR.clone(),
            "1.2.3.4, 10.0.0.1".parse().unwrap(),
        );
        let ci = ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080));
        let req = make_request(headers, Some(ci));

        let extractor =
            SecureIpKeyExtractor::new(ClientIpSource::RightmostXForwardedFor { trusted_hops: 1 });
        let key = extractor.extract(&req).unwrap();
        assert_eq!(
            key, "1.2.3.4",
            "trusted_hops=1 skips the rightmost XFF value and extracts second-from-rightmost"
        );
    }

    #[test]
    fn test_rightmost_xff_trusted_hops_zero_same_key_despite_client_spoofing() {
        let ci = ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080));

        let mut headers_a = HeaderMap::new();
        headers_a.insert(
            X_FORWARDED_FOR.clone(),
            "1.1.1.1, 10.0.0.1".parse().unwrap(),
        );
        let req_a = make_request(headers_a, Some(ci));

        let mut headers_b = HeaderMap::new();
        headers_b.insert(
            X_FORWARDED_FOR.clone(),
            "2.2.2.2, 10.0.0.1".parse().unwrap(),
        );
        let req_b = make_request(headers_b, Some(ci));

        let extractor =
            SecureIpKeyExtractor::new(ClientIpSource::RightmostXForwardedFor { trusted_hops: 0 });
        let key_a = extractor.extract(&req_a).unwrap();
        let key_b = extractor.extract(&req_b).unwrap();
        assert_eq!(
            key_a, key_b,
            "With trusted_hops=0, spoofing the leftmost client IP does NOT change the extracted key \
             because the rightmost value (trusted proxy) is always the same"
        );
        assert_eq!(key_a, "10.0.0.1");
    }

    #[test]
    fn test_rightmost_xff_trusted_hops_one_different_client_keys() {
        let ci = ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080));

        let mut headers_a = HeaderMap::new();
        headers_a.insert(
            X_FORWARDED_FOR.clone(),
            "1.1.1.1, 10.0.0.1".parse().unwrap(),
        );
        let req_a = make_request(headers_a, Some(ci));

        let mut headers_b = HeaderMap::new();
        headers_b.insert(
            X_FORWARDED_FOR.clone(),
            "2.2.2.2, 10.0.0.1".parse().unwrap(),
        );
        let req_b = make_request(headers_b, Some(ci));

        let extractor =
            SecureIpKeyExtractor::new(ClientIpSource::RightmostXForwardedFor { trusted_hops: 1 });
        let key_a = extractor.extract(&req_a).unwrap();
        let key_b = extractor.extract(&req_b).unwrap();
        assert_ne!(
            key_a, key_b,
            "With trusted_hops=1, spoofing the leftmost XFF (client IP) changes the extracted key \
             because trusted_hops skips the rightmost proxy and reads the client IP"
        );
    }

    #[test]
    fn test_rightmost_xff_no_xff_falls_back_to_connect_info() {
        let headers = HeaderMap::new();
        let ci = ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080));
        let req = make_request(headers, Some(ci));

        let extractor =
            SecureIpKeyExtractor::new(ClientIpSource::RightmostXForwardedFor { trusted_hops: 0 });
        let key = extractor.extract(&req).unwrap();
        assert_eq!(
            key, "10.0.0.1",
            "No XFF header should fall back to ConnectInfo IP"
        );
    }

    #[test]
    fn test_rightmost_xff_nginx_overwrites_to_same_connect_info() {
        let ci = ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080));

        let mut headers_spoofed = HeaderMap::new();
        headers_spoofed.insert(
            X_FORWARDED_FOR.clone(),
            "real_client, 10.0.0.1".parse().unwrap(),
        );
        let req_spoofed = make_request(headers_spoofed, Some(ci));

        let req_unspoofed = make_request(HeaderMap::new(), Some(ci));

        let extractor =
            SecureIpKeyExtractor::new(ClientIpSource::RightmostXForwardedFor { trusted_hops: 0 });
        let key_spoofed = extractor.extract(&req_spoofed).unwrap();
        let key_unspoofed = extractor.extract(&req_unspoofed).unwrap();
        assert_eq!(
            key_spoofed, key_unspoofed,
            "nginx-overwritten XFF (client on left, proxy on right) and no-XFF request produce \
             the same key because rightmost extraction gives the same proxy IP, and fallback \
             to peer IP (same proxy) gives the same result"
        );
        assert_eq!(key_spoofed, "10.0.0.1");
    }
}
