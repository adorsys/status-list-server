use std::net::{IpAddr, SocketAddr};

use axum::http::{HeaderMap, Request, header};
use tower_governor::{errors::GovernorError, key_extractor::KeyExtractor};

/// Key extractor that rate-limits auth-protected routes per issuer.
///
/// Reads the `iss` claim from the Bearer JWT without verification (the `auth`
/// middleware still verifies the signature afterwards).  Falls back to the
/// peer IP when the token is absent or malformed so unauthenticated requests
/// are still throttled and then rejected by `auth` with `401`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request as HttpRequest;
    use std::net::{Ipv4Addr, SocketAddr};

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
        let mut headers_a = HeaderMap::new();
        headers_a.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", dummy_jwt("issuer-a")).parse().unwrap(),
        );
        let mut headers_b = HeaderMap::new();
        headers_b.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", dummy_jwt("issuer-b")).parse().unwrap(),
        );
        let req_a = make_request(headers_a, None);
        let req_b = make_request(headers_b, None);
        assert_ne!(
            IssuerKeyExtractor.extract(&req_a).unwrap(),
            IssuerKeyExtractor.extract(&req_b).unwrap()
        );
    }
}
