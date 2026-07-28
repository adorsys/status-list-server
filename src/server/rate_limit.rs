use std::net::{IpAddr, SocketAddr};

use axum::http::{HeaderMap, Request, header};
use tower_governor::{errors::GovernorError, key_extractor::KeyExtractor};

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
    use std::net::SocketAddr;

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
}
