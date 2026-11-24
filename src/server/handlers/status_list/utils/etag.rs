use crate::domain::models::status_list::{StatusListError, StatusListRecord, StatusListSnapshot};
use crate::server::cache::TokenEncoding;
use sha2::{Digest, Sha256};

/// Strong ETag over the exact served bytes, stable within a window because those bytes are cached.
/// Signatures are randomized, so replicas disagree on it; that's accepted.
pub(crate) fn generate_token_etag(representation_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(representation_bytes);
    format!("\"{}\"", hex::encode(hasher.finalize()))
}

/// Cache-key input: any content change forces a fresh sign.
pub(crate) fn content_hash(record: &StatusListRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(record.status_list.bits.to_string().as_bytes());
    hasher.update(record.status_list.lst.as_bytes());
    hasher.update(record.issuer.0.as_bytes());
    hasher.update(record.sub.as_bytes());
    hex::encode(hasher.finalize())
}

/// Weak on purpose: historical tokens are re-signed per request, so their bytes never repeat.
pub(crate) fn generate_historical_etag(
    snapshot: &StatusListSnapshot,
    format: &str,
    encoding: TokenEncoding,
) -> Result<String, StatusListError> {
    let mut hasher = Sha256::new();
    let (bits, lst) = snapshot.status_list.token_lst()?;

    hasher.update(snapshot.snapshot_id.as_bytes());
    hasher.update(snapshot.iat.to_string().as_bytes());
    hasher.update(snapshot.exp.to_string().as_bytes());
    hasher.update(bits.to_string().as_bytes());
    hasher.update(lst.as_bytes());
    hasher.update(snapshot.issuer.0.as_bytes());
    hasher.update(format.as_bytes());
    hasher.update(encoding_label(encoding).as_bytes());

    let hash = hasher.finalize();
    Ok(format!("W/\"{}\"", hex::encode(hash)))
}

fn encoding_label(encoding: TokenEncoding) -> &'static str {
    match encoding {
        TokenEncoding::Identity => "identity",
        TokenEncoding::Gzip => "gzip",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::domain::models::status_list::StatusList;

    fn create_test_record() -> StatusListRecord {
        StatusListRecord {
            list_id: "test-list".to_string(),
            issuer: Issuer("https://issuer.example".to_string()),
            status_list: StatusList {
                bits: 1,
                lst: "eNrbuRgAAhcBXQ".to_string(),
                size: None,
                default_status: None,
            },
            sub: "https://example.com/credentials/status/3".to_string(),
            updated_at: 1234567890,
            version: 1,
        }
    }

    #[test]
    fn test_generate_token_etag_is_strong() {
        let etag = generate_token_etag(b"some representation bytes");
        assert!(
            etag.starts_with('"') && etag.ends_with('"'),
            "live ETag must be strong (\"...\"), not weak (W/\"...\")"
        );
        assert!(!etag.starts_with("W/"), "live ETag must not be weak");
        let hex_part = &etag[1..etag.len() - 1];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_token_etag_determinism() {
        assert_eq!(
            generate_token_etag(b"same bytes"),
            generate_token_etag(b"same bytes")
        );
    }

    #[test]
    fn test_generate_token_etag_changes_with_bytes() {
        assert_ne!(
            generate_token_etag(b"representation A"),
            generate_token_etag(b"representation B")
        );
        assert_ne!(generate_token_etag(b"aaa"), generate_token_etag(b"aab"));
    }

    #[test]
    fn test_generate_token_etag_identity_vs_gzip_bytes_differ() {
        let identity = b"the status list token";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        use std::io::Write as _;
        encoder.write_all(identity).unwrap();
        let gzip = encoder.finish().unwrap();
        assert_ne!(
            generate_token_etag(identity),
            generate_token_etag(&gzip),
            "identity and gzip representations must not share a strong ETag"
        );
    }

    #[test]
    fn test_content_hash_determinism_and_sensitivity() {
        let r1 = create_test_record();
        let r2 = create_test_record();
        assert_eq!(content_hash(&r1), content_hash(&r2));

        let mut changed = create_test_record();
        changed.status_list.lst = "changed".to_string();
        assert_ne!(content_hash(&r1), content_hash(&changed));
    }

    fn base_snapshot() -> StatusListSnapshot {
        StatusListSnapshot {
            snapshot_id: "snap-1".to_string(),
            list_id: "list".to_string(),
            issuer: Issuer("https://issuer.example".to_string()),
            status_list: StatusList {
                bits: 1,
                lst: "eNrbuRgAAhcBXQ".to_string(),
                size: None,
                default_status: None,
            },
            sub: "https://example.com/credentials/status/3".to_string(),
            iat: 1000,
            exp: 1900,
            version: 1,
        }
    }

    #[test]
    fn test_generate_historical_etag_is_weak() {
        let etag = generate_historical_etag(&base_snapshot(), "jwt", TokenEncoding::Identity)
            .expect("etag");
        assert!(
            etag.starts_with("W/\""),
            "historical ETag must be weak (W/\"...\"), not strong"
        );
        assert!(etag.ends_with('"'));
        let hex_part = &etag[3..etag.len() - 1];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_historical_etag_is_deterministic() {
        let a = generate_historical_etag(&base_snapshot(), "jwt", TokenEncoding::Identity).unwrap();
        let b = generate_historical_etag(&base_snapshot(), "jwt", TokenEncoding::Identity).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_generate_historical_etag_changes_with_format_and_encoding() {
        let base = base_snapshot();
        let jwt = generate_historical_etag(&base, "jwt", TokenEncoding::Identity).unwrap();
        let cwt = generate_historical_etag(&base, "cwt", TokenEncoding::Identity).unwrap();
        let gzip = generate_historical_etag(&base, "jwt", TokenEncoding::Gzip).unwrap();
        assert_ne!(jwt, cwt, "JWT and CWT must not share a validator");
        assert_ne!(jwt, gzip, "identity and gzip must not share a validator");
        assert_ne!(
            generate_historical_etag(&base, "cwt", TokenEncoding::Gzip).unwrap(),
            jwt,
            "the CWT-gzip combination must differ from JWT-identity"
        );
    }

    #[test]
    fn test_generate_historical_etag_changes_with_snapshot_content() {
        let base = base_snapshot();
        let mut changed = base.clone();
        changed.status_list.lst = "different-content".to_string();
        assert_ne!(
            generate_historical_etag(&base, "jwt", TokenEncoding::Identity).unwrap(),
            generate_historical_etag(&changed, "jwt", TokenEncoding::Identity).unwrap(),
            "a changed snapshot must change the historical ETag"
        );
    }
}
