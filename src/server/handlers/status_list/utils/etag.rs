use crate::domain::models::status_list::{StatusListRecord, StatusListSnapshot};
use sha2::{Digest, Sha256};

/// Strong ETag for the *live* representation, derived from the actual signed
/// token bytes that the server serves.
///
/// Because the bytes for a given `(list, window_start, format, encoding)` are
/// identical across the whole anchored window (the token's `iat` is pinned to
/// `window_start`), the strong ETag *proves which token the client holds*: a
/// matching `If-None-Match` guarantees the client's cached token is byte-for-byte
/// the same as the current one, and since that token expires at
/// `window_start + exp_secs` (which lies strictly after the window), a 304 never
/// stranding an expired token. This lets the conditional logic drop the separate
/// expired-token runway handling.
pub(crate) fn generate_token_etag(token_bytes: &[u8]) -> String {
    let hash = Sha256::digest(token_bytes);
    format!("\"{}\"", hex::encode(hash))
}

/// Content hash over the representation-driving fields of `record`, excluding
/// the window: used to key the signed-token bytes cache so any content change
/// immediately produces a fresh sign.
pub(crate) fn content_hash(record: &StatusListRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(record.status_list.bits.to_string().as_bytes());
    hasher.update(record.status_list.lst.as_bytes());
    hasher.update(record.issuer.0.as_bytes());
    hasher.update(record.sub.as_bytes());
    hex::encode(hasher.finalize())
}

pub(crate) fn generate_historical_etag(snapshot: &StatusListSnapshot) -> String {
    let mut hasher = Sha256::new();

    hasher.update(snapshot.snapshot_id.as_bytes());
    hasher.update(snapshot.iat.to_string().as_bytes());
    hasher.update(snapshot.exp.to_string().as_bytes());
    hasher.update(snapshot.status_list.lst.as_bytes());
    hasher.update(snapshot.issuer.0.as_bytes());

    let hash = hasher.finalize();
    hex::encode(hash)
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
            },
            sub: "https://example.com/credentials/status/3".to_string(),
            updated_at: 1234567890,
        }
    }

    #[test]
    fn test_generate_token_etag_format() {
        let etag = generate_token_etag(b"token-bytes");
        assert!(
            etag.starts_with('"'),
            "ETag should be a strong quoted value"
        );
        assert!(etag.ends_with('"'), "ETag should end with \"");
        assert!(
            !etag.starts_with("W/"),
            "live ETag must be strong, not weak"
        );

        let hex_part = &etag[1..etag.len() - 1];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_token_etag_determinism() {
        assert_eq!(generate_token_etag(b"same"), generate_token_etag(b"same"));
        assert_ne!(
            generate_token_etag(b"same"),
            generate_token_etag(b"different")
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
}
