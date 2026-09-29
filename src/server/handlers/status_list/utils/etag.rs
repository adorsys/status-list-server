use crate::domain::models::status_list::{StatusListError, StatusListRecord, StatusListSnapshot};
use crate::server::cache::{TokenCacheKey, TokenEncoding};
use sha2::{Digest, Sha256};

/// Weak ETag for the live representation, derived from the *representation
/// identity* rather than the signed bytes themselves.
///
/// A strong ETag must change whenever the bytes change (RFC 9110 §8.8.3.1), but
/// ES256 signatures are randomized: the signed bytes for a token differ between
/// requests on a cold cache, across replicas, across restarts, and on capacity
/// eviction. A digest of the signed bytes would therefore make the ETag only as
/// stable as this replica's cache — a client holding a valid token would get a
/// `200` (and a fresh sign) instead of a `304` whenever the entry wasn't cached
/// here. That defeats the very conditional GET this validator exists to serve.
///
/// Instead the ETag is a **weak** validator (`W/"..."`) over the dimensions that
/// pin the representation identity: `(list_id, content_hash, signer_fingerprint,
/// window_start, format, encoding)`. That tuple is identical across replicas and
/// never requires a sign to answer a `304`, and it changes exactly when the
/// served representation's identity changes (content, signing key, window,
/// format, or encoding). A matching weak ETag proves the client holds a
/// current-window token from the current signer for this content — which is the
/// guarantee the conditional logic needs to certify a `304`.
pub(crate) fn generate_token_etag(key: &TokenCacheKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.list_id.as_bytes());
    hasher.update(key.content_hash.as_bytes());
    hasher.update(key.signer_fingerprint.as_bytes());
    hasher.update(key.window_start.to_string().as_bytes());
    hasher.update(key.format.as_bytes());
    hasher.update(encoding_label(key.encoding).as_bytes());
    format!("W/\"{}\"", hex::encode(hasher.finalize()))
}

fn encoding_label(encoding: TokenEncoding) -> &'static str {
    match encoding {
        TokenEncoding::Identity => "identity",
        TokenEncoding::Gzip => "gzip",
    }
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

pub(crate) fn generate_historical_etag(
    snapshot: &StatusListSnapshot,
) -> Result<String, StatusListError> {
    let mut hasher = Sha256::new();
    let (bits, lst) = snapshot.status_list.token_lst()?;

    hasher.update(snapshot.snapshot_id.as_bytes());
    hasher.update(snapshot.iat.to_string().as_bytes());
    hasher.update(snapshot.exp.to_string().as_bytes());
    hasher.update(bits.to_string().as_bytes());
    hasher.update(lst.as_bytes());
    hasher.update(snapshot.issuer.0.as_bytes());

    let hash = hasher.finalize();
    Ok(format!("\"{}\"", hex::encode(hash)))
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

    fn base_key() -> TokenCacheKey {
        TokenCacheKey {
            list_id: "list".to_string(),
            content_hash: "hash".to_string(),
            signer_fingerprint: "signer".to_string(),
            window_start: 1000,
            format: "jwt".to_string(),
            encoding: TokenEncoding::Identity,
            aggregation_uri: String::new(),
            token_ttl_secs: 300,
            token_exp_secs: 900,
        }
    }

    #[test]
    fn test_generate_token_etag_is_weak() {
        let etag = generate_token_etag(&base_key());
        assert!(
            etag.starts_with("W/\""),
            "live ETag must be weak (W/\"...\"), not strong"
        );
        assert!(etag.ends_with('"'), "ETag should end with \"");
        let hex_part = &etag[3..etag.len() - 1];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_token_etag_determinism() {
        assert_eq!(
            generate_token_etag(&base_key()),
            generate_token_etag(&base_key())
        );
    }

    #[test]
    fn test_generate_token_etag_changes_with_each_identity_dimension() {
        let base = base_key();
        let cases = [
            (
                "list_id",
                TokenCacheKey {
                    list_id: "other".into(),
                    ..base.clone()
                },
            ),
            (
                "content_hash",
                TokenCacheKey {
                    content_hash: "other".into(),
                    ..base.clone()
                },
            ),
            (
                "signer_fingerprint",
                TokenCacheKey {
                    signer_fingerprint: "other".into(),
                    ..base.clone()
                },
            ),
            (
                "window_start",
                TokenCacheKey {
                    window_start: 1001,
                    ..base.clone()
                },
            ),
            (
                "format",
                TokenCacheKey {
                    format: "cwt".into(),
                    ..base.clone()
                },
            ),
            (
                "encoding",
                TokenCacheKey {
                    encoding: TokenEncoding::Gzip,
                    ..base.clone()
                },
            ),
        ];
        for (dim, key) in cases {
            assert_ne!(
                generate_token_etag(&base),
                generate_token_etag(&key),
                "ETag must change when {dim} changes"
            );
        }
        // Aggregate dimensions that are *not* representation identity must not
        // change the ETag (they don't alter the bytes served for this window).
        let same_identity = TokenCacheKey {
            aggregation_uri: "https://agg".into(),
            token_ttl_secs: 600,
            token_exp_secs: 1200,
            ..base.clone()
        };
        assert_eq!(
            generate_token_etag(&base),
            generate_token_etag(&same_identity),
            "ttl/exp/aggregation_uri are not representation identity"
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
