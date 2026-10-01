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
/// window_start, format, encoding, aggregation_uri, token_ttl_secs,
/// token_exp_secs)`. It is identical across replicas, never requires a sign to
/// answer a `304`, and changes exactly when the served representation's identity
/// changes (content, signing key, window, format, encoding, aggregation URI, or
/// token ttl/exp). A matching weak ETag proves the client holds a current-window
/// token from the current signer for this content — the guarantee the
/// conditional logic needs to certify a `304`.
pub(crate) fn generate_token_etag(key: &TokenCacheKey) -> String {
    let mut hasher = Sha256::new();
    // Canonical encoding: strings are length-prefixed and integers are
    // fixed-width, so a raw concatenation can never collide across distinct
    // keys (e.g. aggregation_uri="https://a/1", ttl=2, exp=34 vs
    // aggregation_uri="https://a/", ttl=12, exp=34).
    write_len_prefixed(&mut hasher, key.list_id.as_bytes());
    write_len_prefixed(&mut hasher, key.content_hash.as_bytes());
    write_len_prefixed(&mut hasher, key.signer_fingerprint.as_bytes());
    hasher.update(key.window_start.to_be_bytes());
    write_len_prefixed(&mut hasher, key.format.as_bytes());
    write_len_prefixed(&mut hasher, encoding_label(key.encoding).as_bytes());
    write_len_prefixed(&mut hasher, key.aggregation_uri.as_bytes());
    hasher.update(key.token_ttl_secs.to_be_bytes());
    hasher.update(key.token_exp_secs.to_be_bytes());
    format!("W/\"{}\"", hex::encode(hasher.finalize()))
}

/// Update the hasher with `bytes` prefixed by their `u64` length, making a
/// sequence of variable-length fields unambiguous.
fn write_len_prefixed(hasher: &mut impl Digest, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
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

/// Weak ETag for the historical representation, derived from the *snapshot
/// identity* plus the format and encoding the token was served in.
///
/// Historical tokens are signed fresh on every request, so ES256 randomized
/// signatures make the served bytes differ between requests for the very same
/// snapshot. A strong ETag (RFC 9110 §8.8.3.1 requires it to change whenever
/// the bytes change) would therefore be wrong and would let a byte-different
/// response claim a cached validator. This is deliberately a **weak** validator
/// (`W/"..."`) over the snapshot fields that pin the identity of the replayed
/// state, together with `format` and `encoding`, so JWT vs CWT and gzip vs
/// identity responses (which carry distinct bytes) never share a validator.
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
            (
                "aggregation_uri",
                TokenCacheKey {
                    aggregation_uri: "https://agg".into(),
                    ..base.clone()
                },
            ),
            (
                "token_ttl_secs",
                TokenCacheKey {
                    token_ttl_secs: 600,
                    ..base.clone()
                },
            ),
            (
                "token_exp_secs",
                TokenCacheKey {
                    token_exp_secs: 1200,
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

    #[test]
    fn test_generate_token_etag_canonical_encoding_no_field_boundary_collision() {
        // The ETag must hash a canonical (length-prefixed) encoding of the key,
        // not a raw concatenation. With raw concatenation these two distinct
        // keys feed identical bytes into SHA-256:
        //   aggregation_uri="https://a/1", ttl=2,  exp=34
        //   aggregation_uri="https://a/",  ttl=12, exp=34
        // The canonical encoding must keep them distinct so an ETag never
        // survives a configuration change and certifies a stale token.
        let a = TokenCacheKey {
            aggregation_uri: "https://a/1".to_string(),
            token_ttl_secs: 2,
            ..base_key()
        };
        let b = TokenCacheKey {
            aggregation_uri: "https://a/".to_string(),
            token_ttl_secs: 12,
            ..base_key()
        };
        assert_eq!(a.token_exp_secs, b.token_exp_secs, "same exp=34");
        assert_ne!(
            generate_token_etag(&a),
            generate_token_etag(&b),
            "canonical encoding must not collide across variable-length field \
             boundaries"
        );
    }

    fn base_snapshot() -> StatusListSnapshot {
        StatusListSnapshot {
            snapshot_id: "snap-1".to_string(),
            list_id: "list".to_string(),
            issuer: Issuer("https://issuer.example".to_string()),
            status_list: StatusList {
                bits: 1,
                lst: "eNrbuRgAAhcBXQ".to_string(),
            },
            sub: "https://example.com/credentials/status/3".to_string(),
            iat: 1000,
            exp: 1900,
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
        // The same snapshot served as JWT vs CWT, or gzip vs identity, carries
        // distinct bytes, so those representations must not share a validator.
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
