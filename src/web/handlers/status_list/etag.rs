use crate::models::StatusListRecord;
use sha2::{Digest, Sha256};

/// Computes a weak ETag from the status list's content identity.
///
/// The ETag represents the content identity only (not time-based metadata) so
/// that the same list served across token-expiry validity buckets yields the
/// same validator. Per RFC 9110 §8.8.1, weak validators are appropriate here
/// because the served representation (a re-signed token) may differ byte-wise
/// while being semantically equivalent.
///
/// The ETag is computed from the concatenation of:
/// - bits (as string)
/// - lst (base64url-encoded compressed bitstring)
/// - issuer (string)
/// - sub (string)
///
/// Returns a weak ETag formatted as: W/"<sha256_hex>"
///
/// # Examples
///
/// ```
/// use status_list_server::models::{StatusList, StatusListRecord};
/// use status_list_server::web::handlers::status_list::etag::generate_etag;
///
/// let record = StatusListRecord {
///     list_id: "test-list".to_string(),
///     issuer: "https://issuer.example".to_string(),
///     status_list: StatusList {
///         bits: 1,
///         lst: "eNrbuRgAAhcBXQ".to_string(),
///     },
///     sub: "https://example.com/credentials/status/3".to_string(),
///     updated_at: 1234567890,
/// };
///
/// let etag = generate_etag(&record);
/// assert!(etag.starts_with("W/\""));
/// assert!(etag.ends_with('"'));
/// ```
pub fn generate_etag(record: &StatusListRecord) -> String {
    let mut hasher = Sha256::new();

    // Hash each component that defines the content identity
    hasher.update(record.status_list.bits.to_string().as_bytes());
    hasher.update(record.status_list.lst.as_bytes());
    hasher.update(record.issuer.as_bytes());
    hasher.update(record.sub.as_bytes());

    let hash = hasher.finalize();
    format!("W/\"{}\"", hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::StatusList;

    fn create_test_record() -> StatusListRecord {
        StatusListRecord {
            list_id: "test-list".to_string(),
            issuer: "https://issuer.example".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "eNrbuRgAAhcBXQ".to_string(),
            },
            sub: "https://example.com/credentials/status/3".to_string(),
            updated_at: 1234567890,
        }
    }

    #[test]
    fn test_generate_etag_format() {
        let record = create_test_record();
        let etag = generate_etag(&record);

        // Should start with W/" and end with "
        assert!(etag.starts_with("W/\""), "ETag should start with W/\"");
        assert!(etag.ends_with('"'), "ETag should end with \"");

        // Should be a hex string of appropriate length (SHA-256 is 64 hex chars)
        let hex_part = &etag[3..etag.len() - 1]; // Remove W/" and "
        assert_eq!(
            hex_part.len(),
            64,
            "SHA-256 hash should be 64 hex characters"
        );
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash should contain only hex digits"
        );
    }

    #[test]
    fn test_generate_etag_determinism() {
        let record = create_test_record();
        let etag1 = generate_etag(&record);
        let etag2 = generate_etag(&record);

        assert_eq!(etag1, etag2, "ETag should be deterministic");
    }

    #[test]
    fn test_generate_etag_bits_sensitivity() {
        let mut record = create_test_record();
        let original_etag = generate_etag(&record);

        // Change bits field
        record.status_list.bits = 2;
        let new_etag = generate_etag(&record);

        assert_ne!(
            original_etag, new_etag,
            "ETag should change when bits changes"
        );
    }

    #[test]
    fn test_generate_etag_lst_sensitivity() {
        let mut record = create_test_record();
        let original_etag = generate_etag(&record);

        // Change lst field
        record.status_list.lst = "different_lst".to_string();
        let new_etag = generate_etag(&record);

        assert_ne!(
            original_etag, new_etag,
            "ETag should change when lst changes"
        );
    }

    #[test]
    fn test_generate_etag_issuer_sensitivity() {
        let mut record = create_test_record();
        let original_etag = generate_etag(&record);

        // Change issuer field
        record.issuer = "https://different-issuer.example".to_string();
        let new_etag = generate_etag(&record);

        assert_ne!(
            original_etag, new_etag,
            "ETag should change when issuer changes"
        );
    }

    #[test]
    fn test_generate_etag_sub_sensitivity() {
        let mut record = create_test_record();
        let original_etag = generate_etag(&record);

        // Change sub field
        record.sub = "https://example.com/credentials/status/99".to_string();
        let new_etag = generate_etag(&record);

        assert_ne!(
            original_etag, new_etag,
            "ETag should change when sub changes"
        );
    }

    #[test]
    fn test_generate_etag_list_id_independence() {
        let record1 = create_test_record();
        let mut record2 = create_test_record();

        // Change only list_id (should not affect ETag)
        record2.list_id = "different-list-id".to_string();

        let etag1 = generate_etag(&record1);
        let etag2 = generate_etag(&record2);

        assert_eq!(etag1, etag2, "ETag should not depend on list_id");
    }

    #[test]
    fn test_generate_etag_updated_at_independence() {
        let record1 = create_test_record();
        let mut record2 = create_test_record();

        // Change only updated_at (should not affect ETag)
        record2.updated_at = 9999999999;

        let etag1 = generate_etag(&record1);
        let etag2 = generate_etag(&record2);

        assert_eq!(etag1, etag2, "ETag should not depend on updated_at");
    }

    #[test]
    fn test_generate_etag_empty_strings() {
        let record = StatusListRecord {
            list_id: "test".to_string(),
            issuer: "".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "".to_string(),
            },
            sub: "".to_string(),
            updated_at: 0,
        };

        let etag = generate_etag(&record);

        // Should still generate valid ETag format
        assert!(etag.starts_with("W/\""));
        assert!(etag.ends_with('"'));
    }

    #[test]
    fn test_generate_etag_special_characters() {
        let record = StatusListRecord {
            list_id: "test".to_string(),
            issuer: "https://issuer.example/with/special?chars=value&more=stuff".to_string(),
            status_list: StatusList {
                bits: 8,
                lst: "eNrbuRgAAhcBXQ==".to_string(),
            },
            sub: "https://example.com/credentials/status/3#fragment".to_string(),
            updated_at: 0,
        };

        let etag = generate_etag(&record);

        // Should handle special characters without issues
        assert!(etag.starts_with("W/\""));
        assert!(etag.ends_with('"'));
        let hex_part = &etag[3..etag.len() - 1];
        assert_eq!(hex_part.len(), 64);
    }

    #[test]
    fn test_generate_etag_content_only_stability() {
        let record = create_test_record();
        let etag = generate_etag(&record);

        // The ETag should be purely content-based — calling it again yields the
        // same value. This replaces the old validity_bucket sensitivity test:
        // the same content must produce the same ETag regardless of any token
        // expiry rotation.
        let etag2 = generate_etag(&record);
        assert_eq!(
            etag, etag2,
            "ETag must be stable for identical content"
        );
    }
}
