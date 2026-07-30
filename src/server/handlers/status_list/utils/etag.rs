use crate::domain::models::status_list::{StatusListRecord, StatusListSnapshot};
use sha2::{Digest, Sha256};

pub(crate) fn generate_etag(record: &StatusListRecord) -> String {
    let mut hasher = Sha256::new();

    hasher.update(record.status_list.bits.to_string().as_bytes());
    hasher.update(record.status_list.lst.as_bytes());
    hasher.update(record.issuer.0.as_bytes());
    hasher.update(record.sub.as_bytes());

    let hash = hasher.finalize();
    format!("W/\"{}\"", hex::encode(hash))
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
    fn test_generate_etag_format() {
        let record = create_test_record();
        let etag = generate_etag(&record);

        assert!(etag.starts_with("W/\""), "ETag should start with W/\"");
        assert!(etag.ends_with('"'), "ETag should end with \"");

        let hex_part = &etag[3..etag.len() - 1];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_etag_determinism() {
        let record1 = create_test_record();
        let record2 = create_test_record();

        let etag1 = generate_etag(&record1);
        let etag2 = generate_etag(&record2);

        assert_eq!(etag1, etag2);
    }

    #[test]
    fn test_generate_etag_content_only_stability() {
        let record1 = create_test_record();
        let record2 = create_test_record();

        assert_eq!(generate_etag(&record1), generate_etag(&record2));
    }

    #[test]
    fn test_generate_etag_updated_at_independence() {
        let mut record1 = create_test_record();
        let mut record2 = create_test_record();
        record1.updated_at = 1000;
        record2.updated_at = 2000;

        assert_eq!(generate_etag(&record1), generate_etag(&record2));
    }

    #[test]
    fn test_generate_etag_bits_sensitivity() {
        let mut record1 = create_test_record();
        let mut record2 = create_test_record();
        record1.status_list.bits = 1;
        record2.status_list.bits = 2;

        assert_ne!(generate_etag(&record1), generate_etag(&record2));
    }

    #[test]
    fn test_generate_etag_lst_sensitivity() {
        let mut record1 = create_test_record();
        let mut record2 = create_test_record();
        record1.status_list.lst = "lst1".to_string();
        record2.status_list.lst = "lst2".to_string();

        assert_ne!(generate_etag(&record1), generate_etag(&record2));
    }

    #[test]
    fn test_generate_etag_issuer_sensitivity() {
        let mut record1 = create_test_record();
        let mut record2 = create_test_record();
        record1.issuer = Issuer("https://issuer1.com".to_string());
        record2.issuer = Issuer("https://issuer2.com".to_string());

        assert_ne!(generate_etag(&record1), generate_etag(&record2));
    }

    #[test]
    fn test_generate_etag_sub_sensitivity() {
        let mut record1 = create_test_record();
        let mut record2 = create_test_record();
        record1.sub = "https://example.com/1".to_string();
        record2.sub = "https://example.com/2".to_string();

        assert_ne!(generate_etag(&record1), generate_etag(&record2));
    }
}
