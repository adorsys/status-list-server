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
}
