use base64url;
use flate2::{write::ZlibEncoder, Compression};
use std::io::Write;

use crate::model::Status;

use super::errors::Error;

pub struct PublishStatus {
    pub index: i32,
    pub status: Status,
}

pub fn lst_from(status_updates: Vec<PublishStatus>) -> Result<String, Error> {
    if status_updates.is_empty() {
        return Err(Error::Generic("No status updates provided".to_string()));
    }

    // Find the highest index to determine the array size
    let max_index = status_updates
        .iter()
        .map(|update| update.index)
        .max()
        .ok_or_else(|| Error::Generic("Failed to determine max index".to_string()))?;

    if max_index < 0 {
        return Err(Error::InvalidIndex);
    }

    let total_entries = (max_index as usize) + 1;
    let mut status_array = vec![0u8; total_entries];
    // Apply each status update
    for update in status_updates {
        if update.index < 0 {
            return Err(Error::InvalidIndex);
        }
        let idx = update.index as usize;

        status_array[idx] = match update.status {
            Status::VALID => 0x00,               // VALID = 0
            Status::INVALID => 0x01,             // INVALID = 1
            Status::SUSPENDED => 0x02,           // SUSPENDED = 2
            Status::APPLICATIONSPECIFIC => 0x03, // APPLICATIONSPECIFIC = 3
        };
    }

    // Compress with zlib
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&status_array)
        .map_err(|_| Error::Generic("Failed to compress status list".to_string()))?;
    let compressed = encoder
        .finish()
        .map_err(|_| Error::Generic("Failed to finish compression".to_string()))?;

    // Base64url encode (no padding)
    Ok(base64url::encode(compressed))
}

#[cfg(test)]
mod test {
    use std::io::Read;

    use flate2::read::ZlibDecoder;

    use crate::model::Status;

    use super::{lst_from, PublishStatus};

    #[test]
    fn test_lst_from() {
        let status_updates = vec![
            PublishStatus {
                index: 0,
                status: Status::VALID,
            },
            PublishStatus {
                index: 1,
                status: Status::INVALID,
            },
            PublishStatus {
                index: 2,
                status: Status::SUSPENDED,
            },
            PublishStatus {
                index: 3,
                status: Status::APPLICATIONSPECIFIC,
            },
            PublishStatus {
                index: 10,
                status: Status::INVALID,
            },
        ];

        let encoded_lst = lst_from(status_updates).expect("Failed to create LST");

        // Decode Base64 URL
        let decoded_lst = base64url::decode(&encoded_lst).expect("Failed to decode Base64");

        // Decompress Zlib
        let mut decoder = ZlibDecoder::new(&decoded_lst[..]);
        let mut decompressed_lst = Vec::new();
        decoder
            .read_to_end(&mut decompressed_lst)
            .expect("Failed to decompress LST");

        // Expected bytes (indexes 0,1,2,3,10 modified)
        let mut expected_lst = vec![0x00; 11];
        expected_lst[1] = 0x01; // INVALID = 1
        expected_lst[2] = 0x02; // SUSPENDED = 2
        expected_lst[3] = 0x03; // APPLICATIONSPECIFIC = 3
        expected_lst[10] = 0x01; // INVALID = 1

        assert_eq!(
            decompressed_lst, expected_lst,
            "Decompressed LST does not match expected bytes"
        );
    }
}
