use base64url::encode;
use flate2::{write::ZlibEncoder, Compression};
use serde::{Deserialize, Serialize};
use std::io::Write;

use crate::model::Status;

use super::{bits_validation::BitFlag, errors::Error};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PublishStatus {
    pub index: i32,
    pub status: Status,
}

pub fn lst_from(status_updates: Vec<PublishStatus>, bits: BitFlag) -> Result<String, Error> {
    if status_updates.is_empty() {
        return Err(Error::Generic("No status updates provided".to_string()));
    }

    let bits = bits.value() as usize;
    // Determine the highest index to set the size of the status array
    let max_index = status_updates
        .iter()
        .map(|update| update.index)
        .max()
        .ok_or_else(|| Error::Generic("Failed to determine max index".to_string()))?;

    if max_index < 0 {
        return Err(Error::InvalidIndex);
    }

    let total_entries = (max_index as usize) + 1;
    let total_bits = total_entries * bits;
    let bytes_needed = (total_bits + 7) / 8;
    let mut status_array = vec![0u8; bytes_needed];

    for update in status_updates {
        if update.index < 0 {
            return Err(Error::InvalidIndex);
        }
        let idx = update.index as usize;
        let bit_position = idx * bits;
        let byte_index = bit_position / 8;
        let bit_offset = bit_position % 8;

        let status_value = match update.status {
            Status::VALID => 0b0000_0000,
            Status::INVALID => 0b0000_0001,
            Status::SUSPENDED => 0b0000_0010,
            Status::APPLICATIONSPECIFIC => 0b0000_0011,
        };

        if bits == 8 {
            status_array[byte_index] = status_value;
        } else {
            let mask = ((1 << bits) - 1) << bit_offset;
            status_array[byte_index] &= !mask;
            status_array[byte_index] |= (status_value << bit_offset) & mask;

            if bit_offset + bits > 8 {
                let next_byte_index = byte_index + 1;
                let next_bit_offset = 8 - bit_offset;
                let next_mask = (1 << (bits - next_bit_offset)) - 1;
                status_array[next_byte_index] &= !next_mask;
                status_array[next_byte_index] |= status_value >> next_bit_offset;
            }
        }
    }

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&status_array)
        .map_err(|_| Error::Generic("Failed to compress status list".to_string()))?;
    let compressed = encoder
        .finish()
        .map_err(|_| Error::Generic("Failed to finish compression".to_string()))?;

    Ok(encode(&compressed))
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn test_lst_from_valid_status_1_bit() {
        let updates = vec![
            PublishStatus {
                index: 0,
                status: Status::VALID,
            },
            PublishStatus {
                index: 1,
                status: Status::INVALID,
            },
        ];
        let bits = BitFlag::new(1).ok_or(Error::UnsupportedBits).unwrap();

        let result = lst_from(updates, bits).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b0000_0010]);
    }

    #[test]
    fn test_lst_from_invalid_status_1_bit() {
        let updates = vec![
            PublishStatus {
                index: 0,
                status: Status::INVALID,
            },
            PublishStatus {
                index: 1,
                status: Status::INVALID,
            },
        ];
        let bits = BitFlag::new(1).ok_or(Error::UnsupportedBits).unwrap();
        let result = lst_from(updates, bits).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b0000_0011]);
    }

    #[test]
    fn test_lst_from_mixed_status_2_bits() {
        let updates = vec![
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
        ];

        let bits = BitFlag::new(2).ok_or(Error::UnsupportedBits).unwrap();
        let result = lst_from(updates, bits).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b1110_0100]);
    }

    #[test]
    fn test_lst_from_empty_updates() {
        let updates = vec![];
        let bits = BitFlag::new(1).ok_or(Error::UnsupportedBits).unwrap();
        let result = lst_from(updates, bits);
        assert!(matches!(result, Err(Error::Generic(_))));
    }

    #[test]
    fn test_lst_from_invalid_index() {
        let updates = vec![PublishStatus {
            index: -1,
            status: Status::VALID,
        }];
        let bits = BitFlag::new(1).ok_or(Error::UnsupportedBits).unwrap();
        let result = lst_from(updates, bits);
        assert!(matches!(result, Err(Error::InvalidIndex)));
    }
}
