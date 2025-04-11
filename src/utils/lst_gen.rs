use base64url::{decode, encode};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use std::io::{Read, Write};

use crate::model::{Status, StatusEntry};

use super::{bits_validation::BitFlag, errors::Error};

pub fn update_or_create_status_list(
    existing_lst: Option<String>,
    status_updates: Vec<StatusEntry>,
    bits: BitFlag,
) -> Result<String, Error> {
    if status_updates.is_empty() {
        return Err(Error::Generic("No status updates provided".to_string()));
    }

    let bits = bits.value() as usize;

    let mut status_array: Vec<u8> = if let Some(existing_lst) = existing_lst {
        // Decode & decompress existing list
        let compressed_data = decode(&existing_lst).map_err(|_| Error::DecodeError)?;
        let mut decoder = ZlibDecoder::new(&compressed_data[..]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| Error::Generic(e.to_string()))?;
        decompressed
    } else {
        // Determine the highest index to set the size of the status array
        let max_index = status_updates
            .iter()
            .map(|update| update.index)
            .max()
            .ok_or_else(|| Error::Generic("Failed to determine max index".to_string()))?;

        if max_index < 0 {
            return Err(Error::InvalidIndex);
        }

        // Create a new list initialized to VALID
        let required_len = (max_index as usize + 1) * bits + 7;
        let len = required_len / 8;
        vec![0u8; len]
    };

    // Ensure the array is large enough to apply all updates
    if let Some(max_update_index) = status_updates.iter().map(|u| u.index).max() {
        let required_len = (max_update_index as usize + 1) * bits + 7;
        let len = required_len / 8;
        if status_array.len() < len {
            status_array.resize(len, 0);
        }
    }
    for update in status_updates {
        if update.index < 0 {
            return Err(Error::InvalidIndex);
        }

        let idx = update.index as usize;
        let bit_position = idx * bits;
        let byte_index = bit_position / 8;
        // Determine the offset within that byte
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
            // Create a mask to isolate the target bit segment within the byte
            let mask = ((1 << bits) - 1) << bit_offset;

            // Clear the bits at the target location using bitwise AND with the inverted mask
            status_array[byte_index] &= !mask;

            // Shift the status value into the correct position, then set the bits using bitwise OR
            status_array[byte_index] |= (status_value << bit_offset) & mask;
        }
    }

    // Compress and encode
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(&status_array)
        .map_err(|e| Error::Generic(e.to_string()))?;
    let compressed = encoder
        .finish()
        .map_err(|e| Error::Generic(e.to_string()))?;

    Ok(encode(&compressed))
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn test_lst_from_valid_status_1_bit() {
        let updates = vec![
            StatusEntry {
                index: 0,
                status: Status::VALID,
            },
            StatusEntry {
                index: 1,
                status: Status::INVALID,
            },
        ];
        let bits = BitFlag::new(1).ok_or(Error::UnsupportedBits).unwrap();

        let result = update_or_create_status_list(None, updates, bits).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b0000_0010]);
    }

    #[test]
    fn test_lst_from_invalid_status_1_bit() {
        let updates = vec![
            StatusEntry {
                index: 0,
                status: Status::INVALID,
            },
            StatusEntry {
                index: 1,
                status: Status::INVALID,
            },
        ];
        let bits = BitFlag::new(1).ok_or(Error::UnsupportedBits).unwrap();
        let result = update_or_create_status_list(None, updates, bits).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b0000_0011]);
    }

    #[test]
    fn test_lst_from_mixed_status_2_bits() {
        let updates = vec![
            StatusEntry {
                index: 0,
                status: Status::VALID,
            },
            StatusEntry {
                index: 1,
                status: Status::INVALID,
            },
            StatusEntry {
                index: 2,
                status: Status::SUSPENDED,
            },
            StatusEntry {
                index: 3,
                status: Status::APPLICATIONSPECIFIC,
            },
        ];
        let bits = BitFlag::new(2).ok_or(Error::UnsupportedBits).unwrap();

        let result = update_or_create_status_list(None, updates, bits).unwrap();
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
        let result = update_or_create_status_list(None, updates, bits);
        assert!(matches!(result, Err(Error::Generic(_))));
    }

    #[test]
    fn test_lst_from_invalid_index() {
        let updates = vec![StatusEntry {
            index: -1,
            status: Status::VALID,
        }];
        let bits = BitFlag::new(1).ok_or(Error::UnsupportedBits).unwrap();

        let result = update_or_create_status_list(None, updates, bits);
        assert!(matches!(result, Err(Error::InvalidIndex)));
    }

    #[test]
    fn test_lst_from_unsupported_bits() {
        let _updates = [StatusEntry {
            index: 0,
            status: Status::VALID,
        }];
        let bits = BitFlag::new(3).ok_or(Error::UnsupportedBits);
        assert!(bits.is_err());
    }
    #[test]
    fn test_status_update() {
        let original_status_array = vec![
            0b0000_0000,
            0b0000_0001,
            0b0000_0010,
            0b0000_0011,
            0b0000_0000,
            0b0000_0000,
            0b0000_0000,
            0b0000_0000,
        ];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        // Step 2: Define new status updates
        let status_updates = vec![
            StatusEntry {
                index: 6,
                status: Status::INVALID,
            },
            StatusEntry {
                index: 3,
                status: Status::SUSPENDED,
            },
        ];
        let bits = BitFlag::new(8).ok_or(Error::UnsupportedBits).unwrap();
        let updated_lst = update_or_create_status_list(Some(existing_lst), status_updates, bits)
            .expect("Failed to update status list");

        let decoded = decode(&updated_lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        let expected_status_array = vec![
            0b0000_0000,
            0b0000_0001,
            0b0000_0010,
            0b0000_0010,
            0b0000_0000,
            0b0000_0000,
            0b0000_0001,
            0b0000_0000,
        ];
        assert_eq!(
            updated_status_array, expected_status_array,
            "The status array was not updated correctly"
        );
    }

    #[test]
    fn test_status_update_with_max_index() {
        let original_status_array = vec![
            0b0000_0000,
            0b0000_0001,
            0b0000_0010,
            0b0000_0011,
            0b0000_0000,
            0b0000_0000,
            0b0000_0000,
            0b0000_0000,
        ];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        // Step 2: Define new status updates
        let status_updates = vec![
            StatusEntry {
                index: 7,
                status: Status::INVALID,
            },
            StatusEntry {
                index: 3,
                status: Status::SUSPENDED,
            },
        ];
        let bits = BitFlag::new(8).ok_or(Error::UnsupportedBits).unwrap();
        let updated_lst = update_or_create_status_list(Some(existing_lst), status_updates, bits)
            .expect("Failed to update status list");

        let decoded = decode(&updated_lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        let expected_status_array = vec![
            0b0000_0000,
            0b0000_0001,
            0b0000_0010,
            0b0000_0010,
            0b0000_0000,
            0b0000_0000,
            0b0000_0000,
            0b0000_0001,
        ];
        assert_eq!(
            updated_status_array, expected_status_array,
            "The status array was not updated correctly"
        );
    }

    #[test]
    fn test_update_status_with_bits_set_to_2() {
        let original_status_array = vec![0b11001001, 0b01000100, 0b11111001];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        // Step 2: Define new status updates
        let status_updates = vec![StatusEntry {
            index: 4,
            status: Status::INVALID,
        }];
        let bits = BitFlag::new(2).ok_or(Error::UnsupportedBits).unwrap();

        let updated_lst = update_or_create_status_list(Some(existing_lst), status_updates, bits)
            .expect("Failed to update status list");

        let decoded = decode(&updated_lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        let expected_status_array = vec![0b11001001, 0b01000101, 0b11111001];
        assert_eq!(
            updated_status_array, expected_status_array,
            "The status array was not updated correctly"
        );
    }
}
