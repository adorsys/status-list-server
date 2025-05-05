use base64url::{decode, encode};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use std::io::{Read, Write};

use crate::model::{Status, StatusEntry};

use super::{bits_validation::BitFlag, errors::Error};

pub fn create_status_list(
    status_updates: Vec<StatusEntry>,
    bits: BitFlag,
) -> Result<String, Error> {
    if status_updates.is_empty() {
        return Err(Error::Generic("No status updates provided".to_string()));
    }

    let bits = bits.value() as usize;

    let max_index = status_updates
        .iter()
        .map(|update| update.index)
        .max()
        .ok_or_else(|| Error::Generic("Failed to determine max index".to_string()))?;

    if max_index < 0 {
        return Err(Error::InvalidIndex);
    }

    let required_len = (max_index as usize + 1) * bits + 7;
    let len = required_len / 8;
    let mut status_array = vec![0u8; len];

    apply_updates(&mut status_array, &status_updates, bits)?;

    encode_compressed(&status_array)
}

pub fn update_status_list(
    existing_lst: String,
    status_updates: Vec<StatusEntry>,
    bits: BitFlag,
) -> Result<String, Error> {
    if status_updates.is_empty() {
        return Err(Error::Generic("No status updates provided".to_string()));
    }

    let bits = bits.value() as usize;

    let compressed_data = decode(&existing_lst).map_err(|_| Error::DecodeError)?;
    let mut decoder = ZlibDecoder::new(&compressed_data[..]);
    let mut status_array = Vec::new();
    decoder
        .read_to_end(&mut status_array)
        .map_err(|e| Error::Generic(e.to_string()))?;

    // Resize if necessary
    if let Some(max_update_index) = status_updates.iter().map(|u| u.index).max() {
        let required_len = (max_update_index as usize + 1) * bits + 7;
        let len = required_len / 8;
        if status_array.len() < len {
            status_array.resize(len, 0);
        }
    }

    apply_updates(&mut status_array, &status_updates, bits)?;

    encode_compressed(&status_array)
}

fn apply_updates(
    status_array: &mut [u8],
    status_updates: &[StatusEntry],
    bits: usize,
) -> Result<(), Error> {
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
        }
    }

    Ok(())
}

pub fn encode_compressed(status_array: &[u8]) -> Result<String, Error> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(status_array)
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
    fn test_lst_with_bits_1() {
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

        let result = create_status_list(updates, bits).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b0000_0010]);
    }

    #[test]
    fn test_lst_update_with_bits_1_as_spec() {
        let existing_byte_array = [0xb9, 0xa3];
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
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&existing_byte_array).unwrap();

        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        assert_eq!(existing_lst, "eNrbuRgAAhcBXQ");

        let result = update_status_list(existing_lst, updates, bits).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0xba, 0xa3]);
    }

    #[test]
    fn test_lst_from_with_bits_2() {
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

        let result = create_status_list(updates, bits).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b1110_0100]);
    }

    #[test]
    fn test_lst_update_with_bits_2() {
        let original_status_array = vec![0b11001001, 0b01000100, 0b11111001];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        // Step 2: Define new status updates
        let status_updates = vec![StatusEntry {
            index: 4,
            status: Status::INVALID,
        }];
        let bits = BitFlag::new(2).ok_or(Error::UnsupportedBits).unwrap();

        let updated_lst = update_status_list(existing_lst, status_updates, bits)
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

    #[test]
    fn test_lst_from_with_bits_set_to_2_specs() {
        let original_status_array = vec![0xc9, 0x44, 0xf9];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        assert_eq!(existing_lst, "eNo76fITAAPfAgc");

        let status_updates = vec![StatusEntry {
            index: 0,
            status: Status::INVALID,
        }];

        let bits = BitFlag::new(2).ok_or(Error::UnsupportedBits).unwrap();
        let updated_lst = update_status_list(existing_lst, status_updates, bits)
            .expect("Failed to update status list");

        assert_eq!(updated_lst, "eNo76fITAAPfAgc");
    }

    #[test]
    fn test_lst_update_with_bits_4() {
        let original_status_array = vec![0b11001001, 0b01000100, 0b11111001];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        // Step 2: Define new status updates
        let status_updates = vec![StatusEntry {
            index: 4,
            status: Status::VALID,
        }];
        let bits = BitFlag::new(4).ok_or(Error::UnsupportedBits).unwrap();

        let updated_lst = update_status_list(existing_lst, status_updates, bits)
            .expect("Failed to update status list");

        let decoded = decode(&updated_lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        let expected_status_array = vec![0b11001001, 0b01000100, 0b11110000];
        assert_eq!(
            updated_status_array, expected_status_array,
            "The status array was not updated correctly"
        );
    }

    #[test]
    fn test_lst_update_with_bits_8() {
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

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
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
        let updated_lst = update_status_list(existing_lst, status_updates, bits)
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
    fn test_lst_from_empty_updates() {
        let updates = vec![];
        let bits = BitFlag::new(1).ok_or(Error::UnsupportedBits).unwrap();
        let result = create_status_list(updates, bits);
        assert!(matches!(result, Err(Error::Generic(_))));
    }

    #[test]
    fn test_lst_from_invalid_index() {
        let updates = vec![StatusEntry {
            index: -1,
            status: Status::VALID,
        }];
        let bits = BitFlag::new(1).ok_or(Error::UnsupportedBits).unwrap();

        let result = create_status_list(updates, bits);
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

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
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
        let updated_lst = update_status_list(existing_lst, status_updates, bits)
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
}
