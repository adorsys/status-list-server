use base64url::{decode, encode};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use std::io::{Read, Write};

use crate::model::{Status, StatusEntry};

use super::errors::Error;

// Helper function to determine the appropriate bits
fn determine_bits(
    status_updates: &[StatusEntry],
    original_bits: Option<usize>,
) -> Result<usize, Error> {
    let max_status_value = status_updates
        .iter()
        .map(|entry| match entry.status {
            Status::VALID => 0,
            Status::INVALID => 1,
            Status::SUSPENDED => 2,
            Status::APPLICATIONSPECIFIC => 3,
        })
        .max()
        .ok_or_else(|| Error::Generic("Failed to determine max status value".to_string()))?;

    let max_status_value = match max_status_value {
        0 | 1 => 1,
        2 | 3 => 2,
        4..=15 => 4,
        16..=255 => 8,
        _ => return Err(Error::Generic("Status value too large".to_string())),
    };

    // If original_bits is provided (for updates), use the maximum
    Ok(original_bits.unwrap_or_default().max(max_status_value))
}

// Helper function to calculate the required status array size
fn calculate_array_size(status_updates: &[StatusEntry], bits: usize) -> Result<usize, Error> {
    let max_index = status_updates
        .iter()
        .map(|update| update.index)
        .max()
        .ok_or_else(|| Error::Generic("Failed to determine max index".to_string()))?;

    if max_index < 0 {
        return Err(Error::InvalidIndex);
    }

    let required_len = (max_index as usize + 1) * bits + 7;
    Ok(required_len / 8)
}

// Helper function to apply updates and encode the result
fn apply_and_encode(
    status_array: &mut Vec<u8>,
    status_updates: &[StatusEntry],
    bits: usize,
) -> Result<String, Error> {
    apply_updates(status_array, status_updates, bits)?;
    encode_compressed(status_array)
}

pub fn create_status_list(status_updates: Vec<StatusEntry>) -> Result<String, Error> {
    if status_updates.is_empty() {
        return encode_compressed(&vec![]);
    }

    let bits = determine_bits(&status_updates, None)?;
    let len = calculate_array_size(&status_updates, bits)?;

    let mut status_array = vec![0u8; len];
    apply_and_encode(&mut status_array, &status_updates, bits)
}

// Helper function to decode status array into Status structs
fn decode_status_array(array: &[u8], bits: usize) -> Result<Vec<Status>, Error> {
    let mut statuses = Vec::new();
    for i in 0..(array.len() * 8 / bits) {
        let byte_index = (i * bits) / 8;
        let bit_offset = (i * bits) % 8;
        let status_value = if bits == 8 {
            array[i]
        } else {
            let mut value = 0;
            for j in 0..bits {
                if byte_index < array.len() && bit_offset + j < 8 {
                    value |= ((array[byte_index] >> (bit_offset + j)) & 1) << j;
                }
            }
            value as u8
        };
        statuses.push(match status_value {
            0 => Status::VALID,
            1 => Status::INVALID,
            2 => Status::SUSPENDED,
            3 => Status::APPLICATIONSPECIFIC,
            _ => {
                return Err(Error::Generic(
                    "Invalid status value in existing list".to_string(),
                ))
            }
        });
    }
    Ok(statuses)
}
// Helper function to re-encode the entire status array with a new bits value
fn reencode_status_array(
    old_array: &[u8],
    old_bits: usize,
    status_updates: &[StatusEntry],
) -> Result<String, Error> {
    let decoded_statuses = decode_status_array(old_array, old_bits)?;
    let mut full_statuses: Vec<StatusEntry> = decoded_statuses
        .into_iter()
        .enumerate()
        .map(|(i, status)| StatusEntry {
            index: i as i32,
            status,
        })
        .collect();

    // Apply updates
    for update in status_updates {
        if let Some(entry) = full_statuses.iter_mut().find(|e| e.index == update.index) {
            entry.status = update.status.clone();
        } else {
            full_statuses.push(update.clone());
        }
    }

    // Create new status list with updated bits
    create_status_list(full_statuses)
}

pub fn update_status_list(
    existing_lst: String,
    status_updates: Vec<StatusEntry>,
    current_bits: u8,
) -> Result<String, Error> {
    if status_updates.is_empty() {
        return Ok(existing_lst); // Return unchanged list
    }

    let original_bits = current_bits as usize;
    let new_bits = determine_bits(&status_updates, Some(original_bits))?;

    // Decode the existing list
    let compressed_data = decode(&existing_lst).map_err(|_| Error::DecodeError)?;
    let mut decoder = ZlibDecoder::new(&compressed_data[..]);
    let mut status_array = Vec::new();
    decoder
        .read_to_end(&mut status_array)
        .map_err(|e| Error::Generic(e.to_string()))?;

    // If new_bits > original_bits, re-encode entire list
    if new_bits > original_bits {
        return reencode_status_array(&status_array, original_bits, &status_updates);
    }

    // Proceed with in-place update using original_bits
    // Resize if necessary
    let required_len = calculate_array_size(&status_updates, original_bits)?;
    if status_array.len() < required_len {
        status_array.resize(required_len, 0);
    }

    apply_and_encode(&mut status_array, &status_updates, original_bits)
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
            // Create a mask to isolate the target bit segment within the byte
            let mask = ((1 << bits) - 1) << bit_offset;
            // Clear the bits at the target location using bitwise AND with the inverted mask
            status_array[byte_index] &= !mask;
            // Shift the status value into the correct position, then set the bits using bitwise OR
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
    use flate2::read::ZlibDecoder;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Read;

    use super::*;

    #[test]
    fn test_create_lst_with_1_bit_statuses() {
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

        let result = create_status_list(updates).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b00000010]); // INVALID (1) at index 1, VALID (0) at index 0
    }

    #[test]
    fn test_update_lst_with_1_bit_statuses() {
        let existing_byte_array = vec![0xb9, 0xa3];
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

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&existing_byte_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        assert_eq!(existing_lst, "eNrbuRgAAhcBXQ");

        let result = update_status_list(existing_lst, updates, 1).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0xba, 0xa3]);
    }

    #[test]
    fn test_create_lst_with_2_bit_statuses() {
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

        let result = create_status_list(updates).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        // SUSPENDED (2) and APPLICATIONSPECIFIC (3) require 2 bits
        // VALID (00), INVALID (01), SUSPENDED (10), APPLICATIONSPECIFIC (11) in 1 byte
        assert_eq!(decompressed, vec![0b11100100]); // 11_10_01_00
    }

    #[test]
    fn test_update_lst_with_2_bit_statuses() {
        let original_status_array = vec![0b11001001, 0b01000100, 0b11111001];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        let status_updates = vec![StatusEntry {
            index: 4,
            status: Status::INVALID,
        }];

        let updated_lst = update_status_list(existing_lst, status_updates, 2).unwrap();
        let decoded = decode(&updated_lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        // INVALID (1) requires 1 bit, but existing array likely uses 2 bits
        // Update index 4 (byte 1, bits 0-1) to INVALID (01)
        let expected_status_array = vec![0b11001001, 0b01000101, 0b11111001];
        assert_eq!(
            updated_status_array, expected_status_array,
            "The status array was not updated correctly"
        );
    }

    #[test]
    fn test_update_lst_with_2_bit_statuses_no_change() {
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

        let updated_lst = update_status_list(existing_lst, status_updates, 2).unwrap();
        let decoded = decode(&updated_lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        // INVALID (1) requires 1 bit, but existing array uses 2 bits
        // Update index 0 to INVALID (01), which may not change the array if already set
        assert_eq!(updated_status_array, vec![0xc9, 0x44, 0xf9]);
    }

    #[test]
    fn test_create_lst_empty_updates() {      
        let updates = vec![];

        let result = create_status_list(updates).unwrap();
        let decoded = base64url::decode(&result).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        
        // Empty updates should produce an empty decompressed array
        assert_eq!(decompressed, Vec::<u8>::new());
    }

    #[test]
    fn test_update_lst_empty_updates() {
        let original_status_array = vec![0b11001001, 0b01000100, 0b11111001];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        let status_updates = vec![];

        let updated_lst = update_status_list(existing_lst.clone(), status_updates, 1).unwrap();
        assert_eq!(updated_lst, existing_lst); // Unchanged input list
    }

    #[test]
    fn test_create_lst_invalid_index() {
        let updates = vec![StatusEntry {
            index: -1,
            status: Status::VALID,
        }];

        let result = create_status_list(updates);
        assert!(matches!(result, Err(Error::InvalidIndex)));
    }

    #[test]
    fn test_update_lst_invalid_index() {
        let original_status_array = vec![0b11001001, 0b01000100, 0b11111001];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        let status_updates = vec![StatusEntry {
            index: -1,
            status: Status::INVALID,
        }];

        let result = update_status_list(existing_lst, status_updates, 1);
        assert!(matches!(result, Err(Error::InvalidIndex)));
    }

    #[test]
    fn test_update_lst_with_max_index_2_bit_statuses() {
        let original_status_array = vec![
            0b00001100, // VALID (00), INVALID (01)
            0b00101100, // SUSPENDED (10), APPLICATIONSPECIFIC (11)
        ];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        let status_updates = vec![
            StatusEntry {
                index: 5,
                status: Status::SUSPENDED,
            },
            StatusEntry {
                index: 2,
                status: Status::INVALID,
            },
        ];

        let updated_lst = update_status_list(existing_lst, status_updates, 2).unwrap();
        let decoded = decode(&updated_lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        // SUSPENDED (2) requires 2 bits
        // Original: [00_01, 10_11], update index 2 to 01, index 5 to 10
        // Expected: [00_01, 01_11, 10_00]
        let expected_status_array = vec![0b00001100, 0b01011100, 0b10000000];
        assert_eq!(
            updated_status_array, expected_status_array,
            "The status array was not updated correctly"
        );
    }
}
