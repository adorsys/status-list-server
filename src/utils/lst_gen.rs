use base64url::{decode, encode};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use std::io::{Read, Write};

use crate::models::{Status, StatusEntry, StatusList};

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

    let required_bits = match max_status_value {
        0 | 1 => 1,
        2 | 3 => 2,
        4..=15 => 4,
        16..=255 => 8,
        _ => return Err(Error::Generic("Status value too large".to_string())),
    };

    Ok(original_bits.unwrap_or(required_bits).max(required_bits))
}

// Helper function to calculate the required status array size
fn calculate_array_size(status_updates: &[StatusEntry], bits: usize) -> Result<usize, Error> {
    if status_updates.is_empty() {
        return Ok(0);
    }

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

// Helper function to apply updates
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

        if byte_index >= status_array.len() {
            return Err(Error::Generic("Index out of bounds".to_string()));
        }

        let status_value = match update.status {
            Status::VALID => 0,
            Status::INVALID => 1,
            Status::SUSPENDED => 2,
            Status::APPLICATIONSPECIFIC => 3,
        };

        let mask = ((1u32 << bits) - 1) << bit_offset;
        status_array[byte_index] &= !(mask as u8);
        status_array[byte_index] |= ((status_value as u8) << bit_offset) & (mask as u8);

        if bit_offset + bits > 8 {
            let overflow_bits = (bit_offset + bits) - 8;
            let overflow_mask = ((1u32 << overflow_bits) - 1) as u8;
            if byte_index + 1 < status_array.len() {
                status_array[byte_index + 1] &= !overflow_mask;
                status_array[byte_index + 1] |=
                    ((status_value as u8) >> (bits - overflow_bits)) & overflow_mask;
            }
        }
    }

    Ok(())
}

// Helper function to apply updates and encode the result
fn apply_and_encode(
    status_array: &mut [u8],
    status_updates: &[StatusEntry],
    bits: usize,
) -> Result<String, Error> {
    apply_updates(status_array, status_updates, bits)?;
    encode_compressed(status_array)
}

pub fn create_status_list(status_updates: Vec<StatusEntry>) -> Result<StatusList, Error> {
    if status_updates.is_empty() {
        let stl = StatusList {
            bits: 1,
            lst: String::new(),
        };
        return Ok(stl);
    }

    let bits = determine_bits(&status_updates, None)?;
    let len = calculate_array_size(&status_updates, bits)?;

    let mut status_array = vec![0u8; len];
    let lst = apply_and_encode(&mut status_array, &status_updates, bits)?;
    Ok(StatusList {
        bits: bits as u8,
        lst,
    })
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
            value
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
) -> Result<StatusList, Error> {
    let decoded_statuses = decode_status_array(old_array, old_bits)?;
    let mut full_statuses: Vec<StatusEntry> = decoded_statuses
        .into_iter()
        .enumerate()
        .map(|(i, status)| StatusEntry {
            index: i as i32,
            status,
        })
        .collect();

    for update in status_updates {
        if let Some(entry) = full_statuses.iter_mut().find(|e| e.index == update.index) {
            entry.status = update.status.clone();
        } else {
            full_statuses.push(update.clone());
        }
    }

    create_status_list(full_statuses)
}

pub fn update_status_list(
    existing_lst: String,
    status_updates: Vec<StatusEntry>,
    current_bits: u8,
) -> Result<StatusList, Error> {
    if status_updates.is_empty() {
        return Ok(StatusList {
            bits: current_bits,
            lst: existing_lst,
        });
    }
    let original_bits = current_bits as usize;
    let new_bits = determine_bits(&status_updates, Some(original_bits))?;

    let compressed_data = decode(&existing_lst).map_err(|_| Error::DecodeFailed)?;
    let mut decoder = ZlibDecoder::new(&compressed_data[..]);
    let mut status_array = Vec::new();
    decoder
        .read_to_end(&mut status_array)
        .map_err(|e| Error::Generic(e.to_string()))?;

    if new_bits > original_bits {
        let result = reencode_status_array(&status_array, original_bits, &status_updates)?;
        return Ok(result);
    }

    let required_len = calculate_array_size(&status_updates, original_bits)?;
    if status_array.len() < required_len {
        status_array.resize(required_len, 0);
    }

    let lst = apply_and_encode(&mut status_array, &status_updates, original_bits)?;
    let stl = StatusList {
        bits: original_bits as u8,
        lst,
    };
    Ok(stl)
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
        let decoded = base64url::decode(&result.lst).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b00000010]);
    }

    #[test]
    fn test_update_lst_with_1_bit_statuses() {
        let existing_byte_array = vec![0b01010101];
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

        let result = update_status_list(existing_lst, updates, 1).unwrap();
        let decoded = base64url::decode(&result.lst).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b01010110]);
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
        let decoded = base64url::decode(&result.lst).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b11100100]);
    }

    #[test]
    fn test_update_lst_with_2_bit_statuses() {
        let original_status_array = vec![0b11100100];
        let updates = vec![StatusEntry {
            index: 1,
            status: Status::VALID,
        }];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        let updated_lst = update_status_list(existing_lst, updates, 1).unwrap();
        let decoded = decode(&updated_lst.lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        assert_eq!(updated_status_array, vec![0b11100100]);
    }

    #[test]
    fn test_update_lst_with_2_bit_statuses_larger_bits() {
        let original_status_array = vec![0b00000110];
        let updates = vec![StatusEntry {
            index: 1,
            status: Status::SUSPENDED,
        }];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        let updated_lst = update_status_list(existing_lst, updates, 1).unwrap();
        let decoded = decode(&updated_lst.lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        assert_eq!(updated_status_array, vec![0b00011000, 0b00000000]);
    }

    #[test]
    fn test_create_lst_empty_updates() {
        let updates = vec![];

        let result = create_status_list(updates).unwrap();
        let decoded = base64url::decode(&result.lst).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, Vec::<u8>::new());
    }

    #[test]
    fn test_update_lst_empty_updates() {
        let original_status_array = vec![0b11100100];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        let status_updates = vec![];

        let updated_lst = update_status_list(existing_lst.clone(), status_updates, 1)
            .unwrap()
            .lst;
        assert_eq!(updated_lst, existing_lst);
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
        let original_status_array = vec![0b11100100];

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
    fn test_update_lst_requires_bit_width_expansion() {
        let original_status_array = vec![0b01010101];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original_status_array).unwrap();
        let compressed_status = encoder.finish().expect("Failed to finish compression");
        let existing_lst = base64url::encode(compressed_status);

        let status_updates = vec![
            StatusEntry {
                index: 2,
                status: Status::SUSPENDED,
            },
            StatusEntry {
                index: 5,
                status: Status::INVALID,
            },
        ];

        let updated_lst = update_status_list(existing_lst, status_updates, 1).unwrap();

        let decoded = decode(&updated_lst.lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        let expected_status_array = vec![0b00100001, 0b00010101];
        assert_eq!(
            updated_status_array, expected_status_array,
            "The status array was not re-encoded correctly with wider bit size"
        );
    }
}
