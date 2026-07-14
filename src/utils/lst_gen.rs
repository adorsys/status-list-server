use base64url::{decode, encode};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
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
            Status::ApplicationSpecific(value) => value,
        })
        .max()
        .ok_or_else(|| Error::Generic("Failed to determine max status value".to_string()))?;

    // Validate ALL ApplicationSpecific values are >= 256
    if status_updates
        .iter()
        .any(|e| matches!(e.status, Status::ApplicationSpecific(v) if v < 256))
    {
        return Err(Error::Generic(
            "ApplicationSpecific value must be >= 256".to_string(),
        ));
    }

    let required_bits = match max_status_value {
        0 | 1 => 1,
        2 | 3 => 2,
        4..=15 => 4,
        16..=255 => 8,
        _ => {
            // For values >= 256, compute minimal bits needed
            let bits_needed = (max_status_value as usize + 1)
                .next_power_of_two()
                .trailing_zeros();
            if bits_needed == 0 {
                return Err(Error::Generic("Status value too large".to_string()));
            }
            bits_needed
        }
    };

    Ok(original_bits
        .unwrap_or(required_bits as usize)
        .max(required_bits as usize))
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

    let end_bit = (max_index as usize) * bits + bits - 1;
    Ok(end_bit / 8 + 1)
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
            Status::ApplicationSpecific(value) => {
                if value < 256 {
                    return Err(Error::Generic(
                        "ApplicationSpecific value must be >= 256".to_string(),
                    ));
                }
                value
            }
        };

        let total_bit_pos = idx * bits;
        let start_byte = total_bit_pos / 8;
        let _start_offset = total_bit_pos % 8;

        if bit_offset + bits <= 8 {
            let mask: u8 = (((1u32 << bits) - 1) << bit_offset) as u8;
            status_array[byte_index] &= !mask;
            status_array[byte_index] |= ((status_value as u8) << bit_offset) & mask;
        } else {
            let first_byte_bits = 8 - bit_offset;
            let first_mask: u8 = (((1u32 << first_byte_bits) - 1) << bit_offset) as u8;
            status_array[byte_index] &= !first_mask;
            status_array[byte_index] |= ((status_value as u8) << bit_offset) & first_mask;

            let mut bits_written = first_byte_bits;
            let mut cur_byte = start_byte + 1;
            let mut cur_offset = 0;

            while bits_written < bits {
                let remaining_bits = bits - bits_written;
                let bits_this_byte = remaining_bits.min(8);

                for i in 0..bits_this_byte {
                    let global_bit = bits_written + i;
                    let value_bit = (status_value >> global_bit) & 1;
                    status_array[cur_byte] &= !(1u8 << cur_offset);
                    status_array[cur_byte] |= (value_bit as u8) << cur_offset;
                    cur_offset += 1;
                    if cur_offset >= 8 {
                        cur_byte += 1;
                        cur_offset = 0;
                    }
                }
                bits_written += bits_this_byte;
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

pub(crate) fn create_status_list(status_updates: Vec<StatusEntry>) -> Result<StatusList, Error> {
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
        let total_bit_pos = i * bits;
        let start_byte = total_bit_pos / 8;
        let start_offset = total_bit_pos % 8;

        let mut value: u32 = 0;
        let mut bits_read = 0;
        let mut cur_byte = start_byte;
        let mut cur_offset = start_offset;
        let mut bits_in_current_byte = 8 - start_offset;

        while bits_read < bits {
            if cur_byte >= array.len() {
                break;
            }
            let bits_this_iter = bits_in_current_byte.min(bits - bits_read);

            let extracted =
                ((array[cur_byte] as u16 >> cur_offset) & ((1u16 << bits_this_iter) - 1)) as u32;
            value |= extracted << bits_read;

            bits_read += bits_this_iter;
            bits_in_current_byte -= bits_this_iter;

            if bits_in_current_byte == 0 {
                cur_byte += 1;
                cur_offset = 0;
                bits_in_current_byte = 8;
            }
        }

        statuses.push(match value {
            0 => Status::VALID,
            1 => Status::INVALID,
            2 => Status::SUSPENDED,
            value if value >= 256 => Status::ApplicationSpecific(value),
            _ => {
                return Err(Error::Generic(
                    "Invalid status value in existing list".to_string(),
                ));
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

pub(crate) fn update_status_list(
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

pub(crate) fn encode_compressed(status_array: &[u8]) -> Result<String, Error> {
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
    use flate2::Compression;
    use flate2::read::ZlibDecoder;
    use flate2::write::ZlibEncoder;
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
    fn test_create_lst_with_9_bit_app_specific_exact_bytes() {
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
                status: Status::ApplicationSpecific(256),
            },
        ];

        let result = create_status_list(updates).unwrap();
        let decoded = base64url::decode(&result.lst).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&*decoded);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(result.bits, 9, "Should require 9 bits for value 256");
        assert_eq!(
            decompressed.len(),
            5,
            "4 entries * 9 bits = 36 bits = 5 bytes"
        );

        let statuses = decode_status_array(&decompressed, 9).unwrap();
        assert_eq!(statuses[0], Status::VALID);
        assert_eq!(statuses[1], Status::INVALID);
        assert_eq!(statuses[2], Status::SUSPENDED);
        assert_eq!(statuses[3], Status::ApplicationSpecific(256));
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

    #[test]
    fn test_create_lst_with_2_bit_statuses_original() {
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
                status: Status::INVALID,
            },
        ];

        let result = create_status_list(updates).unwrap();
        let decoded = base64url::decode(&result.lst).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&decoded[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, vec![0b01100100]);
    }

    #[test]
    fn test_app_specific_rejects_values_3_to_255() {
        for val in [3u32, 100, 255] {
            let updates = vec![StatusEntry {
                index: 0,
                status: Status::ApplicationSpecific(val),
            }];
            let result = create_status_list(updates);
            assert!(
                matches!(result, Err(Error::Generic(ref s)) if s.contains(">= 256")),
                "value {} should be rejected",
                val
            );
        }
    }

    #[test]
    fn test_decode_rejects_values_3_to_255() {
        let arr = vec![3u8];
        let result = decode_status_array(&arr, 2);
        assert!(matches!(result, Err(Error::Generic(_))));
    }

    #[test]
    fn test_app_specific_256_at_offset_exact_bytes() {
        let updates = vec![StatusEntry {
            index: 0,
            status: Status::ApplicationSpecific(256),
        }];
        let result = create_status_list(updates).unwrap();
        let decoded = base64url::decode(&result.lst).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&decoded[..]);
        let mut raw = Vec::new();
        decoder.read_to_end(&mut raw).unwrap();

        assert_eq!(result.bits, 9, "Value 256 requires 9 bits");
        assert!(!raw.is_empty(), "Should have encoded bytes");

        let statuses = decode_status_array(&raw, 9).unwrap();
        assert_eq!(
            statuses[0],
            Status::ApplicationSpecific(256),
            "Round-trip should preserve value"
        );
    }

    #[test]
    fn test_app_specific_multibyte_roundtrip() {
        let updates = vec![
            StatusEntry {
                index: 0,
                status: Status::ApplicationSpecific(512),
            },
            StatusEntry {
                index: 3,
                status: Status::ApplicationSpecific(256),
            },
        ];
        let result = create_status_list(updates).unwrap();
        let decoded_bytes = base64url::decode(&result.lst).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&decoded_bytes[..]);
        let mut raw = Vec::new();
        decoder.read_to_end(&mut raw).unwrap();

        let statuses = decode_status_array(&raw, result.bits as usize).unwrap();
        assert_eq!(statuses[0], Status::ApplicationSpecific(512));
        assert_eq!(statuses[3], Status::ApplicationSpecific(256));
    }

    #[test]
    fn test_app_specific_large_value_at_offset() {
        let updates = vec![
            StatusEntry {
                index: 0,
                status: Status::INVALID,
            },
            StatusEntry {
                index: 3,
                status: Status::ApplicationSpecific(4096),
            },
        ];
        let result = create_status_list(updates).unwrap();
        let decoded = base64url::decode(&result.lst).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&decoded[..]);
        let mut raw = Vec::new();
        decoder.read_to_end(&mut raw).unwrap();

        assert_eq!(result.bits, 13, "Value 4096 requires 13 bits (2^13 = 8192)");

        let statuses = decode_status_array(&raw, result.bits as usize).unwrap();
        assert_eq!(statuses[0], Status::INVALID, "Index 0 should be INVALID");
        assert_eq!(
            statuses[3],
            Status::ApplicationSpecific(4096),
            "Index 3 should decode as 4096 (the reviewer's original failing case)"
        );
    }

    #[test]
    fn test_status_serde_integer_roundtrip() {
        use crate::models::Status;
        use serde_json;

        assert_eq!(serde_json::from_str::<Status>("0").unwrap(), Status::VALID);
        assert_eq!(
            serde_json::from_str::<Status>("1").unwrap(),
            Status::INVALID
        );
        assert_eq!(
            serde_json::from_str::<Status>("2").unwrap(),
            Status::SUSPENDED
        );
        assert_eq!(
            serde_json::from_str::<Status>("256").unwrap(),
            Status::ApplicationSpecific(256)
        );
        assert_eq!(serde_json::to_string(&Status::VALID).unwrap(), "0");
        assert_eq!(serde_json::to_string(&Status::INVALID).unwrap(), "1");
        assert_eq!(serde_json::to_string(&Status::SUSPENDED).unwrap(), "2");
        assert_eq!(
            serde_json::to_string(&Status::ApplicationSpecific(256)).unwrap(),
            "256"
        );
        assert!(serde_json::from_str::<Status>("3").is_err());
        assert!(serde_json::from_str::<Status>("100").is_err());
        assert!(serde_json::from_str::<Status>("255").is_err());
    }

    #[test]
    fn test_legacy_status_3_is_rejected() {
        let arr = vec![0b11100100];
        let result = decode_status_array(&arr, 2);
        assert!(
            matches!(result, Err(Error::Generic(_))),
            "Legacy value 3 (old APPLICATIONSPECIFIC) should be rejected per spec: values 3-255 are reserved"
        );
    }

    #[test]
    fn test_decode_rejects_values_3_to_255_various_bits() {
        for (arr, bits) in &[(vec![3u8], 2), (vec![100u8], 8)] {
            let result = decode_status_array(arr, *bits);
            assert!(
                matches!(result, Err(Error::Generic(_))),
                "Value {} in {:?}-bit encoding should be rejected",
                arr[0],
                bits
            );
        }
    }

    // §4.1/§4.2 worked vectors. Decompress-direction is the real (backend-independent)
    // guarantee; encode-direction is a secondary pin coupled to flate2's exact output.

    #[test]
    fn test_spec_vector_1_bit() {
        let expected_bytes = vec![0xB9, 0xA3];
        let spec_lst = "eNrbuRgAAhcBXQ";

        let decoded = decode(spec_lst).expect("Failed to decode base64url");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, expected_bytes);

        assert_eq!(encode_compressed(&expected_bytes).unwrap(), spec_lst);
    }

    #[test]
    fn test_spec_vector_2_bit() {
        let expected_bytes = vec![0xC9, 0x44, 0xF9];
        let spec_lst = "eNo76fITAAPfAgc";

        let decoded = decode(spec_lst).expect("Failed to decode base64url");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, expected_bytes);

        assert_eq!(encode_compressed(&expected_bytes).unwrap(), spec_lst);
    }

    #[test]
    fn test_spec_vector_1_bit_through_create_status_list() {
        // Same §4.1 vector as test_spec_vector_1_bit, but through the real StatusEntry ->
        // create_status_list pipeline, not just encode_compressed.
        let statuses = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        let updates: Vec<StatusEntry> = statuses
            .into_iter()
            .enumerate()
            .map(|(index, bit)| StatusEntry {
                index: index as i32,
                status: if bit == 1 {
                    Status::INVALID
                } else {
                    Status::VALID
                },
            })
            .collect();

        let result = create_status_list(updates).unwrap();
        assert_eq!(result.bits, 1);

        // Decompress direction: backend-independent guarantee (see comment above test_spec_vector_1_bit).
        let decoded = decode(&result.lst).expect("Failed to decode base64url");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, vec![0xB9, 0xA3]);

        // Encode direction: canonical-output pin, coupled to flate2's exact backend.
        assert_eq!(result.lst, "eNrbuRgAAhcBXQ");
    }
}
