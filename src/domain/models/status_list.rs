//! Status list domain models, compressed bitpack serialization, and business operations.

use crate::domain::models::credential::Issuer;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Errors originating from domain validation, storage conflicts, or compression/parsing failures.
///
/// `#[non_exhaustive]` so adding a variant stays patch-level instead of tripping
/// `cargo-semver-checks` (`enum_variant_added`).
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum StatusListError {
    #[error("invalid status list index")]
    InvalidIndex,
    #[error("{0}")]
    InvalidStatusList(String),
    #[error("corrupt stored status list: {0}")]
    CorruptStoredList(String),
    #[error("status list already exists")]
    AlreadyExists,
    #[error("status list was not found")]
    NotFound,
    #[error("historical status list token not found")]
    HistoricalNotFound,
    #[error("invalid historical time")]
    InvalidHistoricalTime,
    #[error("issuer does not own the status list")]
    IssuerMismatch,
    #[error("serialized status list size exceeds configured maximum")]
    TooLarge,
    #[error("too many statuses in request: {count} > {max}")]
    TooManyStatuses { count: usize, max: usize },
    #[error("status index {index} exceeds configured maximum {max}")]
    IndexTooLarge { index: i32, max: i32 },
    #[error("the status list was modified concurrently")]
    Conflict,
    /// The write lost a lock race in storage and was rolled back.
    ///
    /// Distinct from [`Conflict`]: there a racing writer's value won and the
    /// client must re-read first. Here nothing was written and nobody won, so
    /// the request is safe to retry verbatim.
    ///
    /// `code` is an opaque backend tag for the metric only. It never reaches the
    /// client and nothing in the domain branches on it.
    ///
    /// [`Conflict`]: StatusListError::Conflict
    #[error("the write lost a lock race ({code}) and can be retried unchanged")]
    Contention { code: &'static str },
    #[error("the service is currently unavailable. Please try again later")]
    Unavailable,
    #[error("storage error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Represents the status of a specific index in a status list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Valid,
    Invalid,
    Suspended,
    ApplicationSpecific(u32),
}

/// Pair of status list index and target status state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusEntry {
    pub index: i32,
    pub status: Status,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusListRecord {
    pub list_id: String,
    pub issuer: Issuer,
    pub status_list: StatusList,
    pub sub: String,
    /// Unix timestamp (seconds) of last modification
    pub updated_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusListSnapshot {
    pub snapshot_id: String,
    pub list_id: String,
    pub issuer: Issuer,
    pub status_list: StatusList,
    pub sub: String,
    /// Unix timestamp (seconds) when this snapshot becomes valid.
    pub iat: i64,
    /// Unix timestamp (seconds) when this snapshot stops being valid.
    pub exp: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusList {
    pub bits: u8,
    pub lst: String,
}

impl StatusList {
    pub fn create(status_updates: Vec<StatusEntry>) -> Result<Self, StatusListError> {
        if status_updates.is_empty() {
            return Ok(Self {
                bits: 1,
                lst: encode_compressed(&[])?,
            });
        }

        let bits = determine_bits(&status_updates, None)?;
        let len = calculate_array_size(&status_updates, bits)?;
        let mut status_array = vec![0u8; len];
        apply_updates(&mut status_array, &status_updates, bits)?;
        Ok(Self {
            bits: bits as u8,
            lst: encode_compressed(&status_array)?,
        })
    }

    pub fn update(&self, status_updates: Vec<StatusEntry>) -> Result<Self, StatusListError> {
        if status_updates.is_empty() {
            return Ok(self.clone());
        }

        let old_bits = self.bits as usize;
        validate_bits(old_bits)?;
        let new_bits = determine_bits(&status_updates, Some(old_bits))?;
        let mut status_array = decode_compressed(&self.lst)?;

        if new_bits > old_bits {
            let decoded_statuses = decode_status_array(&status_array, old_bits)?;
            let mut full_statuses: Vec<StatusEntry> = decoded_statuses
                .into_iter()
                .enumerate()
                .map(|(index, status)| StatusEntry {
                    index: index as i32,
                    status,
                })
                .collect();
            full_statuses.extend(status_updates);
            return Self::create_with_bits(full_statuses, new_bits);
        }

        let required_len = calculate_array_size(&status_updates, old_bits)?;
        if required_len > status_array.len() {
            status_array.resize(required_len, 0);
        }
        apply_updates(&mut status_array, &status_updates, old_bits)?;
        Ok(Self {
            bits: self.bits,
            lst: encode_compressed(&status_array)?,
        })
    }

    fn create_with_bits(
        status_updates: Vec<StatusEntry>,
        bits: usize,
    ) -> Result<Self, StatusListError> {
        validate_bits(bits)?;
        let len = calculate_array_size(&status_updates, bits)?;
        let mut status_array = vec![0u8; len];
        apply_updates(&mut status_array, &status_updates, bits)?;
        Ok(Self {
            bits: bits as u8,
            lst: encode_compressed(&status_array)?,
        })
    }
}

fn status_value(status: &Status) -> Result<u32, StatusListError> {
    match status {
        Status::Valid => Ok(0),
        Status::Invalid => Ok(1),
        Status::Suspended => Ok(2),
        Status::ApplicationSpecific(value) if *value <= 255 => Ok(*value),
        Status::ApplicationSpecific(value) => Err(StatusListError::InvalidStatusList(format!(
            "status value {value} exceeds 8-bit capacity; maximum supported status value is 255"
        ))),
    }
}

fn validate_bits(bits: usize) -> Result<(), StatusListError> {
    match bits {
        1 | 2 | 4 | 8 => Ok(()),
        _ => Err(StatusListError::CorruptStoredList(format!(
            "stored status list uses unsupported bit width {bits}; expected one of 1, 2, 4, or 8"
        ))),
    }
}

fn determine_bits(
    status_updates: &[StatusEntry],
    original_bits: Option<usize>,
) -> Result<usize, StatusListError> {
    let max_status_value = status_updates
        .iter()
        .map(|entry| status_value(&entry.status))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or_else(|| {
            StatusListError::InvalidStatusList("Failed to determine max status value".to_string())
        })?;

    let required_bits = match max_status_value {
        0 | 1 => 1,
        2 | 3 => 2,
        4..=15 => 4,
        16..=255 => 8,
        _ => unreachable!("status_value rejects values above 255"),
    };

    if let Some(bits) = original_bits {
        validate_bits(bits)?;
    }

    Ok(original_bits.unwrap_or(required_bits).max(required_bits))
}

fn calculate_array_size(
    status_updates: &[StatusEntry],
    bits: usize,
) -> Result<usize, StatusListError> {
    if status_updates.is_empty() {
        return Ok(0);
    }

    let max_index = status_updates
        .iter()
        .map(|update| update.index)
        .max()
        .ok_or_else(|| {
            StatusListError::InvalidStatusList("Failed to determine max index".to_string())
        })?;

    if max_index < 0 {
        return Err(StatusListError::InvalidIndex);
    }

    let end_bit = (max_index as usize) * bits + bits - 1;
    Ok(end_bit / 8 + 1)
}

fn apply_updates(
    status_array: &mut [u8],
    status_updates: &[StatusEntry],
    bits: usize,
) -> Result<(), StatusListError> {
    for update in status_updates {
        if update.index < 0 {
            return Err(StatusListError::InvalidIndex);
        }

        let idx = update.index as usize;
        let bit_position = idx * bits;
        let byte_index = bit_position / 8;
        let bit_offset = bit_position % 8;

        if byte_index >= status_array.len() {
            return Err(StatusListError::InvalidStatusList(
                "Index out of bounds".to_string(),
            ));
        }

        let value = status_value(&update.status)?;
        let start_byte = bit_position / 8;

        if bit_offset + bits <= 8 {
            let mask: u8 = (((1u32 << bits) - 1) << bit_offset) as u8;
            status_array[byte_index] &= !mask;
            status_array[byte_index] |= ((value as u8) << bit_offset) & mask;
        } else {
            let first_byte_bits = 8 - bit_offset;
            let first_mask: u8 = (((1u32 << first_byte_bits) - 1) << bit_offset) as u8;
            status_array[byte_index] &= !first_mask;
            status_array[byte_index] |= ((value as u8) << bit_offset) & first_mask;

            let mut bits_written = first_byte_bits;
            let mut cur_byte = start_byte + 1;
            let mut cur_offset = 0;

            while bits_written < bits {
                let bits_this_byte = (bits - bits_written).min(8);
                for i in 0..bits_this_byte {
                    let global_bit = bits_written + i;
                    let value_bit = (value >> global_bit) & 1;
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

fn encode_compressed(bytes: &[u8]) -> Result<String, StatusListError> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(bytes).map_err(|err| {
        StatusListError::InvalidStatusList(format!("Failed to compress status list: {err}"))
    })?;
    encoder.finish().map(base64url::encode).map_err(|err| {
        StatusListError::InvalidStatusList(format!(
            "Failed to finish status list compression: {err}"
        ))
    })
}

fn decode_compressed(encoded: &str) -> Result<Vec<u8>, StatusListError> {
    let bytes = base64url::decode(encoded).map_err(|err| {
        StatusListError::CorruptStoredList(format!("Invalid lst encoding: {err}"))
    })?;
    let mut decoder = flate2::read::ZlibDecoder::new(&bytes[..]);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).map_err(|err| {
        StatusListError::CorruptStoredList(format!("Failed to decompress status list: {err}"))
    })?;
    Ok(decoded)
}

fn decode_status_array(array: &[u8], bits: usize) -> Result<Vec<Status>, StatusListError> {
    validate_bits(bits)?;

    if array.len() * 8 % bits >= 8 {
        return Err(StatusListError::CorruptStoredList(format!(
            "stored status array of {} bytes leaves an unused trailing byte at {bits}-bit width",
            array.len()
        )));
    }

    let mut statuses = Vec::new();
    for i in 0..(array.len() * 8 / bits) {
        let total_bit_pos = i * bits;
        let mut cur_byte = total_bit_pos / 8;
        let mut cur_offset = total_bit_pos % 8;
        let mut bits_in_current_byte = 8 - cur_offset;
        let mut value: u32 = 0;
        let mut bits_read = 0;

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
            0 => Status::Valid,
            1 => Status::Invalid,
            2 => Status::Suspended,
            value => Status::ApplicationSpecific(value),
        });
    }
    Ok(statuses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    fn decompress(encoded: &str) -> Vec<u8> {
        let decoded = base64url::decode(encoded).unwrap();
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        decompressed
    }

    fn assert_allowed_bits(bits: u8) {
        assert!(
            matches!(bits, 1 | 2 | 4 | 8),
            "bits must be one of 1, 2, 4, or 8, got {bits}"
        );
    }

    #[test]
    fn create_status_list_matches_one_bit_spec_vector() {
        let statuses = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        let updates = statuses
            .into_iter()
            .enumerate()
            .map(|(index, bit)| StatusEntry {
                index: index as i32,
                status: if bit == 1 {
                    Status::Invalid
                } else {
                    Status::Valid
                },
            })
            .collect();

        let result = StatusList::create(updates).unwrap();

        assert_eq!(result.bits, 1);
        assert_eq!(decompress(&result.lst), vec![0xB9, 0xA3]);
        assert_eq!(result.lst, "eNrbuRgAAhcBXQ");
    }

    #[test]
    fn create_status_list_matches_two_bit_spec_vector() {
        let statuses = [1, 2, 0, 3, 0, 1, 3, 3, 1, 2, 3, 3];
        let updates = statuses
            .into_iter()
            .enumerate()
            .map(|(index, value)| StatusEntry {
                index: index as i32,
                status: match value {
                    0 => Status::Valid,
                    1 => Status::Invalid,
                    2 => Status::Suspended,
                    _ => Status::ApplicationSpecific(3),
                },
            })
            .collect();

        let result = StatusList::create(updates).unwrap();

        assert_eq!(result.bits, 2);
        assert_eq!(
            decode_status_array(&decompress(&result.lst), 2)
                .unwrap()
                .len(),
            12,
        );
    }

    #[test]
    fn update_status_list_bumps_bit_width_for_supported_application_specific_values() {
        let original = StatusList::create(vec![StatusEntry {
            index: 0,
            status: Status::Valid,
        }])
        .unwrap();

        let updated = original
            .update(vec![StatusEntry {
                index: 1,
                status: Status::ApplicationSpecific(255),
            }])
            .unwrap();

        assert_eq!(updated.bits, 8);
        let statuses = decode_status_array(&decompress(&updated.lst), 8).unwrap();
        assert_eq!(statuses[0], Status::Valid);
        assert_eq!(statuses[1], Status::ApplicationSpecific(255));
    }

    fn entry(index: i32, status: Status) -> StatusEntry {
        StatusEntry { index, status }
    }

    #[test]
    fn create_one_bit_exact_bytes() {
        let result =
            StatusList::create(vec![entry(0, Status::Valid), entry(1, Status::Invalid)]).unwrap();
        assert_eq!(result.bits, 1);
        assert_eq!(decompress(&result.lst), vec![0b0000_0010]);
    }

    #[test]
    fn create_two_bit_exact_bytes() {
        let result = StatusList::create(vec![
            entry(0, Status::Valid),
            entry(1, Status::Invalid),
            entry(2, Status::Suspended),
            entry(3, Status::Invalid),
        ])
        .unwrap();
        assert_eq!(result.bits, 2);
        assert_eq!(decompress(&result.lst), vec![0b0110_0100]);
    }

    fn from_raw(bytes: &[u8], bits: u8) -> StatusList {
        StatusList {
            bits,
            lst: encode_compressed(bytes).unwrap(),
        }
    }

    #[test]
    fn update_one_bit_exact_bytes() {
        let updated = from_raw(&[0b0101_0101], 1)
            .update(vec![entry(0, Status::Valid), entry(1, Status::Invalid)])
            .unwrap();
        assert_eq!(updated.bits, 1);
        assert_eq!(decompress(&updated.lst), vec![0b0101_0110]);
    }

    #[test]
    fn update_leaves_other_slots_untouched() {
        let updated = from_raw(&[0b1110_0100], 1)
            .update(vec![entry(1, Status::Valid)])
            .unwrap();
        assert_eq!(decompress(&updated.lst), vec![0b1110_0100]);
    }

    #[test]
    fn update_widens_one_bit_list_for_suspended() {
        let updated = from_raw(&[0b0000_0110], 1)
            .update(vec![entry(1, Status::Suspended)])
            .unwrap();
        assert_eq!(updated.bits, 2);
        assert_eq!(decompress(&updated.lst), vec![0b0001_1000, 0b0000_0000]);
    }

    #[test]
    fn update_reencodes_existing_entries_at_wider_bits() {
        let updated = from_raw(&[0b0101_0101], 1)
            .update(vec![entry(2, Status::Suspended), entry(5, Status::Invalid)])
            .unwrap();
        assert_eq!(updated.bits, 2);
        assert_eq!(
            decompress(&updated.lst),
            vec![0b0010_0001, 0b0001_0101],
            "existing statuses must survive the bit-width re-encode"
        );
    }

    #[test]
    fn update_widening_pads_to_byte_boundary() {
        let original = StatusList::create(vec![
            entry(0, Status::Invalid),
            entry(1, Status::Valid),
            entry(2, Status::Invalid),
        ])
        .unwrap();
        assert_eq!(original.bits, 1);
        assert_eq!(
            decompress(&original.lst).len(),
            1,
            "three 1-bit entries -> one byte"
        );

        let widened = original.update(vec![entry(3, Status::Suspended)]).unwrap();
        assert_eq!(widened.bits, 2);

        let statuses = decode_status_array(&decompress(&widened.lst), 2).unwrap();
        assert_eq!(
            statuses.len(),
            8,
            "logical length rounds up to the old byte boundary on widening"
        );
        assert_eq!(statuses[0], Status::Invalid);
        assert_eq!(statuses[1], Status::Valid);
        assert_eq!(statuses[2], Status::Invalid);
        assert_eq!(statuses[3], Status::Suspended);
        assert_eq!(statuses[4], Status::Valid);
        assert_eq!(statuses[7], Status::Valid);
    }

    #[test]
    fn eight_bit_app_specific_exact_layout() {
        let result = StatusList::create(vec![
            entry(0, Status::Valid),
            entry(1, Status::Invalid),
            entry(2, Status::Suspended),
            entry(3, Status::ApplicationSpecific(255)),
        ])
        .unwrap();
        assert_eq!(result.bits, 8);
        let raw = decompress(&result.lst);
        assert_eq!(raw.len(), 4, "4 entries * 8 bits = 4 bytes");
        let statuses = decode_status_array(&raw, 8).unwrap();
        assert_eq!(statuses[0], Status::Valid);
        assert_eq!(statuses[1], Status::Invalid);
        assert_eq!(statuses[2], Status::Suspended);
        assert_eq!(statuses[3], Status::ApplicationSpecific(255));
    }

    #[test]
    fn app_specific_within_8_bit_capacity_roundtrip() {
        let result = StatusList::create(vec![
            entry(0, Status::ApplicationSpecific(255)),
            entry(3, Status::ApplicationSpecific(16)),
        ])
        .unwrap();
        let statuses = decode_status_array(&decompress(&result.lst), result.bits as usize).unwrap();
        assert_eq!(result.bits, 8);
        assert_eq!(statuses[0], Status::ApplicationSpecific(255));
        assert_eq!(statuses[3], Status::ApplicationSpecific(16));
    }

    #[test]
    fn create_rejects_status_values_above_8_bit_capacity() {
        for value in [256u32, 512, 4096] {
            let result = StatusList::create(vec![entry(0, Status::ApplicationSpecific(value))]);
            assert!(
                matches!(result, Err(StatusListError::InvalidStatusList(ref msg)) if msg.contains("exceeds 8-bit capacity") && msg.contains("255")),
                "value {value} must be rejected"
            );
        }
    }

    #[test]
    fn app_specific_values_at_or_below_255_are_supported() {
        for (value, bits) in [(3u32, 2u8), (100, 8), (255, 8)] {
            let result =
                StatusList::create(vec![entry(0, Status::ApplicationSpecific(value))]).unwrap();
            assert_eq!(result.bits, bits);
            assert_allowed_bits(result.bits);
        }
    }

    #[test]
    fn update_rejects_status_values_above_8_bit_capacity() {
        let original = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        let result = original.update(vec![entry(0, Status::ApplicationSpecific(256))]);
        assert!(
            matches!(result, Err(StatusListError::InvalidStatusList(ref msg)) if msg.contains("exceeds 8-bit capacity"))
        );
    }

    #[test]
    fn decode_accepts_application_specific_values_within_bit_width() {
        let statuses = decode_status_array(&[0b1110_0100u8], 2).unwrap();
        assert_eq!(
            statuses[..4],
            [
                Status::Valid,
                Status::Invalid,
                Status::Suspended,
                Status::ApplicationSpecific(3)
            ]
        );

        let statuses = decode_status_array(&[100u8], 8).unwrap();
        assert_eq!(statuses, vec![Status::ApplicationSpecific(100)]);
    }

    #[test]
    fn update_over_corrupt_lst_is_state_error_not_request_error() {
        let bad_base64 = StatusList {
            bits: 1,
            lst: "not valid base64!!".to_string(),
        };
        assert!(matches!(
            bad_base64.update(vec![entry(0, Status::Invalid)]),
            Err(StatusListError::CorruptStoredList(_))
        ));

        let bad_zlib = StatusList {
            bits: 1,
            lst: base64url::encode([0xFF, 0xFF, 0xFF, 0xFF]),
        };
        assert!(matches!(
            bad_zlib.update(vec![entry(0, Status::Invalid)]),
            Err(StatusListError::CorruptStoredList(_))
        ));
    }

    #[test]
    fn update_with_bad_request_value_stays_request_error() {
        let sound = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        assert!(matches!(
            sound.update(vec![entry(0, Status::ApplicationSpecific(256))]),
            Err(StatusListError::InvalidStatusList(_))
        ));
    }

    #[test]
    fn decode_rejects_unsupported_bit_widths() {
        for bits in [0usize, 3, 5, 7, 9, 13] {
            let result = decode_status_array(&[0x00], bits);
            assert!(
                matches!(result, Err(StatusListError::CorruptStoredList(_))),
                "bit width {bits} must be rejected"
            );
        }
    }

    #[test]
    fn update_rejects_stored_lists_with_unsupported_bit_widths() {
        let invalid_bits_list = StatusList {
            bits: 9,
            lst: encode_compressed(&[0x00, 0x01]).unwrap(),
        };
        assert!(matches!(
            invalid_bits_list.update(vec![entry(1, Status::Invalid)]),
            Err(StatusListError::CorruptStoredList(_))
        ));
    }

    #[test]
    fn create_empty_yields_zlib_compressed_empty_list() {
        let result = StatusList::create(Vec::new()).unwrap();
        assert_eq!(result.bits, 1);
        assert!(!result.lst.is_empty());
        assert_eq!(decompress(&result.lst), Vec::<u8>::new());
    }

    #[test]
    fn empty_list_zlib_stream_inflates_with_standard_decoder() {
        let result = StatusList::create(Vec::new()).unwrap();
        let compressed = base64url::decode(&result.lst).unwrap();
        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut inflated = Vec::new();

        decoder.read_to_end(&mut inflated).unwrap();

        assert!(inflated.is_empty());
    }

    #[test]
    fn generated_bits_are_always_draft_21_widths() {
        for status in [
            Status::Valid,
            Status::Invalid,
            Status::Suspended,
            Status::ApplicationSpecific(3),
            Status::ApplicationSpecific(15),
            Status::ApplicationSpecific(16),
            Status::ApplicationSpecific(255),
        ] {
            let result = StatusList::create(vec![entry(0, status)]).unwrap();
            assert_allowed_bits(result.bits);
        }

        let original = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        for status in [
            Status::Invalid,
            Status::Suspended,
            Status::ApplicationSpecific(3),
            Status::ApplicationSpecific(15),
            Status::ApplicationSpecific(16),
            Status::ApplicationSpecific(255),
        ] {
            let result = original.update(vec![entry(1, status)]).unwrap();
            assert_allowed_bits(result.bits);
        }
    }

    #[test]
    fn create_rejects_negative_index() {
        let updates = vec![entry(-1, Status::Valid)];
        assert!(matches!(
            StatusList::create(updates),
            Err(StatusListError::InvalidIndex)
        ));
    }

    #[test]
    fn update_rejects_negative_index() {
        let list = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        assert!(matches!(
            list.update(vec![entry(-5, Status::Invalid)]),
            Err(StatusListError::InvalidIndex)
        ));
    }

    #[test]
    fn update_with_no_entries_is_a_noop() {
        let list = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        let updated = list.update(vec![]).unwrap();
        assert_eq!(list, updated);
    }

    #[test]
    fn update_on_empty_created_list_works_end_to_end() {
        let list = StatusList::create(vec![]).unwrap();
        let updated = list.update(vec![entry(0, Status::Invalid)]).unwrap();
        assert_eq!(updated.bits, 1);
        assert!(!updated.lst.is_empty());
    }
}
