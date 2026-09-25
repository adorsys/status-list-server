//! Status list domain models, compressed bitpack serialization, and business operations.

use crate::domain::models::credential::Issuer;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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
    #[error("duplicate status index {index} in statuses array")]
    DuplicateIndex { index: i32 },
    #[error("status index {index} is outside the fixed status list size {size}")]
    IndexOutOfRange { index: i32, size: u32 },
    #[error("status list does not have enough unallocated indices")]
    AllocationExhausted,
    /// The issuer already holds its configured maximum number of status lists.
    #[error("issuer has {count} status lists, reaching the configured maximum of {max}")]
    QuotaExceeded { count: u64, max: u64 },
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

/// One page of published status list URIs, in `list_id` order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusListUriPage {
    /// `sub` URIs of the lists on this page.
    pub status_lists: Vec<String>,
    /// `list_id` of the last list on this page; `None` on the last page.
    pub next_after: Option<String>,
}

impl StatusListUriPage {
    /// Builds a page from `(list_id, sub)` rows fetched with `limit + 1`; the
    /// extra row only signals that another page exists.
    pub fn from_rows(mut rows: Vec<(String, String)>, limit: usize) -> Self {
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let (mut list_ids, status_lists): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
        Self {
            status_lists,
            next_after: list_ids.pop().filter(|_| has_more),
        }
    }
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
    /// Fixed entry count requested at publish time. `None` preserves legacy,
    /// grow-on-write lists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    /// Default status used to pre-initialise fixed-size lists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_status: Option<Status>,
}

impl StatusList {
    pub fn create(status_updates: Vec<StatusEntry>) -> Result<Self, StatusListError> {
        Self::create_with_options(status_updates, None, Status::Valid)
    }

    pub fn create_with_options(
        status_updates: Vec<StatusEntry>,
        size: Option<u32>,
        default_status: Status,
    ) -> Result<Self, StatusListError> {
        validate_unique_indices(&status_updates)?;
        if let Some(size) = size {
            validate_within_size(&status_updates, size)?;
        }

        if status_updates.is_empty() {
            if let Some(size) = size {
                let bits = determine_bits_for_values(&[default_status.clone()], None)?;
                let rounded_size = round_size_to_byte_boundary(size, bits)?;
                let mut status_array = vec![0u8; bytes_for_entries(rounded_size, bits)];
                fill_status_array(&mut status_array, rounded_size, bits, &default_status)?;
                return Ok(Self {
                    bits: bits as u8,
                    lst: encode_compressed(&status_array)?,
                    size: Some(rounded_size),
                    default_status: Some(default_status),
                });
            }
            return Ok(Self {
                bits: 1,
                lst: encode_compressed(&[])?,
                size: None,
                default_status: None,
            });
        }

        let bits = determine_bits_with_default(
            &status_updates,
            size.as_ref().map(|_| &default_status),
            None,
        )?;
        let rounded_size = size
            .map(|size| round_size_to_byte_boundary(size, bits))
            .transpose()?;
        let len = if let Some(rounded_size) = rounded_size {
            bytes_for_entries(rounded_size, bits)
        } else {
            calculate_array_size(&status_updates, bits)?
        };
        let mut status_array = vec![0u8; len];
        if let Some(rounded_size) = rounded_size {
            fill_status_array(&mut status_array, rounded_size, bits, &default_status)?;
        }
        apply_updates(&mut status_array, &status_updates, bits)?;
        Ok(Self {
            bits: bits as u8,
            lst: encode_compressed(&status_array)?,
            size: rounded_size,
            default_status: rounded_size.map(|_| default_status),
        })
    }

    pub fn update(&self, status_updates: Vec<StatusEntry>) -> Result<Self, StatusListError> {
        if status_updates.is_empty() {
            return Ok(self.clone());
        }

        validate_unique_indices(&status_updates)?;
        if let Some(size) = self.size {
            validate_within_size(&status_updates, size)?;
        }
        let old_bits = self.bits as usize;
        // Draft-21 only permits 1, 2, 4, or 8. Older rows with wider values
        // are repacked when their stored values are still representable.
        if validate_bits(old_bits).is_err() {
            return self.repack_legacy_width()?.update(status_updates);
        }
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
            // The pre-existing entries are re-emitted first and the caller's
            // updates appended after them: an index present in both must end up
            // with the *update's* value, so this widening path relies on
            // [`apply_updates`] letting the last write win for any given index.
            full_statuses.extend(status_updates);
            return Self::create_with_bits(
                full_statuses,
                new_bits,
                self.size,
                self.default_status.clone(),
            );
        }

        let required_len = calculate_array_size(&status_updates, old_bits)?;
        if required_len > status_array.len() {
            status_array.resize(required_len, 0);
        }
        apply_updates(&mut status_array, &status_updates, old_bits)?;
        Ok(Self {
            bits: self.bits,
            lst: encode_compressed(&status_array)?,
            size: self.size,
            default_status: self.default_status.clone(),
        })
    }

    fn create_with_bits(
        status_updates: Vec<StatusEntry>,
        bits: usize,
        size: Option<u32>,
        default_status: Option<Status>,
    ) -> Result<Self, StatusListError> {
        debug_assert!(matches!(bits, 1 | 2 | 4 | 8));
        let len = if let Some(size) = size {
            bytes_for_entries(size, bits)
        } else {
            calculate_array_size(&status_updates, bits)?
        };
        let mut status_array = vec![0u8; len];
        if let (Some(size), Some(default_status)) = (size, default_status.as_ref()) {
            fill_status_array(&mut status_array, size, bits, default_status)?;
        }
        apply_updates(&mut status_array, &status_updates, bits)?;
        Ok(Self {
            bits: bits as u8,
            lst: encode_compressed(&status_array)?,
            size,
            default_status,
        })
    }

    /// The `lst` as it must appear in a token: the stored value, or a valid
    /// zlib-compressed empty stream for legacy `lst = ""` rows.
    pub(crate) fn token_lst(&self) -> Result<(u8, String), StatusListError> {
        if validate_bits(self.bits as usize).is_err() {
            let normalized = self.repack_legacy_width()?;
            return normalized.token_lst();
        }
        let lst = if self.lst.is_empty() {
            encode_compressed(&[])?
        } else {
            self.lst.clone()
        };
        Ok((self.bits, lst))
    }

    /// Raw compressed bytes for the Draft-21 §4.3 CBOR byte string.
    pub(crate) fn token_lst_bytes(&self) -> Result<(u8, Vec<u8>), StatusListError> {
        let (bits, lst) = self.token_lst()?;
        let compressed = base64url::decode(&lst).map_err(|err| {
            StatusListError::CorruptStoredList(format!("Invalid lst encoding: {err}"))
        })?;

        Ok((bits, compressed))
    }

    fn repack_legacy_width(&self) -> Result<Self, StatusListError> {
        let bits = self.bits as usize;
        let status_array = decode_compressed(&self.lst)?;
        let statuses = decode_status_array_legacy_width(&status_array, bits)?;
        let updates = statuses
            .into_iter()
            .enumerate()
            .map(|(index, status)| StatusEntry {
                index: index as i32,
                status,
            })
            .collect();
        Self::create(updates)
    }
}

pub(crate) fn unsupported_status_value_message(value: u32) -> String {
    format!(
        "status value {value} is not a supported Draft-21 status type; accepted values are 0-3 and 12-15"
    )
}

fn status_value(status: &Status) -> Result<u32, StatusListError> {
    match status {
        Status::Valid => Ok(0),
        Status::Invalid => Ok(1),
        Status::Suspended => Ok(2),
        Status::ApplicationSpecific(value) if is_application_specific_status_value(*value) => {
            Ok(*value)
        }
        Status::ApplicationSpecific(value) => Err(StatusListError::InvalidStatusList(
            unsupported_status_value_message(*value),
        )),
    }
}

/// Reject duplicate indices within a single update payload.
///
/// Only the caller-supplied entries are validated, never the entries a widening
/// [`StatusList::update`] re-derives from the existing list: overlapping an
/// already-set index is a legitimate "change that position", so this check is
/// scoped to the request itself.
pub(crate) fn validate_unique_indices(
    status_updates: &[StatusEntry],
) -> Result<(), StatusListError> {
    let mut seen_indices: HashSet<i32> = HashSet::new();
    for entry in status_updates {
        if !seen_indices.insert(entry.index) {
            return Err(StatusListError::DuplicateIndex { index: entry.index });
        }
    }
    Ok(())
}

pub(crate) fn is_application_specific_status_value(value: u32) -> bool {
    matches!(value, 3 | 12..=15)
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
    determine_bits_with_default(status_updates, None, original_bits)
}

fn determine_bits_with_default(
    status_updates: &[StatusEntry],
    default_status: Option<&Status>,
    original_bits: Option<usize>,
) -> Result<usize, StatusListError> {
    let max_status_value = status_updates
        .iter()
        .map(|entry| status_value(&entry.status))
        .chain(default_status.map(status_value).into_iter())
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
        value => {
            return Err(StatusListError::InvalidStatusList(
                unsupported_status_value_message(value),
            ));
        }
    };

    Ok(original_bits.unwrap_or(required_bits).max(required_bits))
}

fn determine_bits_for_values(
    statuses: &[Status],
    original_bits: Option<usize>,
) -> Result<usize, StatusListError> {
    let updates = statuses
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, status)| StatusEntry {
            index: index as i32,
            status,
        })
        .collect::<Vec<_>>();
    determine_bits(&updates, original_bits)
}

fn round_size_to_byte_boundary(size: u32, bits: usize) -> Result<u32, StatusListError> {
    validate_bits(bits)?;
    let entries_per_byte = 8 / bits;
    let size = usize::try_from(size).map_err(|_| {
        StatusListError::InvalidStatusList("status list size does not fit usize".to_string())
    })?;
    let rounded = if size == 0 {
        0
    } else {
        size.next_multiple_of(entries_per_byte)
    };
    u32::try_from(rounded).map_err(|_| {
        StatusListError::InvalidStatusList("rounded status list size exceeds u32".to_string())
    })
}

fn bytes_for_entries(entries: u32, bits: usize) -> usize {
    (entries as usize * bits).div_ceil(8)
}

fn validate_within_size(status_updates: &[StatusEntry], size: u32) -> Result<(), StatusListError> {
    for entry in status_updates {
        let Ok(index) = u32::try_from(entry.index) else {
            continue;
        };
        if index >= size {
            return Err(StatusListError::IndexOutOfRange {
                index: entry.index,
                size,
            });
        }
    }
    Ok(())
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

fn fill_status_array(
    status_array: &mut [u8],
    entries: u32,
    bits: usize,
    status: &Status,
) -> Result<(), StatusListError> {
    if entries == 0 {
        return Ok(());
    }
    let updates = (0..entries)
        .map(|index| StatusEntry {
            index: index as i32,
            status: status.clone(),
        })
        .collect::<Vec<_>>();
    apply_updates(status_array, &updates, bits)
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
    if encoded.is_empty() {
        return Ok(Vec::new());
    }

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
    decode_status_array_values(array, bits)
}

fn decode_status_array_legacy_width(
    array: &[u8],
    bits: usize,
) -> Result<Vec<Status>, StatusListError> {
    if bits == 0 {
        return Err(StatusListError::CorruptStoredList(
            "stored status list uses unsupported bit width 0; expected one of 1, 2, 4, or 8"
                .to_string(),
        ));
    }
    decode_status_array_values(array, bits)
}

fn decode_status_array_values(array: &[u8], bits: usize) -> Result<Vec<Status>, StatusListError> {
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
            value if is_application_specific_status_value(value) => {
                Status::ApplicationSpecific(value)
            }
            value => {
                return Err(StatusListError::CorruptStoredList(format!(
                    "stored status list contains reserved status value {value}; reserved values must not be re-encoded as application-specific"
                )));
            }
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
        let statuses = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
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
        assert_eq!(decompress(&result.lst), vec![0xC9, 0x44, 0xF9]);
        assert_eq!(result.lst, "eNo76fITAAPfAgc");
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
                status: Status::ApplicationSpecific(15),
            }])
            .unwrap();

        assert_eq!(updated.bits, 4);
        let statuses = decode_status_array(&decompress(&updated.lst), 4).unwrap();
        assert_eq!(statuses[0], Status::Valid);
        assert_eq!(statuses[1], Status::ApplicationSpecific(15));
    }

    #[test]
    fn update_existing_eight_bit_list_keeps_legacy_width() {
        let updated = from_raw(&[0, 15], 8)
            .update(vec![entry(0, Status::Invalid)])
            .unwrap();

        assert_eq!(updated.bits, 8);
        assert_eq!(decompress(&updated.lst), vec![1, 15]);
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

    #[test]
    fn create_pre_sized_list_with_non_zero_default() {
        let result = StatusList::create_with_options(vec![], Some(5), Status::Invalid).unwrap();

        assert_eq!(result.bits, 1);
        assert_eq!(result.size, Some(8));
        assert_eq!(result.default_status, Some(Status::Invalid));
        assert_eq!(decompress(&result.lst), vec![0b1111_1111]);
    }

    #[test]
    fn update_rejects_index_beyond_fixed_size() {
        let list = StatusList::create_with_options(vec![], Some(8), Status::Valid).unwrap();

        let err = list.update(vec![entry(8, Status::Invalid)]).unwrap_err();

        assert!(matches!(
            err,
            StatusListError::IndexOutOfRange { index: 8, size: 8 }
        ));
    }

    fn from_raw(bytes: &[u8], bits: u8) -> StatusList {
        StatusList {
            bits,
            lst: encode_compressed(bytes).unwrap(),
            size: None,
            default_status: None,
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
    fn four_bit_app_specific_exact_layout() {
        let result = StatusList::create(vec![
            entry(0, Status::Valid),
            entry(1, Status::Invalid),
            entry(2, Status::Suspended),
            entry(3, Status::ApplicationSpecific(15)),
        ])
        .unwrap();
        assert_eq!(result.bits, 4);
        let raw = decompress(&result.lst);
        assert_eq!(raw.len(), 2, "4 entries * 4 bits = 2 bytes");
        let statuses = decode_status_array(&raw, 4).unwrap();
        assert_eq!(statuses[0], Status::Valid);
        assert_eq!(statuses[1], Status::Invalid);
        assert_eq!(statuses[2], Status::Suspended);
        assert_eq!(statuses[3], Status::ApplicationSpecific(15));
    }

    #[test]
    fn app_specific_registry_values_roundtrip() {
        let result = StatusList::create(vec![
            entry(0, Status::ApplicationSpecific(3)),
            entry(1, Status::ApplicationSpecific(12)),
            entry(2, Status::ApplicationSpecific(13)),
            entry(3, Status::ApplicationSpecific(14)),
            entry(4, Status::ApplicationSpecific(15)),
        ])
        .unwrap();
        let statuses = decode_status_array(&decompress(&result.lst), result.bits as usize).unwrap();
        assert_eq!(result.bits, 4);
        assert_eq!(statuses[0], Status::ApplicationSpecific(3));
        assert_eq!(statuses[1], Status::ApplicationSpecific(12));
        assert_eq!(statuses[2], Status::ApplicationSpecific(13));
        assert_eq!(statuses[3], Status::ApplicationSpecific(14));
        assert_eq!(statuses[4], Status::ApplicationSpecific(15));
    }

    #[test]
    fn create_rejects_unsupported_status_values() {
        for value in [256u32, 512, 4096] {
            let result = StatusList::create(vec![entry(0, Status::ApplicationSpecific(value))]);
            assert!(
                matches!(result, Err(StatusListError::InvalidStatusList(ref msg)) if msg.contains("not a supported Draft-21 status type") && msg.contains("0-3 and 12-15")),
                "value {value} must be rejected"
            );
        }
    }

    #[test]
    fn reserved_status_values_are_rejected() {
        for value in [4u32, 5, 11, 16, 100, 255] {
            let result = StatusList::create(vec![entry(0, Status::ApplicationSpecific(value))]);
            assert!(
                matches!(result, Err(StatusListError::InvalidStatusList(ref msg)) if msg.contains("not a supported Draft-21 status type")),
                "value {value} must be rejected as reserved"
            );
        }
    }

    #[test]
    fn application_specific_registry_values_are_supported() {
        for (value, bits) in [(3u32, 2u8), (12, 4), (13, 4), (14, 4), (15, 4)] {
            let result =
                StatusList::create(vec![entry(0, Status::ApplicationSpecific(value))]).unwrap();
            assert_eq!(result.bits, bits);
            assert_allowed_bits(result.bits);
        }
    }

    #[test]
    fn update_rejects_unsupported_status_values() {
        let original = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        let result = original.update(vec![entry(0, Status::ApplicationSpecific(256))]);
        assert!(
            matches!(result, Err(StatusListError::InvalidStatusList(ref msg)) if msg.contains("not a supported Draft-21 status type"))
        );
    }

    #[test]
    fn update_rejects_reserved_status_values() {
        let original = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        let result = original.update(vec![entry(0, Status::ApplicationSpecific(16))]);
        assert!(
            matches!(result, Err(StatusListError::InvalidStatusList(ref msg)) if msg.contains("not a supported Draft-21 status type"))
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

        let statuses = decode_status_array(&[15u8], 8).unwrap();
        assert_eq!(statuses, vec![Status::ApplicationSpecific(15)]);
    }

    #[test]
    fn update_over_corrupt_lst_is_state_error_not_request_error() {
        let bad_base64 = StatusList {
            bits: 1,
            lst: "not valid base64!!".to_string(),
            size: None,
            default_status: None,
        };
        assert!(matches!(
            bad_base64.update(vec![entry(0, Status::Invalid)]),
            Err(StatusListError::CorruptStoredList(_))
        ));

        let bad_zlib = StatusList {
            bits: 1,
            lst: base64url::encode([0xFF, 0xFF, 0xFF, 0xFF]),
            size: None,
            default_status: None,
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
            size: None,
            default_status: None,
        };
        assert!(matches!(
            invalid_bits_list.update(vec![entry(1, Status::Invalid)]),
            Err(StatusListError::CorruptStoredList(_))
        ));
    }

    #[test]
    fn update_legacy_empty_lst_upgrades_to_compressed_empty_stream() {
        let legacy_empty = StatusList {
            bits: 1,
            lst: String::new(),
            size: None,
            default_status: None,
        };

        let updated = legacy_empty
            .update(vec![entry(0, Status::Invalid)])
            .unwrap();

        assert_eq!(updated.bits, 1);
        assert!(!updated.lst.is_empty());
        assert_eq!(decompress(&updated.lst), vec![0b0000_0001]);
    }

    #[test]
    fn decode_rejects_reserved_stored_status_values_as_corruption() {
        for (raw, bits, value) in [([0x04], 4usize, 4u32), ([0x10], 8, 16)] {
            let result = decode_status_array(&raw, bits);
            assert!(
                matches!(result, Err(StatusListError::CorruptStoredList(ref msg)) if msg.contains(&format!("reserved status value {value}"))),
                "reserved stored value {value} must be stored-state corruption"
            );
        }
    }

    #[test]
    fn token_lst_repacks_representable_legacy_width() {
        let legacy_representable = StatusList {
            bits: 9,
            lst: encode_compressed(&[15, 0]).unwrap(),
            size: None,
            default_status: None,
        };

        let (bits, lst) = legacy_representable.token_lst().unwrap();

        assert_eq!(bits, 4);
        assert_eq!(decompress(&lst), vec![15]);
    }

    #[test]
    fn update_repacks_representable_legacy_width() {
        let legacy_representable = StatusList {
            bits: 9,
            lst: encode_compressed(&[15, 0]).unwrap(),
            size: None,
            default_status: None,
        };

        let updated = legacy_representable
            .update(vec![entry(1, Status::Invalid)])
            .unwrap();

        assert_eq!(updated.bits, 4);
        assert_eq!(decompress(&updated.lst), vec![0x1F]);
    }

    #[test]
    fn token_lst_rejects_unrepresentable_legacy_width_values() {
        let legacy_unrepresentable = StatusList {
            bits: 9,
            lst: encode_compressed(&[0, 1]).unwrap(),
            size: None,
            default_status: None,
        };

        assert!(matches!(
            legacy_unrepresentable.token_lst(),
            Err(StatusListError::CorruptStoredList(_))
        ));
    }

    #[test]
    fn token_lst_normalizes_legacy_empty_lst() {
        let legacy_empty = StatusList {
            bits: 1,
            lst: String::new(),
            size: None,
            default_status: None,
        };

        let (bits, lst) = legacy_empty.token_lst().unwrap();

        assert_eq!(bits, 1);
        assert!(!lst.is_empty());
        assert_eq!(decompress(&lst), Vec::<u8>::new());
    }

    #[test]
    fn create_empty_yields_zlib_compressed_empty_list() {
        let result = StatusList::create(Vec::new()).unwrap();
        assert_eq!(result.bits, 1);
        assert!(!result.lst.is_empty());
        assert_eq!(result.lst, "eNoDAAAAAAE");
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
    fn create_rejects_duplicate_indices() {
        let updates = vec![entry(0, Status::Valid), entry(0, Status::Invalid)];
        assert!(matches!(
            StatusList::create(updates),
            Err(StatusListError::DuplicateIndex { index: 0 })
        ));
    }

    #[test]
    fn update_rejects_duplicate_indices() {
        let list = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        let result = list.update(vec![entry(1, Status::Invalid), entry(1, Status::Suspended)]);
        assert!(matches!(
            result,
            Err(StatusListError::DuplicateIndex { index: 1 })
        ));
    }

    /// Duplicate detection runs before the negative-index check, so a payload
    /// whose duplicate is also negative must report `DuplicateIndex`, never
    /// `InvalidIndex`. This pins that ordering in both create and update.
    #[test]
    fn duplicate_negative_index_reports_duplicate_before_invalid() {
        let duplicates = vec![entry(-1, Status::Valid), entry(-1, Status::Invalid)];

        assert!(matches!(
            StatusList::create(duplicates.clone()),
            Err(StatusListError::DuplicateIndex { index: -1 })
        ));

        let list = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        assert!(matches!(
            list.update(duplicates),
            Err(StatusListError::DuplicateIndex { index: -1 })
        ));
    }

    /// Duplicate detection must not depend on the duplicates being adjacent:
    /// a duplicate with other distinct indices in between is still rejected.
    #[test]
    fn create_rejects_non_adjacent_duplicate_indices() {
        let result = StatusList::create(vec![
            entry(0, Status::Valid),
            entry(1, Status::Invalid),
            entry(0, Status::Valid),
        ]);
        assert!(matches!(
            result,
            Err(StatusListError::DuplicateIndex { index: 0 })
        ));
    }

    /// Re-sending the current value on a legacy-width row must still repack the
    /// list to a supported width, so the result differs from the input. This
    /// keeps the service's no-op guard (which compares whole lists) from
    /// swallowing that one-time normalisation write.
    #[test]
    fn update_value_identical_on_legacy_width_repacks() {
        let legacy = from_raw(&[8, 0], 3);
        let updated = legacy
            .update(vec![entry(1, Status::Invalid)])
            .expect("re-sending the current value on a legacy row must succeed");

        assert_eq!(
            updated.bits, 1,
            "the legacy 3-bit row must be repacked to a supported 1-bit row"
        );
        assert_eq!(
            decompress(&updated.lst),
            vec![0b0000_0010],
            "index 1 = Invalid must survive the repack at 1 bit"
        );
        assert_ne!(
            updated, legacy,
            "the repacked row must differ from the legacy input so a write happens"
        );
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

    fn uri_rows(ids: &[&str]) -> Vec<(String, String)> {
        ids.iter()
            .map(|id| (id.to_string(), format!("https://example.com/{id}")))
            .collect()
    }

    #[test]
    fn uri_page_with_extra_row_points_at_last_returned_list() {
        let page = StatusListUriPage::from_rows(uri_rows(&["a", "b", "c"]), 2);
        assert_eq!(
            page.status_lists,
            ["https://example.com/a", "https://example.com/b"]
        );
        assert_eq!(page.next_after.as_deref(), Some("b"));
    }

    #[test]
    fn uri_page_without_extra_row_is_the_last() {
        let page = StatusListUriPage::from_rows(uri_rows(&["a", "b"]), 2);
        assert_eq!(page.status_lists.len(), 2);
        assert_eq!(page.next_after, None);

        let empty = StatusListUriPage::from_rows(Vec::new(), 2);
        assert!(empty.status_lists.is_empty());
        assert_eq!(empty.next_after, None);
    }
}
