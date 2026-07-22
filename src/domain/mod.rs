//! Framework-independent business concepts for status-list operations.
//!
//! This module deliberately contains no HTTP, database, cache, or cloud SDK
//! dependency.  Adapters translate these values at the boundary.
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("invalid status list index")]
    InvalidIndex,
    #[error("{0}")]
    InvalidStatusList(String),
    /// The stored `lst` could not be decoded — corrupt persisted state, not a
    /// caller error. Surfaces as 500 so data corruption is alerted, not blamed
    /// on the client. Only produced while decoding an existing list (update).
    #[error("corrupt stored status list: {0}")]
    CorruptStoredList(String),
    #[error("invalid public JWK: {0}")]
    InvalidPublicJwk(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicJwk(pub Vec<u8>);

impl PublicJwk {
    /// Create public JWK bytes from UTF-8 JSON.
    ///
    /// The bytes stay opaque to the domain after construction, but they must be
    /// a syntactically valid JSON object so every adapter can safely parse them
    /// as a serialized JWK at the boundary.
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, DomainError> {
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|err| DomainError::InvalidPublicJwk(format!("expected UTF-8 JSON: {err}")))?;
        if !value.is_object() {
            return Err(DomainError::InvalidPublicJwk(
                "expected a JSON object".to_string(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub issuer: Issuer,
    /// Opaque public JWK document bytes. JSON parsing/validation belongs to
    /// inbound or persistence adapters at the boundary.
    pub public_key: PublicJwk,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Valid,
    Invalid,
    Suspended,
    /// Application-specific values start at 256. Values 3..=255 are rejected by
    /// deliberate *server policy* (not a spec requirement): it keeps the
    /// standard 1-/2-bit lists limited to the three standard statuses and
    /// sidesteps ambiguity with the compact bit-width table. This threshold is
    /// pinned by test and treated as spec-evolution surface, not a knob to
    /// loosen as part of unrelated cleanup.
    ApplicationSpecific(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusEntry {
    pub index: i32,
    pub status: Status,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusList {
    pub bits: u8,
    pub lst: String,
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

/// Convert the status enum to its packed integer representation.
///
/// `ApplicationSpecific` is accepted only for values `>= 256`; lower
/// non-standard values are rejected by server policy (see [`Status`]), not by
/// any spec-level reservation, and must not enter newly created or updated
/// lists.
fn status_value(status: &Status) -> Result<u32, DomainError> {
    match status {
        Status::Valid => Ok(0),
        Status::Invalid => Ok(1),
        Status::Suspended => Ok(2),
        Status::ApplicationSpecific(value) if *value >= 256 => Ok(*value),
        Status::ApplicationSpecific(_) => Err(DomainError::InvalidStatusList(
            "ApplicationSpecific value must be >= 256".to_string(),
        )),
    }
}

fn determine_bits(
    status_updates: &[StatusEntry],
    original_bits: Option<usize>,
) -> Result<usize, DomainError> {
    let max_status_value = status_updates
        .iter()
        .map(|entry| status_value(&entry.status))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or_else(|| {
            DomainError::InvalidStatusList("Failed to determine max status value".to_string())
        })?;

    let required_bits = match max_status_value {
        0 | 1 => 1,
        2 | 3 => 2,
        4..=15 => 4,
        16..=255 => 8,
        _ => {
            let bits_needed = (max_status_value as usize + 1)
                .next_power_of_two()
                .trailing_zeros();
            if bits_needed == 0 {
                return Err(DomainError::InvalidStatusList(
                    "Status value too large".to_string(),
                ));
            }
            bits_needed as usize
        }
    };

    Ok(original_bits.unwrap_or(required_bits).max(required_bits))
}

fn calculate_array_size(status_updates: &[StatusEntry], bits: usize) -> Result<usize, DomainError> {
    if status_updates.is_empty() {
        return Ok(0);
    }

    let max_index = status_updates
        .iter()
        .map(|update| update.index)
        .max()
        .ok_or_else(|| {
            DomainError::InvalidStatusList("Failed to determine max index".to_string())
        })?;

    if max_index < 0 {
        return Err(DomainError::InvalidIndex);
    }

    let end_bit = (max_index as usize) * bits + bits - 1;
    Ok(end_bit / 8 + 1)
}

/// Write status values into the little-endian bit-packed status array.
///
/// Each entry occupies `bits` consecutive bits. The first bit of an entry is
/// placed at `index * bits`, with bit offset `0` meaning the least-significant
/// bit of the byte. When an entry spans multiple bytes, the low-order bits are
/// written into the first byte and the remaining bits continue into subsequent
/// bytes. Before writing, the target bits are cleared so updates overwrite only
/// their own slot.
fn apply_updates(
    status_array: &mut [u8],
    status_updates: &[StatusEntry],
    bits: usize,
) -> Result<(), DomainError> {
    for update in status_updates {
        if update.index < 0 {
            return Err(DomainError::InvalidIndex);
        }

        let idx = update.index as usize;
        let bit_position = idx * bits;
        let byte_index = bit_position / 8;
        let bit_offset = bit_position % 8;

        if byte_index >= status_array.len() {
            return Err(DomainError::InvalidStatusList(
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

fn encode_compressed(bytes: &[u8]) -> Result<String, DomainError> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(bytes).map_err(|err| {
        DomainError::InvalidStatusList(format!("Failed to compress status list: {err}"))
    })?;
    encoder.finish().map(base64url::encode).map_err(|err| {
        DomainError::InvalidStatusList(format!("Failed to finish status list compression: {err}"))
    })
}

fn decode_compressed(encoded: &str) -> Result<Vec<u8>, DomainError> {
    let bytes = base64url::decode(encoded)
        .map_err(|err| DomainError::CorruptStoredList(format!("Invalid lst encoding: {err}")))?;
    let mut decoder = flate2::read::ZlibDecoder::new(&bytes[..]);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).map_err(|err| {
        DomainError::CorruptStoredList(format!("Failed to decompress status list: {err}"))
    })?;
    Ok(decoded)
}

/// Decode the `bits`-wide status slots packed into `array`.
///
/// After the well-formedness guard below, a valid buffer holds a whole number
/// of entries plus at most 7 bits of ceil-to-byte padding. Decoding walks every
/// whole slot the buffer can hold (`array.len() * 8 / bits`), so a
/// non-byte-aligned list decodes its trailing sub-byte padding as extra `Valid`
/// (0) entries — the read-side mirror of the floor-division bit-packing in
/// [`apply_updates`]. This has one visible effect: when [`StatusList::update`]
/// widens a list it re-materializes those padding slots as explicit entries, so
/// a widened list's logical length rounds up to the old byte boundary. Those
/// slots decode as `Valid` either way, so it is behavior-preserving from the
/// retired `lst_gen` encoder, not a correctness change — but it does grow a
/// sparse list on widening. Kept intentionally; see the widening branch and the
/// `update_widening_pads_to_byte_boundary` test.
fn decode_status_array(array: &[u8], bits: usize) -> Result<Vec<Status>, DomainError> {
    // Well-formedness guard against corrupt/truncated persisted state.
    //
    // A correct encoder packs entries tightly and ceil-pads only *within* the
    // final byte, so a well-formed array leaves strictly fewer than 8 unused
    // bits for its width: `array.len() * 8 % bits < 8` always holds. If a whole
    // trailing byte or more is unused, the row was truncated mid-list (or is
    // otherwise corrupt) and must not be decoded silently. Floor division below
    // would simply drop the missing entries; on the width-expansion
    // reconstruction path in `update`, those dropped statuses would reappear as
    // `Valid` — silently un-revoking credentials and returning 200. Refuse it
    // as corrupt persisted state (-> 500), never a caller error.
    //
    // This catches every truncation detectable from `(array, bits)` alone: for
    // `bits >= 9` the unused-byte signature is unambiguous. Sub-byte widths
    // (where `bits` divides 8) leave no detectable gap — a shorter array is
    // indistinguishable from a legitimately shorter list — so that residue is a
    // format limitation (the format does not persist the entry count), not
    // something this guard can close.
    if array.len() * 8 % bits >= 8 {
        return Err(DomainError::CorruptStoredList(format!(
            "stored status array of {} bytes leaves an unused trailing byte at {bits}-bit width",
            array.len()
        )));
    }

    let mut statuses = Vec::new();
    // Floor division yields only whole entries; combined with the guard above,
    // for every `i` in range `(i + 1) * bits <= array.len() * 8`, so the inner
    // `break` below is unreachable and each entry is fully in-bounds.
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
            value if value >= 256 => Status::ApplicationSpecific(value),
            _ => {
                return Err(DomainError::CorruptStoredList(
                    "Invalid status value in existing list".to_string(),
                ));
            }
        });
    }
    Ok(statuses)
}

impl StatusList {
    /// Create a compressed status list from sparse status entries.
    ///
    /// The domain stores `lst` using the Status List Token format: status
    /// values are bit-packed least-significant-bit first, compressed with zlib,
    /// then base64url encoded without padding. The `bits` width is the minimum
    /// required by the highest status value, except that `ApplicationSpecific`
    /// values may require more than eight bits.
    pub fn create(status_updates: Vec<StatusEntry>) -> Result<Self, DomainError> {
        if status_updates.is_empty() {
            return Ok(Self {
                bits: 1,
                lst: String::new(),
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

    /// Apply updates while preserving the existing compression and packing
    /// rules.
    ///
    /// Existing lists are decoded from base64url+zlib, modified in-place when
    /// the current bit width is sufficient, and re-created at a wider bit width
    /// when a new status value needs more bits. This keeps previously stored
    /// statuses stable while allowing spec evolution to introduce larger custom
    /// status values.
    pub fn update(&self, status_updates: Vec<StatusEntry>) -> Result<Self, DomainError> {
        if status_updates.is_empty() {
            return Ok(self.clone());
        }

        let old_bits = self.bits as usize;
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
    ) -> Result<Self, DomainError> {
        let len = calculate_array_size(&status_updates, bits)?;
        let mut status_array = vec![0u8; len];
        apply_updates(&mut status_array, &status_updates, bits)?;
        Ok(Self {
            bits: bits as u8,
            lst: encode_compressed(&status_array)?,
        })
    }
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
                    _ => Status::ApplicationSpecific(256),
                },
            })
            .collect();

        let result = StatusList::create(updates).unwrap();

        assert_eq!(result.bits, 9);
        assert_eq!(
            decode_status_array(&decompress(&result.lst), 9)
                .unwrap()
                .len(),
            12
        );
    }

    #[test]
    fn update_status_list_bumps_bit_width_for_application_specific_values() {
        let original = StatusList::create(vec![StatusEntry {
            index: 0,
            status: Status::Valid,
        }])
        .unwrap();

        let updated = original
            .update(vec![StatusEntry {
                index: 1,
                status: Status::ApplicationSpecific(256),
            }])
            .unwrap();

        assert_eq!(updated.bits, 9);
        let statuses = decode_status_array(&decompress(&updated.lst), 9).unwrap();
        assert_eq!(statuses[0], Status::Valid);
        assert_eq!(statuses[1], Status::ApplicationSpecific(256));
    }

    // The tests below are ported from the retired `utils::lst_gen` suite so the
    // live encoder carries the exact same byte-level guarantees, including the
    // §4.1/§4.2 worked vectors. Decompress-direction is the backend-independent
    // guarantee; encode-direction pins are coupled to flate2's exact output.

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

    /// Pins the inherited widening behavior documented on `decode_status_array`:
    /// widening a non-byte-aligned list re-materializes the byte's unwritten
    /// slots as explicit `Valid` entries, so the logical length rounds up to the
    /// old byte boundary. Three real 1-bit entries occupy one byte (eight slots),
    /// so widening to 2 bits yields eight entries, not four. Behavior-preserving
    /// from the retired `lst_gen`; pinned so any future change to the decode loop
    /// is a conscious one.
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

        // Introduce a Suspended (value 2) at index 3, forcing a widen to 2 bits.
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
        // The five originally-unwritten slots are re-materialized as Valid.
        assert_eq!(statuses[4], Status::Valid);
        assert_eq!(statuses[7], Status::Valid);
    }

    #[test]
    fn nine_bit_app_specific_exact_layout() {
        let result = StatusList::create(vec![
            entry(0, Status::Valid),
            entry(1, Status::Invalid),
            entry(2, Status::Suspended),
            entry(3, Status::ApplicationSpecific(256)),
        ])
        .unwrap();
        assert_eq!(result.bits, 9, "value 256 requires 9 bits");
        let raw = decompress(&result.lst);
        assert_eq!(raw.len(), 5, "4 entries * 9 bits = 36 bits = 5 bytes");
        let statuses = decode_status_array(&raw, 9).unwrap();
        assert_eq!(statuses[0], Status::Valid);
        assert_eq!(statuses[1], Status::Invalid);
        assert_eq!(statuses[2], Status::Suspended);
        assert_eq!(statuses[3], Status::ApplicationSpecific(256));
    }

    #[test]
    fn app_specific_multibyte_roundtrip() {
        let result = StatusList::create(vec![
            entry(0, Status::ApplicationSpecific(512)),
            entry(3, Status::ApplicationSpecific(256)),
        ])
        .unwrap();
        let statuses = decode_status_array(&decompress(&result.lst), result.bits as usize).unwrap();
        assert_eq!(statuses[0], Status::ApplicationSpecific(512));
        assert_eq!(statuses[3], Status::ApplicationSpecific(256));
    }

    #[test]
    fn thirteen_bit_app_specific_at_offset_roundtrip() {
        let result = StatusList::create(vec![
            entry(0, Status::Invalid),
            entry(3, Status::ApplicationSpecific(4096)),
        ])
        .unwrap();
        assert_eq!(result.bits, 13, "value 4096 requires 13 bits (2^13 = 8192)");
        let statuses = decode_status_array(&decompress(&result.lst), result.bits as usize).unwrap();
        assert_eq!(statuses[0], Status::Invalid);
        assert_eq!(statuses[3], Status::ApplicationSpecific(4096));
    }

    #[test]
    fn create_rejects_app_specific_below_256() {
        for value in [3u32, 100, 255] {
            let result = StatusList::create(vec![entry(0, Status::ApplicationSpecific(value))]);
            assert!(
                matches!(result, Err(DomainError::InvalidStatusList(ref msg)) if msg.contains(">= 256")),
                "value {value} must be rejected"
            );
        }
    }

    #[test]
    fn update_rejects_app_specific_below_256() {
        let original = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        let result = original.update(vec![entry(0, Status::ApplicationSpecific(3))]);
        assert!(matches!(result, Err(DomainError::InvalidStatusList(_))));
    }

    #[test]
    fn decode_rejects_reserved_values() {
        // Values 3..=255 are reserved by the encoding table; a stored list
        // containing one is corrupt (state-caused, not caller-caused), whatever
        // the bit width — so it must surface as CorruptStoredList (-> 500).
        for (raw, bits) in [(vec![0b1110_0100u8], 2), (vec![3u8], 2), (vec![100u8], 8)] {
            let result = decode_status_array(&raw, bits);
            assert!(
                matches!(result, Err(DomainError::CorruptStoredList(_))),
                "value in {raw:?} at {bits} bits must be rejected as corrupt state"
            );
        }
    }

    #[test]
    fn update_over_corrupt_lst_is_state_error_not_request_error() {
        // Corrupt persisted `lst` must classify as CorruptStoredList (state,
        // -> 500), never InvalidStatusList (request, -> 400): the client's
        // update is well-formed; the stored data is not.
        let bad_base64 = StatusList {
            bits: 1,
            lst: "not valid base64!!".to_string(),
        };
        assert!(matches!(
            bad_base64.update(vec![entry(0, Status::Invalid)]),
            Err(DomainError::CorruptStoredList(_))
        ));

        // Valid base64url that is not valid zlib.
        let bad_zlib = StatusList {
            bits: 1,
            lst: base64url::encode([0xFF, 0xFF, 0xFF, 0xFF]),
        };
        assert!(matches!(
            bad_zlib.update(vec![entry(0, Status::Invalid)]),
            Err(DomainError::CorruptStoredList(_))
        ));
    }

    #[test]
    fn update_with_bad_request_value_stays_request_error() {
        // Complement to the above: a bad *request* value (reserved <256) over a
        // sound stored list stays InvalidStatusList (request, -> 400).
        let sound = StatusList::create(vec![entry(0, Status::Valid)]).unwrap();
        assert!(matches!(
            sound.update(vec![entry(0, Status::ApplicationSpecific(3))]),
            Err(DomainError::InvalidStatusList(_))
        ));
    }

    #[test]
    fn decode_accepts_legitimate_sub_byte_padding() {
        // A 2-byte array at 9 bits holds exactly one whole entry; the 7 trailing
        // bits are legitimate ceil-to-byte padding (< 1 byte) and are ignored,
        // not decoded or errored. Pins that the well-formedness guard in
        // decode_status_array does not false-positive on valid 9-/13-bit lists
        // whose byte length is not a multiple of `bits`.
        let one_entry_256 = vec![0x00, 0x01]; // value 256 packed LSB-first over bits 0..9
        let statuses = decode_status_array(&one_entry_256, 9).unwrap();
        assert_eq!(statuses, vec![Status::ApplicationSpecific(256)]);
    }

    #[test]
    fn decode_rejects_truncated_array_as_corrupt() {
        // A single byte at 9-bit width cannot hold even one whole entry (a
        // 9-bit entry needs two bytes), so the stored row is truncated. Decode
        // must refuse it as corrupt state (-> 500), never silently return zero
        // entries: on the width-expansion reconstruction path that would drop
        // every prior status and re-encode revoked credentials as Valid.
        let truncated = vec![0x00]; // 8 bits available, 9 required
        assert!(matches!(
            decode_status_array(&truncated, 9),
            Err(DomainError::CorruptStoredList(_))
        ));

        // A width-bumping update over a truncated stored `lst` must surface the
        // corruption, not silently reconstruct a short list. `ApplicationSpecific(512)`
        // needs 10 bits, so it forces the decode-and-reconstruct branch where the
        // stored array is read back at its old 9-bit width.
        let truncated_list = StatusList {
            bits: 9,
            lst: encode_compressed(&[0x00]).unwrap(),
        };
        assert!(matches!(
            truncated_list.update(vec![entry(1, Status::ApplicationSpecific(512))]),
            Err(DomainError::CorruptStoredList(_))
        ));
    }

    #[test]
    fn create_empty_yields_empty_list() {
        let result = StatusList::create(Vec::new()).unwrap();
        assert_eq!(result.bits, 1);
        assert_eq!(result.lst, "");
    }

    #[test]
    fn update_on_empty_created_list_works_end_to_end() {
        // `create(vec![])` stores `lst: ""`; an empty input stream decodes as a
        // clean EOF, so a later real update must succeed rather than 400.
        let updated = StatusList::create(Vec::new())
            .unwrap()
            .update(vec![entry(1, Status::Invalid)])
            .unwrap();
        assert_eq!(updated.bits, 1);
        assert_eq!(decompress(&updated.lst), vec![0b0000_0010]);
    }

    #[test]
    fn update_with_no_entries_is_a_noop() {
        let original = from_raw(&[0b1110_0100], 1);
        let updated = original.update(Vec::new()).unwrap();
        assert_eq!(updated, original);
    }

    #[test]
    fn create_rejects_negative_index() {
        let result = StatusList::create(vec![entry(-1, Status::Valid)]);
        assert!(matches!(result, Err(DomainError::InvalidIndex)));
    }

    #[test]
    fn update_rejects_negative_index() {
        let result = from_raw(&[0b1110_0100], 1).update(vec![entry(-1, Status::Invalid)]);
        assert!(matches!(result, Err(DomainError::InvalidIndex)));
    }

    #[test]
    fn spec_vector_one_bit_raw_pin() {
        let expected_bytes = vec![0xB9, 0xA3];
        let spec_lst = "eNrbuRgAAhcBXQ";
        assert_eq!(decompress(spec_lst), expected_bytes);
        assert_eq!(encode_compressed(&expected_bytes).unwrap(), spec_lst);
    }

    #[test]
    fn spec_vector_two_bit_raw_pin() {
        let expected_bytes = vec![0xC9, 0x44, 0xF9];
        let spec_lst = "eNo76fITAAPfAgc";
        assert_eq!(decompress(spec_lst), expected_bytes);
        assert_eq!(encode_compressed(&expected_bytes).unwrap(), spec_lst);
    }
}
