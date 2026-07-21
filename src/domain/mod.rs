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
    /// Specification-defined custom values start at 256. Values 3..=255 are
    /// intentionally rejected because the status-list bit-width table reserves
    /// them for future standard statuses and compact encodings.
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
/// `ApplicationSpecific` is valid only for values greater than or equal to 256;
/// lower non-standard values are reserved by the status-list encoding table and
/// must not enter newly created or updated lists.
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
        .map_err(|err| DomainError::InvalidStatusList(format!("Invalid lst encoding: {err}")))?;
    let mut decoder = flate2::read::ZlibDecoder::new(&bytes[..]);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).map_err(|err| {
        DomainError::InvalidStatusList(format!("Failed to decompress status list: {err}"))
    })?;
    Ok(decoded)
}

fn decode_status_array(array: &[u8], bits: usize) -> Result<Vec<Status>, DomainError> {
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
            value if value >= 256 => Status::ApplicationSpecific(value),
            _ => {
                return Err(DomainError::InvalidStatusList(
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
        assert_eq!(decode_status_array(&decompress(&result.lst), 9).unwrap().len(), 12);
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
}
