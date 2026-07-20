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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicJwk(pub Vec<u8>);

impl PublicJwk {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
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
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
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
