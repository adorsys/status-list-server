//! Wire types for the status-list HTTP API.
//!
//! These carry the draft-21 JSON representation (statuses as bare integers)
//! and are translated into domain values at the handler boundary — they are
//! not persisted and must never leak into inner layers.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    VALID,
    INVALID,
    SUSPENDED,
    ApplicationSpecific(u32),
}

impl Serialize for Status {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(match self {
            Status::VALID => 0,
            Status::INVALID => 1,
            Status::SUSPENDED => 2,
            Status::ApplicationSpecific(v) => *v,
        })
    }
}

impl<'de> Deserialize<'de> for Status {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = u32::deserialize(d)?;
        Ok(match v {
            0 => Status::VALID,
            1 => Status::INVALID,
            2 => Status::SUSPENDED,
            n if n >= 256 => Status::ApplicationSpecific(n),
            other => {
                return Err(serde::de::Error::custom(format!(
                    "status value {} is reserved (only 0, 1, 2, or >= 256 allowed)",
                    other
                )));
            }
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusEntry {
    pub index: i32,
    pub status: Status,
}

/// Request payload for creating or updating status entries in a status list.
#[derive(Deserialize)]
pub struct StatusesRequest {
    pub statuses: Vec<StatusEntry>,
}

#[cfg(test)]
mod tests {
    use super::Status;

    /// Wire format: statuses serialize as bare integers, and deserialization
    /// rejects the reserved range 3..=255 (ported from the retired
    /// `utils::lst_gen` suite).
    #[test]
    fn status_serde_integer_roundtrip() {
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
}
