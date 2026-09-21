use serde::{Deserialize, Serialize};

use crate::domain::models::status_list::is_application_specific_status_value;

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    VALID,
    INVALID,
    SUSPENDED,
    ApplicationSpecific(u32),
}

impl Serialize for Status {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let value = match self {
            Status::VALID => 0,
            Status::INVALID => 1,
            Status::SUSPENDED => 2,
            Status::ApplicationSpecific(v) if is_application_specific_status_value(*v) => *v,
            Status::ApplicationSpecific(v) if *v <= 255 => {
                return Err(serde::ser::Error::custom(format!(
                    "status value {v} is reserved for future registration; application-specific status values are 3 and 12 through 15"
                )));
            }
            Status::ApplicationSpecific(v) => {
                return Err(serde::ser::Error::custom(format!(
                    "status value {v} exceeds 8-bit capacity; maximum supported status value is 255"
                )));
            }
        };
        s.serialize_u32(value)
    }
}

impl<'de> Deserialize<'de> for Status {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = u32::deserialize(d)?;
        Ok(match v {
            0 => Status::VALID,
            1 => Status::INVALID,
            2 => Status::SUSPENDED,
            n if is_application_specific_status_value(n) => Status::ApplicationSpecific(n),
            n @ 4..=255 => {
                return Err(serde::de::Error::custom(format!(
                    "status value {n} is reserved for future registration; application-specific status values are 3 and 12 through 15"
                )));
            }
            other => {
                return Err(serde::de::Error::custom(format!(
                    "status value {} exceeds 8-bit capacity; maximum supported status value is 255",
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

impl From<StatusEntry> for crate::domain::models::status_list::StatusEntry {
    fn from(entry: StatusEntry) -> Self {
        Self {
            index: entry.index,
            status: match entry.status {
                Status::VALID => crate::domain::models::status_list::Status::Valid,
                Status::INVALID => crate::domain::models::status_list::Status::Invalid,
                Status::SUSPENDED => crate::domain::models::status_list::Status::Suspended,
                Status::ApplicationSpecific(value) => {
                    crate::domain::models::status_list::Status::ApplicationSpecific(value)
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Status;

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
        assert_eq!(serde_json::to_string(&Status::VALID).unwrap(), "0");
        assert_eq!(serde_json::to_string(&Status::INVALID).unwrap(), "1");
        assert_eq!(serde_json::to_string(&Status::SUSPENDED).unwrap(), "2");
        assert_eq!(
            serde_json::from_str::<Status>("3").unwrap(),
            Status::ApplicationSpecific(3)
        );
        for value in [12u32, 13, 14, 15] {
            assert_eq!(
                serde_json::from_str::<Status>(&value.to_string()).unwrap(),
                Status::ApplicationSpecific(value)
            );
            assert_eq!(
                serde_json::to_string(&Status::ApplicationSpecific(value)).unwrap(),
                value.to_string()
            );
        }
        for value in [4u32, 11, 16, 100, 255] {
            let err = serde_json::from_str::<Status>(&value.to_string()).unwrap_err();
            assert!(
                err.to_string().contains("reserved for future registration"),
                "value {value} should fail as reserved, got {err}"
            );
            let err = serde_json::to_string(&Status::ApplicationSpecific(value)).unwrap_err();
            assert!(
                err.to_string().contains("reserved for future registration"),
                "value {value} should fail as reserved, got {err}"
            );
        }
        assert!(serde_json::from_str::<Status>("256").is_err());
        assert!(serde_json::to_string(&Status::ApplicationSpecific(256)).is_err());
    }
}
