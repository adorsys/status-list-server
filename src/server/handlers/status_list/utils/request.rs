use serde::{Deserialize, Serialize};

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
        s.serialize_u32(match self {
            Status::VALID => 0,
            Status::INVALID => 1,
            Status::SUSPENDED => 2,
            Status::ApplicationSpecific(v) => *v,
        })
    }
}

/// Map a `u32` to `Status`, rejecting the reserved range 3..=255.
fn status_from_u32<E: serde::de::Error>(v: u32) -> Result<Status, E> {
    match v {
        0 => Ok(Status::VALID),
        1 => Ok(Status::INVALID),
        2 => Ok(Status::SUSPENDED),
        n if n >= 256 => Ok(Status::ApplicationSpecific(n)),
        other => Err(E::custom(format!(
            "status value {} is reserved (only 0, 1, 2, or >= 256 allowed)",
            other
        ))),
    }
}

struct StatusVisitor;

impl<'de> serde::de::Visitor<'de> for StatusVisitor {
    type Value = Status;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an integer (0, 1, 2, >=256) or a string status name")
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
        let v =
            u32::try_from(v).map_err(|_| E::custom(format!("status value {v} overflows u32")))?;
        status_from_u32(v)
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
        let v = u32::try_from(v)
            .map_err(|_| E::custom(format!("status value {v} is out of range for u32")))?;
        status_from_u32(v)
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        // Try case-insensitive name match first.
        match v.to_ascii_uppercase().as_str() {
            "VALID" => return Ok(Status::VALID),
            "INVALID" => return Ok(Status::INVALID),
            "SUSPENDED" => return Ok(Status::SUSPENDED),
            _ => {}
        }
        // Fall back to parsing as a stringified integer.
        match v.parse::<u32>() {
            Ok(n) => status_from_u32(n),
            Err(_) => Err(E::custom(format!(
                "unknown status string \"{v}\"; expected VALID, INVALID, SUSPENDED, or a numeric value"
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for Status {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StatusVisitor)
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
    use super::{Status, StatusEntry};

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
    }

    #[test]
    fn status_deser_string_names() {
        assert_eq!(
            serde_json::from_str::<Status>(r#""VALID""#).unwrap(),
            Status::VALID
        );
        assert_eq!(
            serde_json::from_str::<Status>(r#""INVALID""#).unwrap(),
            Status::INVALID
        );
        assert_eq!(
            serde_json::from_str::<Status>(r#""SUSPENDED""#).unwrap(),
            Status::SUSPENDED
        );
    }

    #[test]
    fn status_deser_string_names_case_insensitive() {
        assert_eq!(
            serde_json::from_str::<Status>(r#""valid""#).unwrap(),
            Status::VALID
        );
        assert_eq!(
            serde_json::from_str::<Status>(r#""Valid""#).unwrap(),
            Status::VALID
        );
        assert_eq!(
            serde_json::from_str::<Status>(r#""iNvAlId""#).unwrap(),
            Status::INVALID
        );
        assert_eq!(
            serde_json::from_str::<Status>(r#""suspended""#).unwrap(),
            Status::SUSPENDED
        );
        assert_eq!(
            serde_json::from_str::<Status>(r#""Suspended""#).unwrap(),
            Status::SUSPENDED
        );
    }

    #[test]
    fn status_deser_stringified_integers() {
        assert_eq!(
            serde_json::from_str::<Status>(r#""0""#).unwrap(),
            Status::VALID
        );
        assert_eq!(
            serde_json::from_str::<Status>(r#""1""#).unwrap(),
            Status::INVALID
        );
        assert_eq!(
            serde_json::from_str::<Status>(r#""2""#).unwrap(),
            Status::SUSPENDED
        );
        assert_eq!(
            serde_json::from_str::<Status>(r#""256""#).unwrap(),
            Status::ApplicationSpecific(256)
        );
        assert_eq!(
            serde_json::from_str::<Status>(r#""512""#).unwrap(),
            Status::ApplicationSpecific(512)
        );
    }

    #[test]
    fn status_deser_rejects_reserved_integers() {
        assert!(serde_json::from_str::<Status>("-1").is_err());
        assert!(serde_json::from_str::<Status>("3").is_err());
        assert!(serde_json::from_str::<Status>("100").is_err());
        assert!(serde_json::from_str::<Status>("255").is_err());
    }

    #[test]
    fn status_deser_rejects_reserved_string_integers() {
        assert!(serde_json::from_str::<Status>(r#""3""#).is_err());
        assert!(serde_json::from_str::<Status>(r#""100""#).is_err());
        assert!(serde_json::from_str::<Status>(r#""255""#).is_err());
    }

    #[test]
    fn status_deser_rejects_invalid_strings() {
        assert!(serde_json::from_str::<Status>(r#""foo""#).is_err());
        assert!(serde_json::from_str::<Status>(r#""REVOKED""#).is_err());
        assert!(serde_json::from_str::<Status>(r#""""#).is_err());
    }

    #[test]
    fn status_deser_full_entry_string() {
        let entry: StatusEntry =
            serde_json::from_str(r#"{"index": 0, "status": "VALID"}"#).unwrap();
        assert_eq!(entry.index, 0);
        assert_eq!(entry.status, Status::VALID);

        let entry: StatusEntry =
            serde_json::from_str(r#"{"index": 5, "status": "suspended"}"#).unwrap();
        assert_eq!(entry.index, 5);
        assert_eq!(entry.status, Status::SUSPENDED);

        let entry: StatusEntry = serde_json::from_str(r#"{"index": 10, "status": "512"}"#).unwrap();
        assert_eq!(entry.index, 10);
        assert_eq!(entry.status, Status::ApplicationSpecific(512));
    }

    #[test]
    fn status_deser_full_entry_integer() {
        let entry: StatusEntry = serde_json::from_str(r#"{"index": 0, "status": 0}"#).unwrap();
        assert_eq!(entry.index, 0);
        assert_eq!(entry.status, Status::VALID);

        let entry: StatusEntry = serde_json::from_str(r#"{"index": 1, "status": 2}"#).unwrap();
        assert_eq!(entry.index, 1);
        assert_eq!(entry.status, Status::SUSPENDED);

        let entry: StatusEntry = serde_json::from_str(r#"{"index": 2, "status": 256}"#).unwrap();
        assert_eq!(entry.index, 2);
        assert_eq!(entry.status, Status::ApplicationSpecific(256));
    }
}
