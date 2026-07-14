//! Framework-independent business concepts for status-list operations.
//!
//! This module deliberately contains no HTTP, database, cache, or cloud SDK
//! dependency.  Adapters translate these values at the boundary.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub issuer: Issuer,
    /// A serialized public JWK.  Parsing/verifying it belongs to the inbound
    /// authentication adapter.
    pub public_key: serde_json::Value,
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
}
