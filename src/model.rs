use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::prelude::FromRow;
#[derive(Deserialize, Serialize, Clone, Default, Debug, PartialEq, Eq, FromRow)]
pub struct Credentials {
    pub issuer: String,
    pub public_key: Value,
    pub alg: String,
}
impl Credentials {
    pub fn new(issuer: String, public_key: Value, alg: String) -> Self {
        Self {
            issuer,
            public_key,
            alg,
        }
    }
}

#[derive(Deserialize)]
pub struct StatusUpdate {
    pub index: i32,
    pub status: Status,
}

#[derive(Deserialize)]
pub enum Status {
    VALID,
    INVALID,
    SUSPENDED,
    APPLICATIONSPECIFIC,
}

impl FromStr for Status {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "valid" => Ok(Status::VALID),
            "invalid" => Ok(Status::INVALID),
            "suspended" => Ok(Status::SUSPENDED),
            "application_specific" => Ok(Status::APPLICATIONSPECIFIC),
            _ => Err("Unknown status".to_string()),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct StatusList {
    pub bits: u8,
    pub lst: String,
}

#[derive(FromRow, Clone, Serialize, Deserialize, Default)]
pub struct StatusListToken {
    exp: Option<i32>,
    iat: i32,
    status_list: StatusList,
    sub: String,
    ttl: Option<String>,
}

#[allow(unused)]
impl StatusListToken {
    fn new(
        exp: Option<i32>,
        iat: i32,
        status_list: StatusList,
        sub: String,
        ttl: Option<String>,
    ) -> Self {
        Self {
            exp,
            iat,
            status_list,
            sub,
            ttl,
        }
    }
}
