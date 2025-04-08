use std::{error::Error, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{
    encode::IsNull,
    postgres::PgTypeInfo,
    prelude::{FromRow, Type},
    Decode, Encode, Postgres,
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, FromRow)]
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

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Eq, Debug, Type)]
pub struct StatusList {
    pub bits: i8,
    pub lst: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct U8Wrapper(pub u8);

impl Type<Postgres> for U8Wrapper {
    fn type_info() -> PgTypeInfo {
        <i8 as Type<Postgres>>::type_info()
    }
}

// Implement `sqlx::Encode<Postgres>` for `U8Wrapper`
impl Encode<'_, Postgres> for U8Wrapper {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<IsNull, Box<(dyn Error + Send + Sync + 'static)>> {
        (self.0 as i8).encode(buf)
    }
}

// Implement `sqlx::Decode<Postgres>` for `U8Wrapper`
impl<'r> Decode<'r, Postgres> for U8Wrapper {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let decoded = i8::decode(value)?;
        Ok(U8Wrapper(decoded as u8))
    }
}
#[derive(Deserialize, Serialize, Clone, Default, Debug, PartialEq, Eq, FromRow, Type)]
pub struct StatusListToken {
    pub exp: Option<i32>,
    pub iat: i32,
    pub status_list: StatusList,
    pub sub: String,
    pub ttl: Option<String>,
    pub list_id: String,
}

impl StatusListToken {
    pub fn new(
        list_id: String,
        exp: Option<i32>,
        iat: i32,
        status_list: StatusList,
        sub: String,
        ttl: Option<String>,
    ) -> Self {
        Self {
            list_id,
            exp,
            iat,
            status_list,
            sub,
            ttl,
        }
    }
}
