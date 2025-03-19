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
        let decoded = i8::decode(value)?; // Decode as `i8` first
        Ok(U8Wrapper(decoded as u8)) // Convert safely to `u8`
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq, Eq, FromRow, Type)]
pub struct StatusList {
    pub bits: U8Wrapper,
    pub lst: String,
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, PartialEq, Eq, FromRow)]
pub struct StatusListToken {
    pub exp: Option<i32>,
    pub iat: i32,
    pub status_list: StatusList,
    pub sub: String,
    pub ttl: Option<String>,
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

pub enum StatusType {
    JWT,
    CWT,
}

impl FromStr for StatusType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "jwt" => Ok(Self::JWT),
            "cwt" => Ok(Self::CWT),
            _ => Err("Unknown status type".to_string()),
        }
    }
}
