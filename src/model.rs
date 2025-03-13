use std::error::Error;

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
        let decoded = i8::decode(value)?;
        Ok(U8Wrapper(decoded as u8))
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub struct StatusList {
    pub bits: U8Wrapper,
    pub lst: String,
}

impl Type<Postgres> for StatusList {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("jsonb")
    }
}

impl<'r> Decode<'r, Postgres> for StatusList {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let json = <serde_json::Value as Decode<Postgres>>::decode(value)?;

        // Extract the bits value as a number and convert to U8Wrapper
        let bits = json
            .get("bits")
            .and_then(|v| v.as_i64())
            .ok_or("Missing or invalid bits field")?;

        let lst = json
            .get("lst")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid lst field")?
            .to_string();

        Ok(StatusList {
            bits: U8Wrapper(bits as u8),
            lst,
        })
    }
}

impl Encode<'_, Postgres> for StatusList {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<IsNull, Box<dyn Error + Send + Sync + 'static>> {
        let json = serde_json::json!({
            "bits": self.bits.0,
            "lst": self.lst
        });
        <serde_json::Value as Encode<Postgres>>::encode(json, buf)
    }
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, PartialEq, Eq, FromRow, Type)]
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
