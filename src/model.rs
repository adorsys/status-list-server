use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::prelude::FromRow;
#[derive(Deserialize, Serialize, Clone, Default, Debug, PartialEq, Eq)]
#[derive(FromRow)]
pub struct Credentials {
    pub issuer: String,
    pub public_key: Value,
    pub alg: String,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct StatusList {
    pub bits: u8,
    pub lst: String,
}

#[derive(FromRow)]
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct StatusListToken {
    pub exp: Option<i32>,
    pub iat: i32,
    pub status_list: StatusList,
    pub sub: String,
    pub ttl: Option<String>,
}
