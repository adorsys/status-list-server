use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
pub struct Credentials {
    #[serde(rename = "_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub issuer: String,
    public_key: Vec<u8>,
    algorithm: String,
}

pub struct StatusList {
    pub bits: u8,
    pub lst: String,
}

pub struct StatusListToken {
    pub exp: Option<i32>,
    pub iat: i32,
    pub status_list: StatusList,
    pub sub: String,
    pub ttl: Option<String>,
}
