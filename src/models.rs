use jsonwebtoken::jwk::Jwk;
use sea_orm::ActiveValue::Set;
use sea_orm::{FromJsonQueryResult, entity::prelude::*};
use serde::{Deserialize, Serialize};

/// Represents the public key in Json Web Key format
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, FromJsonQueryResult)]
pub struct PublicKey(pub Jwk);

impl From<PublicKey> for Jwk {
    fn from(public_key: PublicKey) -> Self {
        public_key.0
    }
}

impl From<Jwk> for PublicKey {
    fn from(jwk: Jwk) -> Self {
        PublicKey(jwk)
    }
}

// Credentials entity 
pub mod credentials {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "credentials")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub issuer: String,
        #[sea_orm(column_type = "Json")]
        pub public_key: PublicKey,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub issuer: String,
    pub public_key: Jwk,
}

impl Credentials {
    pub fn new(issuer: String, public_key: Jwk) -> Self {
        Self { issuer, public_key }
    }
}

impl From<credentials::Model> for Credentials {
    fn from(model: credentials::Model) -> Self {
        Self {
            issuer: model.issuer,
            public_key: model.public_key.into(),
        }
    }
}

impl From<Credentials> for credentials::ActiveModel {
    fn from(creds: Credentials) -> Self {
        Self {
            issuer: Set(creds.issuer),
            public_key: Set(PublicKey(creds.public_key)),
        }
    }
}

// Statuses entries
pub mod status_lists {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "status_lists")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub list_id: String,
        pub issuer: String,
        #[sea_orm(column_type = "Json")]
        pub status_list: StatusList,
        pub sub: String,
        /// Unix timestamp (seconds) of last modification
        pub updated_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub type StatusListRecord = status_lists::Model;

// Additional types for status list handling
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, FromJsonQueryResult)]
pub struct StatusList {
    pub bits: u8,
    pub lst: String,
}

/// Status list claims serialized inside Status List Tokens (JWT/CWT).
///
/// `aggregation_uri` is injected from server configuration at token-issuance
/// time (draft-21 §4.2/§4.3) and is **not** part of the persisted `StatusList`
/// storage model.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusListClaims {
    pub bits: u8,
    pub lst: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aggregation_uri: Option<String>,
}

/// Request payload for creating or updating status entries in a status list.
#[derive(Deserialize)]
pub struct StatusesRequest {
    pub statuses: Vec<StatusEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusEntry {
    pub index: i32,
    pub status: Status,
}
