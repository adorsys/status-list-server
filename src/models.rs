use jsonwebtoken::jwk::Jwk;
use sea_orm::ActiveValue::Set;
use sea_orm::{entity::prelude::*, FromJsonQueryResult};
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
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub type StatusListRecord = status_lists::Model;

// Additional types for status list handling
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Status {
    VALID,
    INVALID,
    SUSPENDED,
    APPLICATIONSPECIFIC,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, FromJsonQueryResult)]
pub struct StatusList {
    pub bits: u8,
    pub lst: String,
}

/// Request payload for perfoming actions(publish / update) on a status list token
#[derive(Deserialize)]
pub struct StatusRequest {
    pub list_id: String,
    pub status: Vec<StatusEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusEntry {
    pub index: i32,
    pub status: Status,
}
