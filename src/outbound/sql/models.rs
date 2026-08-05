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
pub(crate) mod credentials {
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
pub(crate) mod status_lists {
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

pub(crate) type StatusListRecord = status_lists::Model;

// An immutable Status List Token payload and the interval during which it was
// issued as valid. These rows are retained for draft-21 §8.4 resolution.
pub(crate) mod status_list_history {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "status_list_history")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub snapshot_id: String,
        pub list_id: String,
        pub issuer: String,
        pub status_list: StatusList,
        pub sub: String,
        pub iat: i64,
        pub exp: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) type StatusListHistoryRecord = status_list_history::Model;

// Generic key/value storage for certificate chains, ACME account data and
// signing material. Callers must not log `value`; the SQL storage adapter keeps
// tracing fields to key/backend metadata only.
#[allow(unreachable_pub)]
pub(crate) mod certificate_storage {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "certificate_storage")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false, column_name = "storage_key")]
        pub key: String,
        #[sea_orm(column_type = "Text")]
        pub value: String,
        #[sea_orm(column_type = "Json", nullable)]
        pub metadata: Option<serde_json::Value>,
        /// Unix timestamp (seconds) when the row was first created.
        pub created_at: i64,
        /// Unix timestamp (seconds) when the row was last updated.
        pub updated_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

// Persisted JSON shape of a status list column.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, FromJsonQueryResult)]
pub struct StatusList {
    pub bits: u8,
    pub lst: String,
}
