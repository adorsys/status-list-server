use jsonwebtoken::jwk::Jwk;
use sea_orm::ActiveValue::{NotSet, Set};
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
        /// Status lists published by this issuer; see `store::reserve_list_slot`.
        pub list_count: i64,
        /// Hyphenated `AggregationId`. `NULL` on rows a release that predates it
        /// wrote, until the first lookup assigns one.
        pub aggregation_id: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub issuer: String,
    pub public_key: Jwk,
    pub aggregation_id: Option<String>,
}

impl Credentials {
    pub fn new(issuer: String, public_key: Jwk) -> Self {
        Self {
            issuer,
            public_key,
            aggregation_id: None,
        }
    }

    pub fn with_aggregation_id(self, aggregation_id: String) -> Self {
        Self {
            aggregation_id: Some(aggregation_id),
            ..self
        }
    }
}

impl From<credentials::Model> for Credentials {
    fn from(model: credentials::Model) -> Self {
        Self {
            issuer: model.issuer,
            public_key: model.public_key.into(),
            aggregation_id: model.aggregation_id,
        }
    }
}

impl From<Credentials> for credentials::ActiveModel {
    fn from(creds: Credentials) -> Self {
        Self {
            issuer: Set(creds.issuer),
            public_key: Set(PublicKey(creds.public_key)),
            // NotSet so a credential update never resets the counter.
            list_count: NotSet,
            // NotSet unless given, so a credential update never replaces the ID
            // that published aggregation URIs point to.
            aggregation_id: creds
                .aggregation_id
                .map_or(NotSet, |aggregation_id| Set(Some(aggregation_id))),
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
        #[sea_orm(column_type = "Json")]
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

#[allow(unreachable_pub)]
pub(crate) mod status_list_allocations {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "status_list_allocations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub list_id: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub idx: i32,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_status: Option<crate::domain::models::status_list::Status>,
}
