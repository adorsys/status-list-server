use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as SerdeJsonValue;
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub issuer: String,
    pub public_key: SerdeJsonValue, // Consistent with struct definition
    pub alg: String,
}

impl Credentials {
    pub fn new(issuer: String, public_key: SerdeJsonValue, alg: String) -> Self {
        Self {
            issuer,
            public_key,
            alg,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusListToken {
    pub list_id: String,
    pub exp: Option<i32>,
    pub iat: i32,
    pub status_list: StatusList,
    pub sub: String,
    pub ttl: Option<String>,
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

#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Eq, Debug)]
pub struct StatusList {
    pub bits: i8,
    pub lst: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusUpdate {
    pub index: i32,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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

// SeaORM Entities
pub mod credentials {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "credentials")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub issuer: String,
        pub public_key: SerdeJsonValue, // Matches Credentials
        pub alg: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl Related<super::status_list_tokens::Entity> for Entity {
        fn to() -> RelationDef {
            panic!("No relations defined")
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod status_list_tokens {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "status_list_tokens")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub list_id: String,
        pub exp: Option<i32>,
        pub iat: i32,
        #[sea_orm(column_type = "Json")]
        pub status_list: SerdeJsonValue,
        pub sub: String,
        pub ttl: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl Related<super::credentials::Entity> for Entity {
        fn to() -> RelationDef {
            panic!("No relations defined")
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

impl From<credentials::Model> for Credentials {
    fn from(model: credentials::Model) -> Self {
        Credentials::new(model.issuer, model.public_key, model.alg)
    }
}

impl From<status_list_tokens::Model> for StatusListToken {
    fn from(model: status_list_tokens::Model) -> Self {
        StatusListToken::new(
            model.list_id,
            model.exp,
            model.iat,
            serde_json::from_value(model.status_list).unwrap_or_default(),
            model.sub,
            model.ttl,
        )
    }
}

impl From<StatusList> for sea_orm::Value {
    fn from(status_list: StatusList) -> sea_orm::Value {
        sea_orm::Value::Json(Some(Box::new(serde_json::to_value(status_list).unwrap())))
    }
}
