use jsonwebtoken::Algorithm;
use sea_orm::ActiveValue::Set;
use sea_orm::{entity::prelude::*, FromJsonQueryResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alg(pub Algorithm);

impl From<Algorithm> for Alg {
    fn from(alg: Algorithm) -> Self {
        Alg(alg)
    }
}

impl From<Alg> for Algorithm {
    fn from(alg: Alg) -> Self {
        alg.0
    }
}

impl sea_orm::sea_query::ValueType for Alg {
    fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            sea_orm::Value::String(Some(s)) => s
                .parse::<Algorithm>()
                .map(Alg)
                .map_err(|_| sea_orm::sea_query::ValueTypeErr),
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }

    fn type_name() -> String {
        "Alg".to_string()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::String(sea_orm::sea_query::StringLen::N(255))
    }
}

impl sea_orm::sea_query::Nullable for Alg {
    fn null() -> sea_orm::Value {
        sea_orm::Value::String(None)
    }
}

impl From<Alg> for sea_orm::Value {
    fn from(alg: Alg) -> Self {
        sea_orm::Value::String(Some(Box::new(format!("{:?}", alg.0))))
    }
}

impl sea_orm::TryGetable for Alg {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &sea_orm::QueryResult,
        index: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let value: String = res.try_get_by(index)?;
        value
            .parse::<Algorithm>()
            .map(Alg)
            .map_err(|e| sea_orm::TryGetError::DbErr(sea_orm::DbErr::Custom(e.to_string())))
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
        pub public_key: String,
        pub alg: Alg,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub issuer: String,
    pub public_key: String,
    pub alg: Algorithm,
}

impl Credentials {
    pub fn new(issuer: String, public_key: String, alg: Algorithm) -> Self {
        Self {
            issuer,
            public_key,
            alg,
        }
    }
}

impl From<credentials::Model> for Credentials {
    fn from(model: credentials::Model) -> Self {
        Self {
            issuer: model.issuer,
            public_key: model.public_key,
            alg: model.alg.into(),
        }
    }
}

impl From<Credentials> for credentials::ActiveModel {
    fn from(creds: Credentials) -> Self {
        Self {
            issuer: Set(creds.issuer),
            public_key: Set(creds.public_key),
            alg: Set(Alg(creds.alg)),
        }
    }
}

// StatusListToken entity
pub mod status_list_tokens {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "status_list_tokens")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub list_id: String,
        pub issuer: String,
        pub exp: Option<i64>,
        pub iat: i64,
        #[sea_orm(column_type = "Json")]
        pub status_list: StatusList,
        pub sub: String,
        pub ttl: Option<i64>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub type StatusListToken = status_list_tokens::Model;

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

/// Request payload for publishing and updating a status list token
#[derive(Deserialize, Serialize, Clone)]
pub struct StatusListTokenPayload {
    pub list_id: String,
    pub status: Vec<StatusEntry>,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub ttl: Option<i64>,
    pub bits: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusEntry {
    pub index: i32,
    pub status: Status,
}
