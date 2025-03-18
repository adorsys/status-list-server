use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct StatusList {
    pub bits: u8,
    pub lst: String,
}

// Status list claims token.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct StatusListClaims {
    pub exp: Option<u64>,
    pub iat: u64,
    pub status_list: StatusList,
    pub sub: String,
    pub ttl: Option<u64>,
}

// Status list record from the database.
// This is created and updated by the handlers of status list creation and update.
#[derive(sqlx::FromRow)]
pub(super) struct StatusListRecord {
    pub id: u32,
    pub bits: u8,
    pub lst: String,
    pub uri: String,
    pub exp: Option<u64>,
}
