use crate::{
    database::queries::SeaOrmStore,
    utils::state::{AppState, MockSecretCache},
};
use std::sync::Arc;

pub fn test_app_state(db_conn: Arc<sea_orm::DatabaseConnection>) -> AppState {
    let pem = include_str!("../test_resources/ec-private.pem").to_string();
    AppState {
        credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
        status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
        secret_cache: Arc::new(MockSecretCache { value: Some(pem) }),
        server_secret_name: "test-server-key".to_string(),
    }
}
