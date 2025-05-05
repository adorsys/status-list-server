use crate::{
    model::{StatusEntry, StatusListTokenPayload},
    utils::keygen::Keypair,
};

// Helper to create a test request payload with customizable bits
pub fn create_test_token(list_id: &str, status: Vec<StatusEntry>, bits: u8) -> StatusListTokenPayload {
    StatusListTokenPayload {
        list_id: list_id.to_string(),
        status,
        sub: Some("issuer".to_string()),
        ttl: Some(3600),
        bits,
    }
}

// Helper to generate a test server key
// Note: It does nothing, it's just use to build the AppState
pub fn server_key() -> Keypair {
    Keypair::generate().unwrap()
}
