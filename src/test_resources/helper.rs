use crate::model::PublishStatusRequest;
#[cfg(test)]
use crate::{model::StatusEntry, utils::keygen::Keypair};

// Helper to create a test request payload with customizable bits
#[cfg(test)]
pub fn publish_test_token(list_id: &str, status: Vec<StatusEntry>) -> PublishStatusRequest {
    PublishStatusRequest {
        list_id: list_id.to_owned(),
        status,
        sub: "https://example.com/statuslists/1".to_string(),
    }
}

// Helper to generate a test server key
// Note: It does nothing, it's just use to build the AppState
#[cfg(test)]
pub fn server_key() -> Keypair {
    Keypair::generate().unwrap()
}
