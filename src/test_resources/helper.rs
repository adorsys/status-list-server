#[cfg(test)]
use crate::models::StatusEntry;
use crate::models::StatusRequest;

// Helper to create a test request payload with customizable bits
#[cfg(test)]
pub fn publish_test_token(list_id: &str, status: Vec<StatusEntry>) -> StatusRequest {
    StatusRequest {
        list_id: list_id.to_owned(),
        status,
    }
}
