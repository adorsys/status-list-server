use crate::models::StatusEntry;
use serde::Deserialize;

pub(crate) mod aggregation;
pub(super) mod constants;
pub(super) mod error;
pub(crate) mod get_status_list;
pub mod publish_status;
pub mod update_status;

/// Request payload for perfoming actions(publish / update) on a status list token
#[derive(Deserialize)]
pub struct StatusRequest {
    pub list_id: String,
    pub status: Vec<StatusEntry>,
}
