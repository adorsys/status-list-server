pub(super) mod aggregation;
pub(super) mod constants;
pub(super) mod error;
pub(crate) mod get_status_list;
pub mod publish_status;
pub mod update_status;

// Re-export request types from models
pub use crate::models::StatusesRequest;

fn to_domain_entry(entry: crate::models::StatusEntry) -> crate::domain::StatusEntry {
    crate::domain::StatusEntry {
        index: entry.index,
        status: match entry.status {
            crate::models::Status::VALID => crate::domain::Status::Valid,
            crate::models::Status::INVALID => crate::domain::Status::Invalid,
            crate::models::Status::SUSPENDED => crate::domain::Status::Suspended,
            crate::models::Status::ApplicationSpecific(value) => {
                crate::domain::Status::ApplicationSpecific(value)
            }
        },
    }
}
