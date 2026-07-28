mod aggregation;
pub mod conditional;
pub(super) mod constants;
pub(super) mod etag;
mod get_status_list;
mod publish_status;
mod request;
mod update_status;

pub use aggregation::get_aggregation;
pub use get_status_list::{StatusListQuery, get_status_list};
pub use publish_status::publish_status;
pub use request::{Status, StatusEntry, StatusesRequest};
pub use update_status::update_status;

fn to_domain_entry(entry: StatusEntry) -> crate::domain::models::status_list::StatusEntry {
    crate::domain::models::status_list::StatusEntry {
        index: entry.index,
        status: match entry.status {
            Status::VALID => crate::domain::models::status_list::Status::Valid,
            Status::INVALID => crate::domain::models::status_list::Status::Invalid,
            Status::SUSPENDED => crate::domain::models::status_list::Status::Suspended,
            Status::ApplicationSpecific(value) => {
                crate::domain::models::status_list::Status::ApplicationSpecific(value)
            }
        },
    }
}
