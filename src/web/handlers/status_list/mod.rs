pub(super) mod aggregation;
pub mod conditional;
pub(super) mod constants;
pub(super) mod error;
pub mod etag;
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

fn validate_status_request_limits(
    statuses: &[crate::models::StatusEntry],
    max_statuses_per_request: usize,
    max_status_index: i32,
) -> Result<(), error::StatusListError> {
    if statuses.len() > max_statuses_per_request {
        return Err(error::StatusListError::TooManyStatuses {
            count: statuses.len(),
            max: max_statuses_per_request,
        });
    }

    if let Some(entry) = statuses.iter().find(|entry| entry.index > max_status_index) {
        return Err(error::StatusListError::IndexTooLarge(entry.index));
    }

    Ok(())
}

fn ensure_serialized_list_size(
    status_list: &crate::domain::StatusList,
    max_serialized_list_size: usize,
) -> Result<(), error::StatusListError> {
    if status_list.lst.len() > max_serialized_list_size {
        return Err(error::StatusListError::StatusTooLarge);
    }
    Ok(())
}

fn map_domain_error(error: crate::domain::DomainError) -> error::StatusListError {
    match error {
        crate::domain::DomainError::InvalidIndex => error::StatusListError::InvalidIndex,
        crate::domain::DomainError::InvalidStatusList(message) => {
            error::StatusListError::Generic(message)
        }
        crate::domain::DomainError::InvalidPublicJwk(message) => {
            error::StatusListError::Generic(message)
        }
    }
}
