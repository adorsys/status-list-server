pub(super) mod aggregation;
pub mod conditional;
pub(super) mod constants;
pub mod error;
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

fn map_domain_error(error: crate::domain::DomainError) -> error::StatusListError {
    match error {
        crate::domain::DomainError::InvalidIndex => error::StatusListError::InvalidIndex,
        crate::domain::DomainError::InvalidStatusList(message) => {
            error::StatusListError::Generic(message)
        }
        // Corrupt persisted state, not a caller error: 500, never 400. Log the
        // decode detail at error level *here* so the alert survives even a
        // handler that routes corruption through this central mapping without
        // its own arm — the 500 variant carries no message, so this is the last
        // place the detail exists. Handlers with richer context (e.g. `list_id`)
        // may still intercept `CorruptStoredList` before this mapping.
        crate::domain::DomainError::CorruptStoredList(detail) => {
            tracing::error!(%detail, "Corrupt stored status list");
            error::StatusListError::InternalServerError
        }
        crate::domain::DomainError::InvalidPublicJwk(message) => {
            error::StatusListError::Generic(message)
        }
    }
}

/// Fixture builders for handler tests, replacing the retired `utils::lst_gen`.
///
/// `encode_compressed` constructs the wire form (zlib level 9 + base64url,
/// no padding) independently of the domain encoder, so handler fixtures don't
/// silently inherit an encoder bug they're meant to exercise.
#[cfg(test)]
pub(crate) mod test_support {
    use std::io::Write;

    pub(crate) fn encode_compressed(bytes: &[u8]) -> String {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(bytes).expect("compressing test fixture");
        base64url::encode(encoder.finish().expect("finishing test fixture"))
    }

    pub(crate) fn create_status_list(
        entries: Vec<crate::models::StatusEntry>,
    ) -> Result<crate::models::StatusList, crate::domain::DomainError> {
        let domain_list = crate::domain::StatusList::create(
            entries.into_iter().map(super::to_domain_entry).collect(),
        )?;
        Ok(crate::models::StatusList {
            bits: domain_list.bits,
            lst: domain_list.lst,
        })
    }
}
