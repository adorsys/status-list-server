use sea_orm::DatabaseTransaction;

use super::super::error::{RepositoryError, contention_err};

/// Classifies an insert failure, distinguishing unique-constraint violations
/// (client conflicts mapped to 409) from server errors (500).
pub(super) fn map_insert_err(e: sea_orm::DbErr) -> RepositoryError {
    match e.sql_err() {
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_)) => RepositoryError::DuplicateEntry,
        _ => contention_err(&e).unwrap_or_else(|| RepositoryError::InsertError(e.to_string())),
    }
}

pub(super) fn map_update_err(e: sea_orm::DbErr) -> RepositoryError {
    contention_err(&e).unwrap_or_else(|| RepositoryError::UpdateError(e.to_string()))
}

/// For `status_list_history` inserts, which must **not** map unique constraint
/// violations to `DuplicateEntry`.
pub(super) fn map_snapshot_insert_err(e: sea_orm::DbErr) -> RepositoryError {
    contention_err(&e).unwrap_or_else(|| RepositoryError::InsertError(e.to_string()))
}

pub(super) fn map_delete_err(e: sea_orm::DbErr) -> RepositoryError {
    contention_err(&e).unwrap_or_else(|| RepositoryError::DeleteError(e.to_string()))
}

pub(super) fn find_err(e: sea_orm::DbErr) -> RepositoryError {
    RepositoryError::FindError(e.to_string())
}

/// Helper to roll back a transaction on error and map the operation failure.
pub(super) async fn rollback_and_map_err<F>(
    txn: DatabaseTransaction,
    err: sea_orm::DbErr,
    action: &str,
    map_err: F,
) -> RepositoryError
where
    F: FnOnce(sea_orm::DbErr) -> RepositoryError,
{
    if let Err(rollback_err) = txn.rollback().await {
        RepositoryError::InsertError(format!(
            "{action} failed ({err}); rolling the transaction back also failed: {rollback_err}"
        ))
    } else {
        map_err(err)
    }
}

/// Validates that an optimistic update's timestamp advances strictly past the guard.
pub(super) fn validate_advancing_stamp(new: i64, expected: i64) -> Result<(), RepositoryError> {
    if new <= expected {
        Err(RepositoryError::UpdateError(format!(
            "guarded update requires a strictly newer updated_at \
             (new={new}, expected-guard={expected}); a non-advancing stamp would \
             silently reintroduce the same-second lost update"
        )))
    } else {
        Ok(())
    }
}
