/// Storage-adapter failures.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("Insert error: {0}")]
    InsertError(String),
    #[error("Find error: {0}")]
    FindError(String),
    #[error("Update error: {0}")]
    UpdateError(String),
    #[error("Delete error: {0}")]
    DeleteError(String),
    #[error("Could not store entity")]
    CouldNotStoreEntity,
    #[error("Repository not set")]
    RepositoryNotSet,
    #[error("Duplicate entry")]
    DuplicateEntry,
    /// Nothing was written, so the request can be retried as-is.
    /// `code` separates lock-wait timeouts from deadlocks in the metric.
    #[error("Write contention ({code}): the transaction lost a lock race and may be retried")]
    Contention { code: &'static str },
    #[error("Status list quota exceeded: issuer holds {count} of {max}")]
    QuotaExceeded { count: u64, max: u64 },
    #[error("Status list not found")]
    NotFound,
    #[error("Issuer mismatch")]
    IssuerMismatch,
    #[error("Status list is not fixed-size")]
    ListNotFixedSize,
    #[error("Status list does not have enough unallocated indices")]
    AllocationExhausted,
}

// Deliberately no From<DbErr>: `?` would drop sql_err() and turn a racing publish's 409 into a 500.
// Classify at each call site with map_insert_err and friends.

/// 40001 serialization failure, 40P01 deadlock. 23505 is a duplicate, not a retry.
#[cfg(feature = "postgres")]
fn classify_postgres(sqlstate: &str) -> Option<&'static str> {
    match sqlstate {
        "40001" => Some("40001"),
        "40P01" => Some("40P01"),
        _ => None,
    }
}

/// Error numbers, not SQLSTATE: 1205 shares HY000 with plenty of non-retryable errors.
#[cfg(feature = "mysql")]
fn classify_mysql(number: u16) -> Option<&'static str> {
    match number {
        1205 => Some("1205"),
        1213 => Some("1213"),
        _ => None,
    }
}

/// Mirrors how DbErr::sql_err matches, so it tracks sea-orm's error shape.
fn contention_code(err: &sea_orm::DbErr) -> Option<&'static str> {
    #[cfg(any(feature = "mysql", feature = "postgres"))]
    {
        use sea_orm::{DbErr, RuntimeErr, SqlxError};

        let db = match err {
            DbErr::Exec(RuntimeErr::SqlxError(inner))
            | DbErr::Query(RuntimeErr::SqlxError(inner)) => match inner.as_ref() {
                SqlxError::Database(db) => db,
                _ => return None,
            },
            _ => return None,
        };

        #[cfg(feature = "mysql")]
        if let Some(mysql_err) = db.try_downcast_ref::<sea_orm::SqlxMySqlError>() {
            return classify_mysql(mysql_err.number());
        }
        #[cfg(feature = "postgres")]
        if let Some(postgres_err) = db.try_downcast_ref::<sea_orm::SqlxPostgresError>() {
            return classify_postgres(postgres_err.code());
        }
    }

    let _ = err;
    None
}

/// Call at the adapter boundary; the driver code is gone once DbErr is stringified.
/// Logs at warn because the client only sees a 409, and warn stays out of alerting.
pub(super) fn contention_err(err: &sea_orm::DbErr) -> Option<RepositoryError> {
    let code = contention_code(err)?;
    tracing::warn!(
        error = %err,
        db.contention_code = code,
        "storage write lost a lock race; classifying as retryable contention"
    );
    Some(RepositoryError::Contention { code })
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "mysql", feature = "postgres"))]
    use super::*;

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_unique_violation_is_not_contention() {
        assert!(classify_postgres("23505").is_none());
        assert!(classify_postgres("23503").is_none());
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_serialization_and_deadlock_are_contention() {
        for sqlstate in ["40001", "40P01"] {
            assert_eq!(
                classify_postgres(sqlstate),
                Some(sqlstate),
                "SQLSTATE {sqlstate} must classify as contention, reporting itself"
            );
        }
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_unrelated_sqlstates_are_not_contention() {
        for sqlstate in ["57014", "55P03", "42P01", ""] {
            assert!(
                classify_postgres(sqlstate).is_none(),
                "SQLSTATE {sqlstate} must not classify as contention"
            );
        }
    }

    #[cfg(feature = "mysql")]
    #[test]
    fn mysql_duplicate_entry_is_not_contention() {
        for number in [1022, 1062, 1169, 1586] {
            assert!(
                classify_mysql(number).is_none(),
                "error {number} is a duplicate key, not contention"
            );
        }
    }

    #[cfg(feature = "mysql")]
    #[test]
    fn mysql_lock_wait_timeout_and_deadlock_are_contention() {
        for (number, expected) in [(1205u16, "1205"), (1213, "1213")] {
            assert_eq!(
                classify_mysql(number),
                Some(expected),
                "error {number} must classify as contention, reporting itself"
            );
        }
    }

    #[cfg(feature = "mysql")]
    #[test]
    fn mysql_other_hy000_errors_are_not_contention() {
        for number in [1030, 1114, 1436] {
            assert!(
                classify_mysql(number).is_none(),
                "error {number} shares SQLSTATE HY000 with 1205 but is not contention"
            );
        }
    }
}
