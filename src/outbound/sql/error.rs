/// Storage-adapter failures.
///
/// `#[non_exhaustive]` so adding a variant stays patch-level instead of tripping
/// `cargo-semver-checks` (`enum_variant_added`).
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
    /// The statement lost a lock race and was rolled back. Distinct from
    /// [`DuplicateEntry`] and from the optimistic-guard miss: nothing was
    /// written, nobody won, and the request is safe to retry verbatim.
    ///
    /// `code` is the driver's discriminator, always one of `"40001"`, `"40P01"`,
    /// `"1205"` or `"1213"` — a closed set, produced only by the private
    /// `classify_postgres` / `classify_mysql` tables in this module. Carried so
    /// the metric can separate lock-wait timeouts from deadlocks, which have
    /// different remediations. Opaque otherwise; nothing branches on it.
    ///
    /// [`DuplicateEntry`]: RepositoryError::DuplicateEntry
    #[error("Write contention ({code}): the transaction lost a lock race and may be retried")]
    Contention { code: &'static str },
}

// There is deliberately no `impl From<sea_orm::DbErr>` for this type, nor for
// `StatusListError` / `CredentialError`.
//
// A blanket conversion would make `?` on a `DbErr` compile anywhere, and every
// such conversion silently discards `DbErr::sql_err()` — turning a unique-key
// violation into a generic backend error, and a racing publish into a 500
// instead of a 409 (#143, #244). Requiring `.map_err(map_insert_err)` at each
// insert site keeps that classification an explicit, reviewable decision rather
// than something a one-character edit can drop.
//
// The `Generic` variant went with it: it existed only as that impl's output, and
// an unclassified catch-all is the same trapdoor wearing a different hat.
//
// `Contention` depends on exactly this discipline: the SQLSTATE/error number it
// carries survives only until the first `DbErr` stringification, so a blanket
// conversion would erase it before any call site could classify it.

/// PostgreSQL `SQLSTATE`s meaning "lost a race, safe to retry":
/// `40001` serialization_failure, `40P01` deadlock_detected.
///
/// `23505` (unique_violation) is excluded: it is a duplicate entry and must keep
/// reaching [`RepositoryError::DuplicateEntry`], not become a retry signal.
#[cfg(feature = "postgres")]
fn classify_postgres(sqlstate: &str) -> Option<&'static str> {
    match sqlstate {
        "40001" => Some("40001"),
        "40P01" => Some("40P01"),
        _ => None,
    }
}

/// MySQL server error *numbers*, not `SQLSTATE`s: `1205` ER_LOCK_WAIT_TIMEOUT,
/// `1213` ER_LOCK_DEADLOCK.
///
/// `1205` carries `HY000`, MySQL's catch-all, shared with many unrelated and
/// non-retryable errors — so the error number is the only sound discriminator
/// here. `1062` (duplicate entry) is excluded, as `23505` is on Postgres.
#[cfg(feature = "mysql")]
fn classify_mysql(number: u16) -> Option<&'static str> {
    match number {
        1205 => Some("1205"),
        1213 => Some("1213"),
        _ => None,
    }
}

/// The matched error shape is the same one [`sea_orm::DbErr::sql_err`] uses,
/// so it stays valid if sea-orm reshuffles its public error enums.
fn contention_code(err: &sea_orm::DbErr) -> Option<&'static str> {
    #[cfg(any(feature = "mysql", feature = "postgres"))]
    {
        use sea_orm::{DbErr, RuntimeErr, SqlxError};

        let (DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(db)))
        | DbErr::Query(RuntimeErr::SqlxError(SqlxError::Database(db)))) = err
        else {
            return None;
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

/// Must happen at the adapter boundary: every call site stringifies the `DbErr`
/// immediately, so this is the last point where the driver's `SQLSTATE`/error
/// number still exists.
///
/// Logs because classification is lossy — the client sees only
/// `409 write_contention`. `warn`, not `error`, so it stays out of alerting.
pub(super) fn contention_err(err: &sea_orm::DbErr) -> Option<RepositoryError> {
    let code = contention_code(err)?;
    tracing::warn!(
        error = %err,
        db.contention_code = code,
        "storage write lost a lock race; classifying as retryable contention"
    );
    Some(RepositoryError::Contention { code })
}

/// The decision tables are tested directly; the downcast that feeds them cannot
/// be, because the driver error types have private payloads and cannot be
/// constructed outside their own crates. It is exercised instead by the
/// container tests in `store.rs`, one code per backend: `1205` and `40P01`.
///
/// Those two are chosen because they are reachable at READ COMMITTED. `40001`
/// is not reachable from a pinned write, but remains reachable from
/// `delete_older_than`, which inherits the server default — so the arm is live,
/// not a safety net.
#[cfg(test)]
mod tests {
    #[cfg(any(feature = "mysql", feature = "postgres"))]
    use super::*;

    /// A duplicate key is not contention. If `23505` classified as retryable, a
    /// racing publish would tell the client to retry a write that cannot succeed.
    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_unique_violation_is_not_contention() {
        assert!(classify_postgres("23505").is_none());
        assert!(classify_postgres("23503").is_none());
    }

    /// Asserts the reported code, not just the classification: it feeds the
    /// metric that separates lock-wait timeouts from deadlocks.
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
        // 57014 query_canceled, 55P03 lock_not_available (only ever raised when
        // an operator sets `lock_timeout`), 42P01 undefined_table.
        for sqlstate in ["57014", "55P03", "42P01", ""] {
            assert!(
                classify_postgres(sqlstate).is_none(),
                "SQLSTATE {sqlstate} must not classify as contention"
            );
        }
    }

    /// Same regression on the MySQL side: 1062 is a duplicate entry.
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

    /// Guards the choice of error number over `SQLSTATE`: a `SQLSTATE`-based
    /// table would classify all of these `HY000` errors as retryable.
    #[cfg(feature = "mysql")]
    #[test]
    fn mysql_other_hy000_errors_are_not_contention() {
        // 1030 got error from storage engine, 1114 table is full,
        // 1436 thread stack overrun — all HY000, none retryable.
        for number in [1030, 1114, 1436] {
            assert!(
                classify_mysql(number).is_none(),
                "error {number} shares SQLSTATE HY000 with 1205 but is not contention"
            );
        }
    }
}
