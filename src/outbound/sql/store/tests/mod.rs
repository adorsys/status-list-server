//! Concern-based tests for [`crate::outbound::sql::store`], split out of the
//! former single `mod test`. Shared setup lives in `fixtures`; each sibling
//! module covers one repository concern.

/// Multi-backend contention/race tests (locked, deadlock, serialization).
mod contention;
/// Credential round-trip, duplicate-PK mapping, and mock-backed store tests.
mod credentials;
/// Shared JWK const, sqlite connection, credential seeding, and record/snapshot builders.
mod fixtures;
/// `delete_older_than` sweep coverage against real SQLite.
mod history;
/// Status-list find/round-trip, optimistic-guard, atomicity, and duplicate mapping tests.
mod status_list;
