//! Concern-based tests for [`crate::outbound::sql::store`], split out of
//! the former single `mod test`. Shared setup lives in `fixtures`.

mod contention;
mod credentials;
mod fixtures;
mod history;
mod status_list;
