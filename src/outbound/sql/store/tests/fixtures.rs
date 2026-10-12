use crate::outbound::sql::models::{StatusList, StatusListHistoryRecord, StatusListRecord};

#[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
mod database;

#[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
pub(super) use database::{
    NO_LIST_QUOTA, enforce_list_quota, insert_list_as_old_pod, list_count, seed_credential,
};
#[cfg(feature = "sqlite")]
pub(super) use database::{sqlite_connection, sqlite_connection_migrated};

pub(super) const TEST_EC_JWK: &str = crate::test_fixtures::TEST_EC_PUBLIC_JWK;

pub(super) fn record(
    list_id: &str,
    issuer: &str,
    lst: &str,
    sub: &str,
    updated_at: i64,
) -> StatusListRecord {
    StatusListRecord {
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: lst.to_string(),
            size: None,
            default_status: None,
        },
        sub: sub.to_string(),
        updated_at,
        version: 1,
    }
}

pub(super) fn snapshot(
    snapshot_id: &str,
    list_id: &str,
    issuer: &str,
    lst: &str,
    sub: &str,
    iat: i64,
    exp: i64,
) -> StatusListHistoryRecord {
    StatusListHistoryRecord {
        snapshot_id: snapshot_id.to_string(),
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: lst.to_string(),
            size: None,
            default_status: None,
        },
        sub: sub.to_string(),
        iat,
        exp,
        version: 0,
    }
}
