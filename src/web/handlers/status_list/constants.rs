pub(super) const ACCEPT_STATUS_LISTS_HEADER_JWT: &str = "application/statuslist+jwt";
pub(super) const ACCEPT_STATUS_LISTS_HEADER_CWT: &str = "application/statuslist+cwt";
pub(super) const STATUS_LISTS_HEADER_JWT: &str = "statuslist+jwt";
pub(super) const STATUS_LISTS_HEADER_CWT: &str = "statuslist+cwt";

// CBOR Web Token (CWT) constants
pub(super) const CWT_TYPE: i64 = 16;
pub(super) const SUBJECT: i32 = 2;
pub(super) const ISSUED_AT: i32 = 6;
pub(super) const EXP: i32 = 4;
pub(super) const TTL: i32 = 65534;
pub(super) const STATUS_LIST: i32 = 65533;
