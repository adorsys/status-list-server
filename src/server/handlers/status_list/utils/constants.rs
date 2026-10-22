pub(crate) const ACCEPT_STATUS_LISTS_HEADER_JWT: &str = "application/statuslist+jwt";
pub(crate) const ACCEPT_STATUS_LISTS_HEADER_CWT: &str = "application/statuslist+cwt";
pub(crate) const STATUS_LISTS_HEADER_JWT: &str = "statuslist+jwt";

/// COSE "type" (label 16) must be the full media type, unlike JWT's short typ (§5.2).
pub(crate) const STATUS_LISTS_CWT_TYPE_VALUE: &str = "application/statuslist+cwt";

// CWT and COSE integer labels.
pub(crate) const CWT_TYPE: i64 = 16;
pub(crate) const SUBJECT: i32 = 2;
pub(crate) const ISSUED_AT: i32 = 6;
pub(crate) const EXP: i32 = 4;
pub(crate) const TTL: i32 = 65534;
pub(crate) const STATUS_LIST: i32 = 65533;

pub(crate) const GZIP_HEADER: &str = "gzip";
