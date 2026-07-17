pub(super) const ACCEPT_STATUS_LISTS_HEADER_JWT: &str = "application/statuslist+jwt";
pub(super) const ACCEPT_STATUS_LISTS_HEADER_CWT: &str = "application/statuslist+cwt";
pub(super) const STATUS_LISTS_HEADER_JWT: &str = "statuslist+jwt";

/// COSE label 16 ("type") value — unlike JWT's abbreviated `typ`, CWT's MUST be the full media type (§5.2).
pub(super) const STATUS_LISTS_CWT_TYPE_VALUE: &str = "application/statuslist+cwt";

// CBOR Web Token (CWT) constants
pub(super) const CWT_TYPE: i64 = 16;
pub(super) const SUBJECT: i32 = 2;
pub(super) const ISSUED_AT: i32 = 6;
pub(super) const EXP: i32 = 4;
pub(super) const TTL: i32 = 65534;
pub(super) const STATUS_LIST: i32 = 65533;

pub(super) const GZIP_HEADER: &str = "gzip";

/// Cache-Control directive for error responses — prevents caching of error states.
pub(super) const ERROR_CACHE_CONTROL: &str = "no-store, max-age=0";
