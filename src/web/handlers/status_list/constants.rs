pub(super) const ACCEPT_STATUS_LISTS_HEADER_JWT: &str = "application/statuslist+jwt";
pub(super) const ACCEPT_STATUS_LISTS_HEADER_CWT: &str = "application/statuslist+cwt";
pub(super) const STATUS_LISTS_HEADER_JWT: &str = "statuslist+jwt";

/// COSE header label 16 ("type") value for the CWT protected header (draft-ietf-oauth-status-list-21 §5.2).
/// Unlike the JWT `typ` header, which uses the abbreviated `statuslist+jwt` form, the CWT
/// type header MUST carry the full media type.
pub(super) const STATUS_LIST_CWT_TYPE_VALUE: &str = "application/statuslist+cwt";

// CBOR Web Token (CWT) constants
pub(super) const CWT_TYPE: i64 = 16;
pub(super) const SUBJECT: i32 = 2;
pub(super) const ISSUED_AT: i32 = 6;
pub(super) const EXP: i32 = 4;
pub(super) const TTL: i32 = 65534;
pub(super) const STATUS_LIST: i32 = 65533;

pub(super) const GZIP_HEADER: &str = "gzip";
