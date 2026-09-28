use time::macros::format_description;
use tracing::warn;

const IMF_FIXDATE: &[time::format_description::BorrowedFormatItem<'static>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConditionalResponse {
    NotModified,
    Modified,
    /// A 304 must not be answered even though the representation is unchanged.
    ExpiredToken,
}

/// Token lifetime policy that shapes the freshness gates below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TokenValidity {
    /// Length of a token validity window, and the `exp - iat` of a minted token.
    pub exp_secs: u64,
    /// Minimum remaining validity required before a 304 is certified.
    pub ttl_secs: u64,
}

impl TokenValidity {
    pub(crate) const fn new(exp_secs: u64, ttl_secs: u64) -> Self {
        Self { exp_secs, ttl_secs }
    }
}

/// Boundaries of the token validity window containing `now`.
///
/// Live tokens are minted with `exp = iat + exp_secs` at request time, so the
/// server cannot know when an individual client last fetched. Anchoring the
/// validator to a window of length `W = exp_secs - ttl_secs` makes it rotate
/// every `W` seconds: within a window a matching ETag proves the client's cached
/// token still has more than `ttl_secs` of validity left, and once the window
/// rolls over the ETag changes so a stale client is served a freshly signed
/// token instead of a body-less 304. The width is clamped to `>= 1` so the
/// modulus stays meaningful for degenerate configs (`exp_secs == 0` or
/// `ttl_secs >= exp_secs`) where the caller must never certify a 304.
pub(crate) fn token_window(now: i64, validity: TokenValidity) -> (i64, i64) {
    let exp = i64::try_from(validity.exp_secs).unwrap_or(i64::MAX);
    let ttl = i64::try_from(validity.ttl_secs).unwrap_or(i64::MAX);
    let width = exp.saturating_sub(ttl).max(1);
    let start = now.div_euclid(width) * width;
    (start, start.saturating_add(width))
}

pub(crate) fn evaluate_if_none_match(
    if_none_match: Option<&str>,
    current_etag: &str,
) -> ConditionalResponse {
    let Some(header_value) = if_none_match else {
        return ConditionalResponse::Modified;
    };

    let trimmed = header_value.trim();
    if trimmed == "*" {
        return ConditionalResponse::NotModified;
    }

    for etag in header_value.split(',') {
        let etag = etag.trim();
        if etag.is_empty() {
            continue;
        }
        if etag_eq_weak(etag, current_etag) {
            return ConditionalResponse::NotModified;
        }
    }

    ConditionalResponse::Modified
}

pub(crate) fn evaluate_if_modified_since(
    if_modified_since: Option<&str>,
    updated_at: i64,
    now: i64,
    validity: TokenValidity,
) -> ConditionalResponse {
    let Some(header_value) = if_modified_since else {
        return ConditionalResponse::Modified;
    };

    let Some(client_timestamp) = parse_http_date(header_value) else {
        warn!("Malformed If-Modified-Since header: {}", header_value);
        return ConditionalResponse::Modified;
    };

    if client_timestamp > now {
        warn!("If-Modified-Since contains future date: {}", header_value);
        return ConditionalResponse::Modified;
    }

    // A client holding the current version fetched it no earlier than
    // `updated_at`, so its token stays valid until at least `updated_at +
    // exp_secs`. Never answer 304 once that bound has been reached — that would
    // strand the client with an expired token and no body — and require at least
    // `ttl_secs` of remaining validity so the relying party can actually use the
    // token (and absorb clock skew) instead of refetching at once.
    let exp_secs = i64::try_from(validity.exp_secs).unwrap_or(i64::MAX);
    let ttl_secs = i64::try_from(validity.ttl_secs).unwrap_or(i64::MAX);
    let guaranteed_valid_until = updated_at.saturating_add(exp_secs);
    if guaranteed_valid_until.saturating_sub(now) <= ttl_secs {
        return ConditionalResponse::ExpiredToken;
    }

    if updated_at <= client_timestamp {
        ConditionalResponse::NotModified
    } else {
        ConditionalResponse::Modified
    }
}

pub(crate) fn evaluate_conditional_request(
    if_none_match: Option<&str>,
    if_modified_since: Option<&str>,
    current_etag: &str,
    updated_at: i64,
    now: i64,
    validity: TokenValidity,
) -> ConditionalResponse {
    if if_none_match.is_some() {
        // `current_etag` is keyed to the current `E - ttl` window, so a match
        // alone already guarantees the cached token has enough remaining
        // validity (the window rollover enforces the expiry boundary) — no extra
        // runway check is needed. The one exception is a degenerate config where
        // `ttl >= E`: no minted token is ever usable, so never certify a 304.
        if validity.ttl_secs >= validity.exp_secs {
            return ConditionalResponse::ExpiredToken;
        }
        return if evaluate_if_none_match(if_none_match, current_etag)
            == ConditionalResponse::NotModified
        {
            ConditionalResponse::NotModified
        } else {
            ConditionalResponse::Modified
        };
    }
    evaluate_if_modified_since(if_modified_since, updated_at, now, validity)
}

pub(crate) fn format_http_date(unix_timestamp: i64) -> String {
    use time::OffsetDateTime;

    let datetime =
        OffsetDateTime::from_unix_timestamp(unix_timestamp).unwrap_or(OffsetDateTime::UNIX_EPOCH);

    datetime
        .format(IMF_FIXDATE)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

pub(crate) fn parse_http_date(date_str: &str) -> Option<i64> {
    use time::OffsetDateTime;

    OffsetDateTime::parse(date_str, IMF_FIXDATE)
        .or_else(|_| {
            OffsetDateTime::parse(date_str, &time::format_description::well_known::Rfc2822)
        })
        .ok()
        .map(|dt| dt.unix_timestamp())
}

fn normalize_etag(etag: &str) -> String {
    etag.trim()
        .trim_start_matches("W/")
        .trim_matches('"')
        .to_string()
}

fn etag_eq_weak(a: &str, b: &str) -> bool {
    normalize_etag(a) == normalize_etag(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_if_none_match_single_etag_match() {
        let current_etag = r#"W/"abc123""#;
        let if_none_match = r#"W/"abc123""#;

        let result = evaluate_if_none_match(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_if_none_match_single_etag_no_match() {
        let current_etag = r#"W/"abc123""#;
        let if_none_match = r#"W/"different""#;

        let result = evaluate_if_none_match(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_if_none_match_weak_strong_match() {
        let current_etag = r#"W/"abc123""#;
        let if_none_match = r#""abc123""#;

        let result = evaluate_if_none_match(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_if_none_match_strong_weak_match() {
        let current_etag = r#""abc123""#;
        let if_none_match = r#"W/"abc123""#;

        let result = evaluate_if_none_match(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_if_none_match_multiple_etags_with_match() {
        let current_etag = r#"W/"abc123""#;
        let if_none_match = r#"W/"xyz789", W/"abc123", W/"def456""#;

        let result = evaluate_if_none_match(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_if_none_match_multiple_etags_no_match() {
        let current_etag = r#"W/"abc123""#;
        let if_none_match = r#"W/"xyz789", W/"def456""#;

        let result = evaluate_if_none_match(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_if_none_match_wildcard() {
        let current_etag = r#"W/"abc123""#;
        let if_none_match = "*";

        let result = evaluate_if_none_match(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_if_none_match_none_header() {
        let current_etag = r#"W/"abc123""#;

        let result = evaluate_if_none_match(None, current_etag);
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_if_none_match_malformed_no_quotes() {
        let current_etag = r#"W/"abc123""#;
        let if_none_match = "abc123";

        let result = evaluate_if_none_match(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_token_window() {
        // Defaults E=900, ttl=300 -> window length W=600.
        let v = TokenValidity::new(900, 300);
        assert_eq!(token_window(1_000_000, v), (999_600, 1_000_200));
        assert_eq!(token_window(1_000_600, v), (1_000_200, 1_000_800));
        assert_eq!(token_window(1_000_200, v), (1_000_200, 1_000_800));
    }

    #[test]
    fn test_token_window_degenerate_no_usable_runway() {
        // ttl >= E leaves no usable lifetime; the window still rotates every
        // second so the caller never certifies a 304.
        assert_eq!(
            token_window(1_000_000, TokenValidity::new(300, 300)),
            (1_000_000, 1_000_001)
        );
        assert_eq!(
            token_window(1_000_000, TokenValidity::new(0, 300)),
            (1_000_000, 1_000_001)
        );
    }

    #[test]
    fn test_evaluate_if_modified_since_not_modified() {
        let updated_at = 1000000;
        let client_time = 1000000;
        let if_modified_since = format_http_date(client_time);

        let result = evaluate_if_modified_since(
            Some(&if_modified_since),
            updated_at,
            client_time + 1,
            TokenValidity::new(900, 300),
        );
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_if_modified_since_modified() {
        let updated_at = 1000000;
        let client_time = 999999;
        let if_modified_since = format_http_date(client_time);

        let result = evaluate_if_modified_since(
            Some(&if_modified_since),
            updated_at,
            1000001,
            TokenValidity::new(900, 300),
        );
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_if_modified_since_client_newer() {
        let updated_at = 999999;
        let client_time = 1000000;
        let if_modified_since = format_http_date(client_time);

        let result = evaluate_if_modified_since(
            Some(&if_modified_since),
            updated_at,
            client_time + 1,
            TokenValidity::new(900, 300),
        );
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_if_modified_since_none_header() {
        let updated_at = 1000000;

        let result =
            evaluate_if_modified_since(None, updated_at, 1000001, TokenValidity::new(900, 300));
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_if_modified_since_malformed() {
        let updated_at = 1000000;
        let if_modified_since = "not a valid date";

        let result = evaluate_if_modified_since(
            Some(if_modified_since),
            updated_at,
            1000001,
            TokenValidity::new(900, 300),
        );
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_if_modified_since_token_fully_expired() {
        // Same content (updated_at <= client_time) but `now` has passed
        // `updated_at + token_exp_secs`, so the cached token is expired and a 304
        // must not be returned.
        let updated_at = 1000000;
        let if_modified_since = format_http_date(updated_at);
        assert_eq!(
            evaluate_if_modified_since(
                Some(&if_modified_since),
                updated_at,
                updated_at + 901,
                TokenValidity::new(900, 300)
            ),
            ConditionalResponse::ExpiredToken
        );
        // At the exact expiry instant (`now == updated_at + exp`) the token is
        // expired too.
        assert_eq!(
            evaluate_if_modified_since(
                Some(&if_modified_since),
                updated_at,
                updated_at + 900,
                TokenValidity::new(900, 300)
            ),
            ConditionalResponse::ExpiredToken
        );
        // A second before expiry the token is not yet expired but has no usable
        // runway (< token_ttl_secs), so we still must not certify it with a 304.
        assert_eq!(
            evaluate_if_modified_since(
                Some(&if_modified_since),
                updated_at,
                updated_at + 899,
                TokenValidity::new(900, 300)
            ),
            ConditionalResponse::ExpiredToken
        );
    }

    #[test]
    fn test_evaluate_if_modified_since_within_ttl_runway_returns_304() {
        let updated_at = 1000000;
        let if_modified_since = format_http_date(updated_at);
        // remaining = updated_at + exp - now = 700 > token_ttl_secs (300) -> 304.
        assert_eq!(
            evaluate_if_modified_since(
                Some(&if_modified_since),
                updated_at,
                updated_at + 200,
                TokenValidity::new(900, 300)
            ),
            ConditionalResponse::NotModified
        );
    }

    #[test]
    fn test_evaluate_conditional_request_if_none_match_precedence() {
        let current_etag = r#"W/"abc123""#;
        let if_none_match = r#"W/"abc123""#;
        let updated_at = 1000000;
        let now = updated_at + 100;
        let if_modified_since = format_http_date(999999);

        let result = evaluate_conditional_request(
            Some(if_none_match),
            Some(&if_modified_since),
            current_etag,
            updated_at,
            now,
            TokenValidity::new(900, 300),
        );
        // If-None-Match takes precedence: a matching (window-keyed) ETag means
        // the cached token is still valid, regardless of how old the content is.
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_conditional_request_if_none_match_no_match_modified() {
        let current_etag = r#"W/"abc123""#;
        let if_none_match = r#"W/"different""#;
        let updated_at = 1000000;
        let now = updated_at + 100;

        let result = evaluate_conditional_request(
            Some(if_none_match),
            None,
            current_etag,
            updated_at,
            now,
            TokenValidity::new(900, 300),
        );
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_conditional_request_degenerate_ttl_ge_exp_never_304() {
        // When ttl >= E no token is ever usable, so a matching ETag must still
        // not certify a 304 -> ExpiredToken forces a fresh 200.
        let current_etag = r#"W/"abc123""#;
        let if_none_match = r#"W/"abc123""#;
        let updated_at = 1000000;

        let result = evaluate_conditional_request(
            Some(if_none_match),
            None,
            current_etag,
            updated_at,
            updated_at + 1,
            TokenValidity::new(300, 300),
        );
        assert_eq!(result, ConditionalResponse::ExpiredToken);
    }

    #[test]
    fn test_evaluate_conditional_request_if_modified_since_fallback() {
        let current_etag = r#"W/"abc123""#;
        let updated_at = 999999;
        let now = 1000001;
        let if_modified_since = format_http_date(1000000);

        let result = evaluate_conditional_request(
            None,
            Some(&if_modified_since),
            current_etag,
            updated_at,
            now,
            TokenValidity::new(900, 300),
        );
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_conditional_request_if_modified_since_expired_fallback() {
        let current_etag = r#"W/"abc123""#;
        let updated_at = 1000000;
        let if_modified_since = format_http_date(1000000);

        let result = evaluate_conditional_request(
            None,
            Some(&if_modified_since),
            current_etag,
            updated_at,
            updated_at + 901,
            TokenValidity::new(900, 300),
        );
        assert_eq!(result, ConditionalResponse::ExpiredToken);
    }

    #[test]
    fn test_evaluate_conditional_request_no_headers() {
        let current_etag = r#"W/"abc123""#;
        let updated_at = 1000000;

        let result = evaluate_conditional_request(
            None,
            None,
            current_etag,
            updated_at,
            0,
            TokenValidity::new(900, 300),
        );
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_format_http_date() {
        let timestamp = 1672531200;
        let formatted = format_http_date(timestamp);

        assert!(formatted.contains("2023"));
        assert!(formatted.contains("GMT"));
        assert!(!formatted.contains("+0000"));
    }

    #[test]
    fn test_format_http_date_rejects_rfc2822_zone() {
        let timestamp = 1672531200;
        let formatted = format_http_date(timestamp);

        assert!(formatted.contains("GMT"));
        assert!(!formatted.contains("+0000"));
    }

    #[test]
    fn test_parse_http_date_roundtrip() {
        let timestamp = 1672531200;
        let formatted = format_http_date(timestamp);
        let parsed = parse_http_date(&formatted);

        assert_eq!(parsed, Some(timestamp));
    }

    #[test]
    fn test_parse_http_date_invalid() {
        let result = parse_http_date("not a date");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_http_date_valid_rfc2822() {
        let date_str = "Sun, 01 Jan 2023 00:00:00 +0000";
        let result = parse_http_date(date_str);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_http_date_valid_imf_fixdate() {
        let date_str = "Sun, 06 Nov 1994 08:49:37 GMT";
        let result = parse_http_date(date_str);
        assert!(result.is_some());
    }
}
