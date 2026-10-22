use time::macros::format_description;

const IMF_FIXDATE: &[time::format_description::BorrowedFormatItem<'static>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConditionalResponse {
    NotModified,
    Modified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TokenValidity {
    /// Length of a token validity window, and the `exp - iat` of a minted token.
    pub exp_secs: u64,
    /// Sent as max-age and as the token's ttl claim.
    pub ttl_secs: u64,
}

impl TokenValidity {
    pub(crate) const fn new(exp_secs: u64, ttl_secs: u64) -> Self {
        Self { exp_secs, ttl_secs }
    }
}

/// Windows are exactly one token lifetime wide, so a token never outlives its window.
pub(crate) fn token_window(now: i64, validity: TokenValidity) -> (i64, i64) {
    let width = window_width(validity.exp_secs);
    let start = now.div_euclid(width) * width;
    (start, start.saturating_add(width))
}

pub(crate) fn window_width(exp_secs: u64) -> i64 {
    let exp = i64::try_from(exp_secs).unwrap_or(i64::MAX);
    exp.max(1)
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

/// Only If-None-Match can earn a 304; If-Modified-Since alone never does.
pub(crate) fn evaluate_conditional_request(
    if_none_match: Option<&str>,
    current_etag: &str,
) -> ConditionalResponse {
    if if_none_match.is_some()
        && evaluate_if_none_match(if_none_match, current_etag) == ConditionalResponse::NotModified
    {
        ConditionalResponse::NotModified
    } else {
        ConditionalResponse::Modified
    }
}

pub(crate) fn format_http_date(unix_timestamp: i64) -> String {
    use time::OffsetDateTime;

    let datetime =
        OffsetDateTime::from_unix_timestamp(unix_timestamp).unwrap_or(OffsetDateTime::UNIX_EPOCH);

    datetime
        .format(IMF_FIXDATE)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

/// Only used by tests.
#[allow(dead_code)]
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
        let v = TokenValidity::new(900, 300);
        assert_eq!(token_window(1_000_000, v), (999_900, 1_000_800));
        assert_eq!(token_window(1_000_300, v), (999_900, 1_000_800));
        assert_eq!(token_window(1_000_800, v), (1_000_800, 1_001_700));
    }

    #[test]
    fn test_token_window_expiry_sized() {
        for ttl in [0u64, 300, 600, 899, 900] {
            let v = TokenValidity::new(900, ttl);
            assert_eq!(token_window(1_000_000, v), (999_900, 1_000_800));
        }
    }

    #[test]
    fn test_token_window_degenerate_no_usable_lifetime() {
        assert_eq!(
            token_window(1_000_000, TokenValidity::new(0, 300)),
            (1_000_000, 1_000_001)
        );
    }

    #[test]
    fn test_evaluate_conditional_request_matching_etag_certifies_304() {
        let current_etag = r#""abc123""#;
        let if_none_match = r#""abc123""#;

        let result = evaluate_conditional_request(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_conditional_request_weak_vs_strong_match() {
        let current_etag = r#""abc123""#;
        for inm in [r#""abc123""#, r#"W/"abc123""#] {
            assert_eq!(
                evaluate_conditional_request(Some(inm), current_etag),
                ConditionalResponse::NotModified
            );
        }
    }

    #[test]
    fn test_evaluate_conditional_request_no_match_modified() {
        let current_etag = r#""abc123""#;
        let if_none_match = r#""different""#;

        let result = evaluate_conditional_request(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_conditional_request_wildcard() {
        let result = evaluate_conditional_request(Some("*"), r#""abc123""#);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_conditional_request_no_inm_modified() {
        assert_eq!(
            evaluate_conditional_request(None, r#""abc123""#),
            ConditionalResponse::Modified
        );
    }

    #[test]
    fn test_evaluate_conditional_request_multiple_etags() {
        let current_etag = r#""abc123""#;
        let if_none_match = r#""xyz789", "abc123", "def456""#;
        assert_eq!(
            evaluate_conditional_request(Some(if_none_match), current_etag),
            ConditionalResponse::NotModified
        );
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
