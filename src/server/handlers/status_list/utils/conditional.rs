use time::macros::format_description;
use tracing::warn;

const IMF_FIXDATE: &[time::format_description::BorrowedFormatItem<'static>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConditionalResponse {
    NotModified,
    Modified,
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
) -> ConditionalResponse {
    let Some(header_value) = if_modified_since else {
        return ConditionalResponse::Modified;
    };

    let Some(client_timestamp) = parse_http_date(header_value) else {
        warn!("Malformed If-Modified-Since header: {}", header_value);
        return ConditionalResponse::Modified;
    };

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if client_timestamp > now {
        warn!("If-Modified-Since contains future date: {}", header_value);
        return ConditionalResponse::Modified;
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
) -> ConditionalResponse {
    if if_none_match.is_some() {
        return evaluate_if_none_match(if_none_match, current_etag);
    }
    evaluate_if_modified_since(if_modified_since, updated_at)
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
    fn test_evaluate_if_modified_since_not_modified() {
        let updated_at = 1000000;
        let client_time = 1000000;
        let if_modified_since = format_http_date(client_time);

        let result = evaluate_if_modified_since(Some(&if_modified_since), updated_at);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_if_modified_since_modified() {
        let updated_at = 1000000;
        let client_time = 999999;
        let if_modified_since = format_http_date(client_time);

        let result = evaluate_if_modified_since(Some(&if_modified_since), updated_at);
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_if_modified_since_client_newer() {
        let updated_at = 999999;
        let client_time = 1000000;
        let if_modified_since = format_http_date(client_time);

        let result = evaluate_if_modified_since(Some(&if_modified_since), updated_at);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_if_modified_since_none_header() {
        let updated_at = 1000000;

        let result = evaluate_if_modified_since(None, updated_at);
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_if_modified_since_malformed() {
        let updated_at = 1000000;
        let if_modified_since = "not a valid date";

        let result = evaluate_if_modified_since(Some(if_modified_since), updated_at);
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_conditional_request_if_none_match_precedence() {
        let current_etag = r#"W/"abc123""#;
        let if_none_match = r#"W/"abc123""#;
        let updated_at = 1000000;
        let if_modified_since = format_http_date(999999);

        let result = evaluate_conditional_request(
            Some(if_none_match),
            Some(&if_modified_since),
            current_etag,
            updated_at,
        );
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_conditional_request_if_modified_since_fallback() {
        let current_etag = r#"W/"abc123""#;
        let updated_at = 999999;
        let if_modified_since = format_http_date(1000000);

        let result =
            evaluate_conditional_request(None, Some(&if_modified_since), current_etag, updated_at);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_conditional_request_no_headers() {
        let current_etag = r#"W/"abc123""#;
        let updated_at = 1000000;

        let result = evaluate_conditional_request(None, None, current_etag, updated_at);
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
