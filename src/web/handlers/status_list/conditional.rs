use tracing::warn;

/// Response type for conditional request evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalResponse {
    /// Return 304 Not Modified (client cache is fresh)
    NotModified,
    /// Return 200 OK with full body (content has changed)
    Modified,
}

/// Evaluates If-None-Match header against current ETag
///
/// Returns NotModified if any ETag in the header matches the current ETag,
/// or if the header contains the wildcard "*".
///
/// Per RFC 7232 Section 3.2: If-None-Match with GET/HEAD returns 304 when
/// any listed ETag matches the current representation.
///
/// # Arguments
/// * `if_none_match` - The If-None-Match header value (may contain comma-separated ETags)
/// * `current_etag` - The ETag computed for the current resource state
///
/// # Returns
/// * `NotModified` if any ETag matches or wildcard present
/// * `Modified` if no match or header is malformed
pub fn evaluate_if_none_match(
    if_none_match: Option<&str>,
    current_etag: &str,
) -> ConditionalResponse {
    let Some(header_value) = if_none_match else {
        return ConditionalResponse::Modified;
    };

    // Check for wildcard "*" - matches any representation
    let trimmed = header_value.trim();
    if trimmed == "*" {
        return ConditionalResponse::NotModified;
    }

    // Parse comma-separated ETags
    // ETags may be in formats: W/"value", "value", or just value (malformed)
    for etag in header_value.split(',') {
        let etag = etag.trim();

        // Skip empty entries
        if etag.is_empty() {
            continue;
        }

        // Compare directly - handles both W/"hash" and "hash" formats
        if etag == current_etag {
            return ConditionalResponse::NotModified;
        }

        // Also try removing quotes for loose matching (some clients may send malformed ETags)
        let normalized_etag = etag.trim_matches('"');
        let normalized_current = current_etag.trim_matches('"');
        if normalized_etag == normalized_current {
            return ConditionalResponse::NotModified;
        }
    }

    // No match found
    ConditionalResponse::Modified
}

/// Evaluates If-Modified-Since header against record timestamp
///
/// Returns NotModified if the resource has not been modified since the
/// provided timestamp.
///
/// Per RFC 7232 Section 3.3: If-Modified-Since with GET/HEAD returns 304
/// when the resource modification time is earlier than or equal to the
/// provided timestamp.
///
/// # Arguments
/// * `if_modified_since` - The If-Modified-Since header value (HTTP-date format)
/// * `updated_at` - Unix timestamp (seconds) of the resource's last modification
///
/// # Returns
/// * `NotModified` if resource not modified since provided time
/// * `Modified` if resource has been modified or header is malformed
pub fn evaluate_if_modified_since(
    if_modified_since: Option<&str>,
    updated_at: i64,
) -> ConditionalResponse {
    let Some(header_value) = if_modified_since else {
        return ConditionalResponse::Modified;
    };

    // Parse the HTTP-date timestamp
    let Some(client_timestamp) = parse_http_date(header_value) else {
        warn!("Malformed If-Modified-Since header: {}", header_value);
        return ConditionalResponse::Modified;
    };

    // Check for future dates (client clock skew or malicious input)
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if client_timestamp > now {
        warn!("If-Modified-Since contains future date: {}", header_value);
        return ConditionalResponse::Modified;
    }

    // Return NotModified if resource hasn't been updated since client's cached version
    if updated_at <= client_timestamp {
        ConditionalResponse::NotModified
    } else {
        ConditionalResponse::Modified
    }
}

/// Evaluates conditional request headers following RFC 7232 precedence rules
///
/// Per RFC 7232 Section 6: When both If-None-Match and If-Modified-Since are
/// present, If-None-Match takes precedence and If-Modified-Since is ignored.
///
/// # Arguments
/// * `if_none_match` - The If-None-Match header value (optional)
/// * `if_modified_since` - The If-Modified-Since header value (optional)
/// * `current_etag` - The ETag computed for the current resource state
/// * `updated_at` - Unix timestamp (seconds) of the resource's last modification
///
/// # Returns
/// * `NotModified` if conditional request conditions are met (return 304)
/// * `Modified` if conditions not met or no conditional headers present (return 200)
pub fn evaluate_conditional_request(
    if_none_match: Option<&str>,
    if_modified_since: Option<&str>,
    current_etag: &str,
    updated_at: i64,
) -> ConditionalResponse {
    // If-None-Match takes precedence per RFC 7232 Section 6
    if if_none_match.is_some() {
        return evaluate_if_none_match(if_none_match, current_etag);
    }

    // Fall back to If-Modified-Since if no If-None-Match
    evaluate_if_modified_since(if_modified_since, updated_at)
}

/// Formats Unix timestamp to HTTP-date format (RFC 7231 Section 7.1.1.1)
///
/// HTTP-date format: "Day, DD Mon YYYY HH:MM:SS GMT"
/// Example: "Mon, 27 Jul 2024 12:28:53 GMT"
///
/// # Arguments
/// * `unix_timestamp` - Unix timestamp in seconds since epoch
///
/// # Returns
/// * Formatted HTTP-date string in RFC 2822 format
pub fn format_http_date(unix_timestamp: i64) -> String {
    use time::OffsetDateTime;

    let datetime =
        OffsetDateTime::from_unix_timestamp(unix_timestamp).unwrap_or(OffsetDateTime::UNIX_EPOCH);

    // Format as RFC 2822 (HTTP-date compatible)
    datetime
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".to_string())
}

/// Parses HTTP-date format to Unix timestamp
///
/// Supports RFC 2822 date format used by HTTP-date.
/// Returns None if parsing fails.
///
/// # Arguments
/// * `date_str` - HTTP-date formatted string
///
/// # Returns
/// * `Some(timestamp)` if parsing succeeds
/// * `None` if date string is malformed
pub fn parse_http_date(date_str: &str) -> Option<i64> {
    use time::OffsetDateTime;

    // Try parsing as RFC 2822 format
    OffsetDateTime::parse(date_str, &time::format_description::well_known::Rfc2822)
        .ok()
        .map(|dt| dt.unix_timestamp())
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
        let if_none_match = "abc123"; // Malformed - missing W/ prefix and quotes

        // Malformed ETag should not match
        let result = evaluate_if_none_match(Some(if_none_match), current_etag);
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_if_modified_since_not_modified() {
        let updated_at = 1000000;
        let client_time = 1000000; // Same time
        let if_modified_since = format_http_date(client_time);

        let result = evaluate_if_modified_since(Some(&if_modified_since), updated_at);
        assert_eq!(result, ConditionalResponse::NotModified);
    }

    #[test]
    fn test_evaluate_if_modified_since_modified() {
        let updated_at = 1000000;
        let client_time = 999999; // Older time
        let if_modified_since = format_http_date(client_time);

        let result = evaluate_if_modified_since(Some(&if_modified_since), updated_at);
        assert_eq!(result, ConditionalResponse::Modified);
    }

    #[test]
    fn test_evaluate_if_modified_since_client_newer() {
        let updated_at = 999999;
        let client_time = 1000000; // Newer time
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
        let if_modified_since = format_http_date(999999); // Would indicate modified

        // If-None-Match should take precedence and return NotModified
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
        let if_modified_since = format_http_date(1000000); // Client has newer

        // Should fall back to If-Modified-Since
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
        let timestamp = 1672531200; // 2023-01-01 00:00:00 UTC
        let formatted = format_http_date(timestamp);

        // Should be in RFC 2822 format
        assert!(formatted.contains("2023"));
        // RFC 2822 uses +0000 instead of GMT
        assert!(formatted.contains("+0000") || formatted.contains("GMT"));
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
}
