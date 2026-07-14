# Implementation Plan: HTTP Caching Headers

## Overview

This implementation adds HTTP caching support to the `GET /api/v1/statuslists/{list_id}` endpoint by introducing ETag-based and time-based conditional requests. The approach involves:

1. Adding an `updated_at` timestamp field to the database schema
2. Implementing ETag generation from status list content
3. Adding conditional request evaluation logic
4. Modifying the GET handler to support 304 Not Modified responses
5. Updating publish/update handlers to maintain timestamps
6. Comprehensive testing with property-based tests for correctness properties

All tasks build incrementally, with early validation through tests to catch issues before full integration.

## Tasks

- [x] 1. Database schema migration - Add updated_at column
  - Create migration to add `updated_at: i64` column to `status_lists` table
  - Set default value to 0 for existing records
  - Update `src/models.rs` to add `updated_at` field to `status_lists::Model`
  - Run migration and verify schema change
  - _Requirements: 9.1, 9.3, 9.4_

- [ ] 2. Implement ETag generation module
  - [x] 2.1 Create `src/web/handlers/status_list/etag.rs` module
    - Implement `generate_etag(record: &StatusListRecord) -> String` function
    - Use SHA-256 to hash concatenation of bits, lst, issuer, and sub
    - Format as weak ETag with `W/"` prefix and quotes
    - Add module to `src/web/handlers/status_list/mod.rs`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8_

  - [ ]* 2.2 Write unit tests for ETag generation
    - Test with known record produces expected hash
    - Test weak validator format (starts with `W/"`, ends with `"`)
    - Test with empty strings and special characters
    - Test with maximum length lst values
    - _Requirements: 1.1, 1.7, 1.8_

  - [ ]* 2.3 Write property test for ETag determinism
    - **Property 1: ETag Determinism**
    - **Validates: Requirements 1.1**
    - Generate ETag twice for same record, verify equality

  - [ ]* 2.4 Write property test for ETag field sensitivity
    - **Property 2: ETag Field Sensitivity**
    - **Validates: Requirements 1.2, 1.3, 1.4, 1.5**
    - Change each field (bits, lst, issuer, sub), verify ETag changes

  - [ ]* 2.5 Write property test for ETag format independence
    - **Property 3: ETag Format Independence**
    - **Validates: Requirements 1.6**
    - Verify ETag is identical regardless of JWT/CWT format

  - [ ]* 2.6 Write property test for weak validator format
    - **Property 4: ETag Weak Validator Format**
    - **Validates: Requirements 1.7, 1.8**
    - Verify all ETags start with `W/"` and end with `"`

- [ ] 3. Implement conditional request evaluation module
  - [x] 3.1 Create `src/web/handlers/status_list/conditional.rs` module
    - Define `ConditionalResponse` enum (NotModified, Modified)
    - Implement `evaluate_if_none_match(if_none_match: Option<&str>, current_etag: &str) -> ConditionalResponse`
    - Implement `evaluate_if_modified_since(if_modified_since: Option<&str>, updated_at: i64) -> ConditionalResponse`
    - Implement `evaluate_conditional_request()` with RFC 7232 precedence
    - Implement `format_http_date(unix_timestamp: i64) -> String`
    - Implement `parse_http_date(date_str: &str) -> Option<i64>`
    - Add module to `src/web/handlers/status_list/mod.rs`
    - _Requirements: 5.1, 5.2, 5.3, 5.6, 5.7, 6.1, 6.2, 6.3, 6.4, 4.3_

  - [ ]* 3.2 Write unit tests for conditional evaluation
    - Test If-None-Match with single ETag (match and no-match)
    - Test If-None-Match with multiple comma-separated ETags
    - Test If-None-Match with wildcard `*`
    - Test If-Modified-Since with various timestamps (before, equal, after)
    - Test precedence when both headers present (If-None-Match wins)
    - Test malformed ETag header handling
    - Test malformed date header handling
    - Test future date in If-Modified-Since
    - _Requirements: 5.2, 5.3, 5.6, 5.7, 6.2, 6.3, 6.4, 10.1, 10.2, 10.3_

  - [ ]* 3.3 Write unit tests for HTTP-date formatting
    - Format known timestamps and verify RFC 2822 format
    - Parse various valid date formats
    - Test parsing invalid formats returns None
    - Test edge cases (Unix epoch, far future)
    - _Requirements: 4.3_

  - [ ]* 3.4 Write property test for conditional ETag matching
    - **Property 5: Conditional Request ETag Matching**
    - **Validates: Requirements 5.2, 5.3**
    - Verify 304 returned if and only if ETag matches

  - [ ]* 3.5 Write property test for multiple ETag matching
    - **Property 6: Multiple ETag Matching**
    - **Validates: Requirements 5.6**
    - Verify 304 returned when any ETag in list matches

  - [ ]* 3.6 Write property test for time-based conditional matching
    - **Property 7: Time-based Conditional Request Matching**
    - **Validates: Requirements 6.2, 6.3**
    - Verify 304 returned if and only if not modified since client time

  - [ ]* 3.7 Write property test for HTTP-date round-trip
    - **Property 8: HTTP-date Format Validity**
    - **Validates: Requirements 4.3**
    - Format timestamp to HTTP-date and parse back, verify equality

  - [ ]* 3.8 Write property test for invalid header tolerance
    - **Property 9: Invalid Conditional Header Tolerance**
    - **Validates: Requirements 10.1, 10.2**
    - Verify malformed headers treated as absent (return 200)

- [ ] 4. Update publish and update handlers to set timestamps
  - [x] 4.1 Modify `src/web/handlers/status_list/publish_status.rs`
    - Add `use time::OffsetDateTime`
    - Set `updated_at` field to `OffsetDateTime::now_utc().unix_timestamp()` when creating records
    - _Requirements: 9.1, 9.3_

  - [x] 4.2 Modify `src/web/handlers/status_list/update_status.rs`
    - Add `use time::OffsetDateTime`
    - Update `updated_at` field to `OffsetDateTime::now_utc().unix_timestamp()` when updating records
    - _Requirements: 9.2, 9.3_

  - [ ]* 4.3 Write integration tests for timestamp persistence
    - Test PUT creates record with non-zero updated_at
    - Test PATCH updates the updated_at timestamp
    - Test timestamps are UTC and have second-level precision
    - _Requirements: 9.1, 9.2, 9.3_

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Implement Cache-Control header builders
  - [x] 6.1 Add helper functions to `src/web/handlers/status_list/get_status_list.rs`
    - Implement `build_cache_control(token_ttl_secs: u64) -> String` 
    - Format as `"public, max-age={token_ttl_secs}, immutable"`
    - Implement `build_error_cache_control() -> &'static str`
    - Return `"no-store, max-age=0"`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 8.1, 8.2, 8.3_

  - [ ]* 6.2 Write unit tests for Cache-Control builders
    - Test success Cache-Control includes public, max-age, immutable
    - Test error Cache-Control includes no-store, max-age=0
    - Verify exact formatting matches HTTP spec
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 8.1, 8.2, 8.3_

- [ ] 7. Modify GET handler for conditional requests
  - [x] 7.1 Update `get_status_list` function signature and logic
    - Extract `If-None-Match` and `If-Modified-Since` headers from request
    - Generate ETag using `generate_etag(&status_record)`
    - Format Last-Modified using `format_http_date(status_record.updated_at)`
    - Evaluate conditional request using `evaluate_conditional_request()`
    - Build 304 response with headers (ETag, Last-Modified, Cache-Control) but no body
    - Build 200 response with full token and all caching headers
    - _Requirements: 3.1, 3.2, 3.3, 4.1, 4.2, 5.1, 5.2, 5.3, 5.4, 5.5, 6.1, 6.2, 6.3, 6.4, 6.5_

  - [x] 7.2 Update `build_response_from_record` to accept ETag and Last-Modified
    - Add ETag header to 200 responses
    - Add Last-Modified header to 200 responses  
    - Add Cache-Control header using `build_cache_control()`
    - Maintain existing Content-Type and Content-Encoding headers
    - _Requirements: 2.1, 2.5, 3.1, 3.2, 3.3, 4.1, 4.2, 4.3, 4.4, 7.1, 7.2, 7.3, 7.4_

  - [x] 7.3 Create `build_304_response` function
    - Return 304 status code
    - Include ETag, Last-Modified, and Cache-Control headers
    - Omit response body
    - _Requirements: 5.4, 5.5, 6.5_

  - [ ] 7.4 Update error response paths to include no-store Cache-Control
    - Add Cache-Control header with `build_error_cache_control()` to all error responses
    - Omit ETag and Last-Modified from error responses
    - Cover 404, 500, and 503 error cases
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [ ]* 7.5 Write unit tests for handler modifications
    - Test 200 response includes ETag, Last-Modified, Cache-Control
    - Test 304 response includes headers but no body
    - Test If-None-Match matching returns 304
    - Test If-None-Match not matching returns 200
    - Test If-Modified-Since logic (with and without If-None-Match)
    - Test both JWT and CWT formats get same caching headers
    - Test cache hit and miss both include ETag
    - Test error responses include no-store Cache-Control
    - Test error responses omit ETag and Last-Modified
    - _Requirements: 2.5, 3.1, 3.2, 3.3, 3.4, 4.1, 4.2, 4.4, 5.2, 5.3, 5.4, 5.5, 6.2, 6.3, 6.5, 8.1, 8.2, 8.3, 8.4_

- [ ] 8. Handle malformed conditional request headers with logging
  - [~] 8.1 Add logging for malformed headers in conditional evaluation
    - Log warning when If-None-Match contains invalid ETag syntax
    - Log warning when If-Modified-Since contains invalid date format
    - Log warning when If-Modified-Since contains future date
    - Use `tracing::warn!` with structured context
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

  - [ ]* 8.2 Write integration tests for malformed header logging
    - Send requests with malformed If-None-Match, verify warning logged
    - Send requests with malformed If-Modified-Since, verify warning logged
    - Verify 200 response returned for malformed headers
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

- [~] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ]* 10. Write integration tests for end-to-end caching behavior
  - [ ]* 10.1 Test full request cycle with conditional requests
    - Create status list via PUT
    - GET with no conditional headers, verify 200 with all headers
    - GET with matching If-None-Match, verify 304
    - GET with non-matching If-None-Match, verify 200
    - GET with matching If-Modified-Since, verify 304
    - GET with non-matching If-Modified-Since, verify 200
    - Update status list via PATCH
    - GET with old ETag, verify 304 not returned (ETag changed)
    - _Requirements: 1.1, 2.1, 3.1, 4.1, 5.2, 5.3, 6.2, 6.3, 9.2_

  - [ ]* 10.2 Test gzip encoding with ETags
    - Request with Accept-Encoding: gzip
    - Verify ETag present and Content-Encoding: gzip present
    - Request with If-None-Match matching ETag, verify 304
    - Verify 304 includes same ETag regardless of Accept-Encoding changes
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

  - [ ]* 10.3 Test JWT and CWT format consistency
    - GET same list as JWT, capture ETag
    - GET same list as CWT, capture ETag
    - Verify ETags are identical
    - Test conditional requests work for both formats
    - _Requirements: 1.6, 2.5, 3.3, 4.4_

- [ ] 11. Update OpenAPI specification
  - [~] 11.1 Modify `docs/openapi.yaml` for GET /api/v1/statuslists/{list_id}
    - Add ETag response header to 200 responses
    - Add Last-Modified response header to 200 responses
    - Add Cache-Control response header to 200 responses
    - Add If-None-Match request header parameter (optional)
    - Add If-Modified-Since request header parameter (optional)
    - Add 304 Not Modified response with headers but no body
    - Update error responses (404, 500, 503) to include Cache-Control header
    - Add examples for conditional request/response flows
    - _Requirements: 2.1, 3.1, 4.1, 5.1, 6.1, 8.1, 8.2, 8.3_

- [~] 12. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements from the requirements document for traceability
- Property-based tests validate universal correctness properties defined in the design
- Unit tests validate specific examples and edge cases
- Checkpoints ensure incremental validation throughout implementation
- The implementation is fully backward compatible - clients not sending conditional headers continue to work unchanged
- Database migration adds a non-nullable column with default value 0, so existing records will work correctly
