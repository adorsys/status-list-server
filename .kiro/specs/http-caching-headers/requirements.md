# Requirements Document

## Introduction

This document defines the requirements for implementing HTTP caching headers for the status list token retrieval endpoint (`GET /api/v1/statuslists/{list_id}`). The feature adds Cache-Control, ETag, Last-Modified, and conditional request support to enable efficient caching by relying parties and CDNs while maintaining content freshness guarantees.

The status list server currently returns compressed JWT or CWT tokens with a `ttl` field indicating the recommended cache lifetime, but does not provide corresponding HTTP-level cache directives. This creates a gap between the token-level freshness semantics and HTTP caching behavior, preventing CDNs and clients from caching responses effectively.

## Glossary

- **Status_List_Handler**: The HTTP handler responsible for processing GET requests to `/api/v1/statuslists/{list_id}`
- **ETag_Generator**: Component that generates entity tags from status list content
- **Cache_Control_Header**: HTTP header that specifies caching directives for the response
- **ETag_Header**: HTTP header that provides a unique identifier for a specific version of a resource
- **Last_Modified_Header**: HTTP header that indicates when the resource was last modified
- **Conditional_Request**: HTTP request that includes If-None-Match or If-Modified-Since headers
- **Token_TTL**: The time-to-live value in seconds from the status list token payload
- **Status_List_Record**: Database/cache record containing list_id, issuer, status_list (bits, lst), and sub
- **Gzip_Variant**: Compressed representation of the response body with Content-Encoding: gzip
- **JWT_Token**: Status list token in JSON Web Token format (application/statuslist+jwt)
- **CWT_Token**: Status list token in CBOR Web Token format (application/statuslist+cwt)

## Requirements

### Requirement 1: Generate ETag from Status List Content

**User Story:** As a relying party, I want each status list version to have a unique ETag, so that I can efficiently detect changes without downloading the full token.

#### Acceptance Criteria

1. THE ETag_Generator SHALL compute an ETag value from the status list content (bits, lst, issuer, sub)
2. WHEN the status_list.lst field changes, THE ETag_Generator SHALL produce a different ETag value
3. WHEN the status_list.bits field changes, THE ETag_Generator SHALL produce a different ETag value
4. WHEN the issuer field changes, THE ETag_Generator SHALL produce a different ETag value
5. WHEN the sub field changes, THE ETag_Generator SHALL produce a different ETag value
6. THE ETag_Generator SHALL produce the same ETag value for identical Status_List_Record content regardless of request format (JWT or CWT)
7. THE ETag_Generator SHALL prefix the ETag value with "W/" to indicate weak validation
8. THE ETag_Generator SHALL enclose the ETag value in double quotes per RFC 7232

### Requirement 2: Return Cache-Control Header with Token TTL

**User Story:** As a CDN operator, I want Cache-Control headers that match the token's TTL, so that cached responses expire at the same time as the token validity.

#### Acceptance Criteria

1. WHEN a status list token is returned, THE Status_List_Handler SHALL include a Cache_Control_Header in the response
2. THE Status_List_Handler SHALL set Cache-Control max-age to the Token_TTL value in seconds
3. THE Status_List_Handler SHALL include the "immutable" directive in the Cache_Control_Header
4. THE Status_List_Handler SHALL include the "public" directive in the Cache_Control_Header
5. FOR ALL responses (JWT_Token or CWT_Token), THE Status_List_Handler SHALL include the same Cache_Control_Header

### Requirement 3: Return ETag Header in Successful Responses

**User Story:** As a relying party client, I want an ETag header in the response, so that I can use it in subsequent conditional requests.

#### Acceptance Criteria

1. WHEN a status list token is returned with status code 200, THE Status_List_Handler SHALL include an ETag_Header in the response
2. THE ETag_Header value SHALL be the output of the ETag_Generator for the current Status_List_Record
3. FOR ALL response formats (JWT_Token or CWT_Token), THE Status_List_Handler SHALL include the ETag_Header
4. THE ETag_Header SHALL be present for both cache hits and cache misses

### Requirement 4: Return Last-Modified Header

**User Story:** As a relying party client, I want a Last-Modified header, so that I can use time-based conditional requests as a fallback.

#### Acceptance Criteria

1. WHEN a status list token is returned with status code 200, THE Status_List_Handler SHALL include a Last_Modified_Header in the response
2. THE Last_Modified_Header value SHALL be derived from the most recent update timestamp of the Status_List_Record
3. THE Last_Modified_Header SHALL be formatted according to HTTP-date format (RFC 7231 Section 7.1.1.1)
4. FOR ALL response formats (JWT_Token or CWT_Token), THE Status_List_Handler SHALL include the Last_Modified_Header

### Requirement 5: Support Conditional Requests with If-None-Match

**User Story:** As a relying party client, I want to send If-None-Match headers, so that I receive 304 Not Modified responses when content hasn't changed.

#### Acceptance Criteria

1. WHEN a request includes an If-None-Match header, THE Status_List_Handler SHALL extract the ETag value from the header
2. WHEN the If-None-Match ETag matches the current Status_List_Record ETag, THE Status_List_Handler SHALL return status code 304
3. WHEN the If-None-Match ETag does not match the current Status_List_Record ETag, THE Status_List_Handler SHALL return status code 200 with the full token
4. WHEN a 304 response is returned, THE Status_List_Handler SHALL include the ETag_Header, Cache_Control_Header, and Last_Modified_Header
5. WHEN a 304 response is returned, THE Status_List_Handler SHALL omit the response body
6. WHEN If-None-Match contains multiple ETags separated by commas, THE Status_List_Handler SHALL return 304 if any ETag matches
7. WHEN If-None-Match contains the wildcard value "*", THE Status_List_Handler SHALL return 304 if the resource exists

### Requirement 6: Support Conditional Requests with If-Modified-Since

**User Story:** As a relying party client without ETag support, I want to send If-Modified-Since headers, so that I can still benefit from conditional requests.

#### Acceptance Criteria

1. WHEN a request includes an If-Modified-Since header and no If-None-Match header, THE Status_List_Handler SHALL parse the timestamp from the header
2. WHEN the Status_List_Record has not been modified since the If-Modified-Since timestamp, THE Status_List_Handler SHALL return status code 304
3. WHEN the Status_List_Record has been modified after the If-Modified-Since timestamp, THE Status_List_Handler SHALL return status code 200 with the full token
4. WHEN both If-None-Match and If-Modified-Since headers are present, THE Status_List_Handler SHALL evaluate If-None-Match and ignore If-Modified-Since
5. WHEN a 304 response is returned via If-Modified-Since, THE Status_List_Handler SHALL include the ETag_Header, Cache_Control_Header, and Last_Modified_Header

### Requirement 7: Handle Gzip Encoding with ETags

**User Story:** As a CDN operator, I want ETags to work correctly with gzip compression, so that cached gzip variants don't cause validation issues.

#### Acceptance Criteria

1. THE ETag_Generator SHALL compute the ETag from the uncompressed Status_List_Record content before gzip compression
2. WHEN a response includes Content-Encoding: gzip, THE Status_List_Handler SHALL use the same ETag value as uncompressed responses
3. WHEN a conditional request matches the ETag for a Gzip_Variant, THE Status_List_Handler SHALL return 304 regardless of Accept-Encoding header changes
4. WHEN returning a 200 response with gzip encoding, THE Status_List_Handler SHALL include both ETag_Header and Content-Encoding headers

### Requirement 8: Maintain Cache Headers for Error Responses

**User Story:** As a relying party developer, I want clear cache behavior for error responses, so that temporary failures don't get permanently cached.

#### Acceptance Criteria

1. WHEN the Status_List_Handler returns status code 404 (not found), THE Status_List_Handler SHALL include a Cache_Control_Header with max-age=0 and no-store directives
2. WHEN the Status_List_Handler returns status code 500 (internal server error), THE Status_List_Handler SHALL include a Cache_Control_Header with max-age=0 and no-store directives
3. WHEN the Status_List_Handler returns status code 503 (service unavailable), THE Status_List_Handler SHALL include a Cache_Control_Header with max-age=0 and no-store directives
4. FOR ALL error responses (4xx and 5xx), THE Status_List_Handler SHALL omit the ETag_Header and Last_Modified_Header

### Requirement 9: Store Last-Modified Timestamp

**User Story:** As a system maintainer, I want status list records to include modification timestamps, so that Last-Modified headers can be populated accurately.

#### Acceptance Criteria

1. WHEN a status list is created via PUT /api/v1/status-lists/{list_id}/statuses, THE system SHALL store a creation timestamp with the Status_List_Record
2. WHEN a status list is updated via PATCH /api/v1/status-lists/{list_id}/statuses, THE system SHALL update the modification timestamp of the Status_List_Record
3. THE modification timestamp SHALL be stored as a UTC timestamp with at least second-level precision
4. THE Status_List_Handler SHALL access the modification timestamp without requiring additional database queries beyond the existing Status_List_Record fetch

### Requirement 10: Validate Conditional Request Headers

**User Story:** As a security engineer, I want malformed conditional request headers to be handled safely, so that invalid input doesn't cause server errors.

#### Acceptance Criteria

1. WHEN an If-None-Match header contains invalid ETag syntax, THE Status_List_Handler SHALL treat the header as not present and return status code 200
2. WHEN an If-Modified-Since header contains an invalid date format, THE Status_List_Handler SHALL treat the header as not present and return status code 200
3. WHEN an If-Modified-Since header contains a future date, THE Status_List_Handler SHALL return status code 200 with the full token
4. THE Status_List_Handler SHALL log a warning when malformed conditional request headers are encountered
