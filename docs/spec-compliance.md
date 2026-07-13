# OAuth Status List Specification Compliance Matrix (Draft 21)

**Version:** [Draft 21](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21)
**Last Updated:** 2026-07-09
**Status:** In Progress

## Project Feature Implementation Tracker

| Spec Section           | Feature                                                                                                              | Spec Status | Implementation Status | Changes Required                                                                                                                                                                                      |
| :--------------------- | :------------------------------------------------------------------------------------------------------------------- | :---------- | :-------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [§1](#section-1)       | Introduction – Overview and motivation for OAuth Status List                                                         | DRAFT       | ✅                    | None                                                                                                                                                                                                  |
| [§2](#section-2)       | Conventions and Definitions – RFC 2119 key words (MUST, SHOULD, etc.)                                                | DRAFT       | ✅                    | None                                                                                                                                                                                                  |
| [§3](#section-3)       | Terminology – Issuer, Holder, Relying Party, Status, Client definitions                                              | DRAFT       | ✅                    | None                                                                                                                                                                                                  |
| [§4](#section-4)       | Status List – Compressed bit array, JSON/CBOR encoding with `bits`, `lst`, `aggregation_uri`                         | DRAFT       | ✅                    | None – wire format unchanged from draft-11                                                                                                                                                            |
| [§5.1](#section-5.1)   | JWT Status List Token – JWS Compact Serialization with `status_list`, `bits`, `idx`, `ttl`, `exp` claims             | DRAFT       | ✅                    | None – `exp`/`ttl` already mandatory (exceeds RECOMMENDED)                                                                                                                                            |
| [§5.2](#section-5.2)   | CWT Status List Token – COSE_Sign1_Tagged (tag 18) with claims: `status_list`, `bits`, `idx`, `ttl`, `exp`           | DRAFT       | ⚪                    | **Verify COSE tagging:** Write unit test asserting first byte is `0xd2` (tag 18). If `coset` emits untagged, wrap with tag 18. If wrong, fix serialization.                                           |
| [§6.1](#section-6.1)   | Status Claim – `status` object with `status_list` and `idx` for referencing tokens                                   | DRAFT       | ✅                    | None                                                                                                                                                                                                  |
| [§6.2](#section-6.2)   | Referenced Token Index – Non-negative integer `idx` pointing to status entry                                         | DRAFT       | ✅                    | None – `idx` already non-negative integer                                                                                                                                                             |
| [§6.3](#section-6.3)   | Status CBOR Structure – Generic CBOR map for CWT/SD-CWT/mdoc status embedding                                        | DRAFT       | ⚪                    | **Track downstream consumers:** Server doesn't issue Referenced Tokens. Audit any integration using removed draft-11 mdoc embedding pattern.                                                          |
| [§7](#section-7)       | Status Types – Single status value per token (1/2/4/8-bit encoded)                                                   | DRAFT       | ✅                    | None – `decode_status_array` reads contiguous bits as one value                                                                                                                                       |
| [§7.1](#section-7.1)   | Status Type Values – VALID (0x00), INVALID (0x01), SUSPENDED (0x02), APPLICATIONSPECIFIC (0x03–0x0F)                 | DRAFT       | ✅                    | None – Reserved range `0x0C–0x0F` correct (no hardcoded `0x0B`). Custom types must register with IANA.                                                                                                |
| [§8.1](#section-8.1)   | HTTP Content Negotiation – RFC 9110 Accept header with `application/statuslist+jwt` and `application/statuslist+cwt` | DRAFT       | ⚪                    | **Loosen Accept header:** Support RFC 9110 patterns: `*/*`, `application/*`, quality factors (`q=`). Default to JWT if absent. Return 406 only for explicitly unsupported types.                      |
| [§8.2](#section-8.2)   | GIFRS Encoding – JWT (JWS Compact) and CWT (CBOR) raw binary formats                                                 | DRAFT       | ⚪                    | **Scope gzip to JWT only:** Draft-21 makes gzip RECOMMENDED for JWT, not CWT. Make `GzEncoder` conditional on JWT format. Remove `Content-Encoding: gzip` from CWT responses.                         |
| [§8.3](#section-8.3)   | Referenced Token Validation – Signature, expiry, bounds checking before status evaluation                            | DRAFT       | ⚪                    | **Out-of-bounds:** Add specific `Error::IndexOutOfBounds` variant if future RP role added. For now, `apply_updates` returns generic error.                                                            |
| [§8.4](#section-8.4)   | Historical Resolution – `time=` query parameter for historical status retrieval                                      | DRAFT       | ❌                    | **Implement optional:** Parse `time=` param. If unsupported timestamp → 404 Not Found. If feature unsupported → 501 Not Implemented. Client MUST reject responses outside token's `iat`/`exp` window. |
| [§9](#section-9)       | Status List Aggregation – Fetching status lists from multiple issuers via `aggregation_uri`                          | DRAFT       | ❌                    | **Implement full feature:** Fetch aggregated status lists from multiple issuers. Handle multiple `status_lists` entries with error tolerance.                                                         |
| [§9.1](#section-9.1)   | Issuer Metadata – RFC 8414 discovery with `credential_issuer` and `authorization_server`                             | DRAFT       | ✅                    | None – Optional capability, not a MUST requirement                                                                                                                                                    |
| [§9.3](#section-9.3)   | Status List Data Structure – JSON object with `status_lists` array containing token URIs and metadata                | DRAFT       | ✅                    | None                                                                                                                                                                                                  |
| [§10](#section-10)     | X.509 Certificate EKU – OID `id-kp-oauthStatusSigning` for TLFS certificate validation                               | DRAFT       | ⚪                    | **Update OID:** Rename `id-kp-oauthStatusListSigning` → `id-kp-oauthStatusSigning` across config/comments. Replace placeholder `30` with real IANA-assigned arc when available.                       |
| [§11.2](#section-11.2) | JWT/CWT Security – RFC 8725/8392 MUST compliance, algorithm pinning ES256                                            | DRAFT       | ✅                    | None – Already pinned to ES256. Audit any future verification code for algorithm allow-listing.                                                                                                       |
| [§11.6](#section-11.6) | Token Protection – Digital signatures (ES256) over MACs as default                                                   | DRAFT       | ✅                    | None – Exclusively uses ES256, no MAC usage                                                                                                                                                           |
| [§12](#section-12)     | Privacy Considerations – Issuer tracking mitigation, linkability, batching guidance                                  | DRAFT       | ✅                    | None – Informational only, client-side guidance                                                                                                                                                       |
| [§13](#section-13)     | Operational Considerations – Update intervals, caching, revocation strategies                                        | DRAFT       | ✅                    | None                                                                                                                                                                                                  |
| [§14](#section-14)     | IANA Considerations – Status Type registry, JWT/CWT claim registrations, media types                                 | DRAFT       | ⚪                    | **Verify CWT claim key:** Confirm `STATUS_LIST = 65533` matches draft-21 §14.3.1 IANA registry. Update if spec assigns different number.                                                              |

## Implementation Details

- ✅ = Implemented
- ⚪ = Partial (needs verification or minor work)
- ❌ = Not Started

## References

- [Draft 21](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21)
- [RFC 9470: OAuth 2.0 JWT Status Lists](https://datatracker.ietf.org/doc/html/rfc9470)

<a id="section-1"></a>

## Section 1

### Introduction

See [Spec Section §1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-1) for overview and motivation.

<a id="section-2"></a>

## Section 2

### Conventions and Definitions

See [Spec Section §2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-2) for RFC 2119 keywords.

<a id="section-3"></a>

## Section 3

### Terminology

See [Spec Section §3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-3) for definitions.

<a id="section-4"></a>

## Section 4

### Status List

See [Spec Section §4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4) for compressed bit array specification.

<a id="section-5.1"></a>

## Section 5.1

### JWT Status List Token

See [Spec Section §5.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1) for JWT token claims.

<a id="section-5.2"></a>

## Section 5.2

### CWT Status List Token

See [Spec Section §5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.2) for CWT token specification.

<a id="section-6.1"></a>

## Section 6.1

### Status Claim

See [Spec Section §6.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1) for status claim structure.

<a id="section-6.2"></a>

## Section 6.2

### Referenced Token Index

See [Spec Section §6.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2) for index specification.

<a id="section-6.3"></a>

## Section 6.3

### Status CBOR Structure

See [Spec Section §6.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3) for CBOR structure.

<a id="section-7"></a>

## Section 7

### Status Types

See [Spec Section §7](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7) for status type encodings.

<a id="section-7.1"></a>

## Section 7.1

### Status Type Values

See [Spec Section §7.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1) for defined values.

<a id="section-8.1"></a>

## Section 8.1

### HTTP Content Negotiation

See [Spec Section §8.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1) for HTTP negotiation.

<a id="section-8.2"></a>

## Section 8.2

### GIFRS Encoding

See [Spec Section §8.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2) for encoding specification.

<a id="section-8.3"></a>

## Section 8.3

### Referenced Token Validation

See [Spec Section §8.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3) for validation requirements.

<a id="section-8.4"></a>

## Section 8.4

### Historical Resolution

See [Spec Section §8.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.4) for historical status retrieval.

<a id="section-9"></a>

## Section 9

### Status List Aggregation

See [Spec Section §9](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-9) for aggregation specification.

<a id="section-9.1"></a>

## Section 9.1

### Issuer Metadata

See [Spec Section §9.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-9.1) for issuer discovery.

<a id="section-9.3"></a>

## Section 9.3

### Status List Data Structure

See [Spec Section §9.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-9.3) for data structure.

<a id="section-10"></a>

## Section 10

### X.509 Certificate EKU

See [Spec Section §10](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-10) for EKU specification.

<a id="section-11.2"></a>

## Section 11.2

### JWT/CWT Security

See [Spec Section §11.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.2) for security requirements.

<a id="section-11.6"></a>

## Section 11.6

### Token Protection

See [Spec Section §11.6](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.6) for token protection.

<a id="section-12"></a>

## Section 12

### Privacy Considerations

See [Spec Section §12](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-12) for privacy guidance.

<a id="section-13"></a>

## Section 13

### Operational Considerations

See [Spec Section §13](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-13) for operational guidance.

<a id="section-14"></a>

## Section 14

### IANA Considerations

See [Spec Section §14](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14) for IANA registration requirements.
