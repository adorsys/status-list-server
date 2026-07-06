# OAuth Status List Specification Compliance Matrix (Draft 21)

**Version:** Draft 21 (https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
**Last Updated:** 2026-07-06
**Status:** In Progress

## Overview

This document tracks the compliance of the OAuth Status List server implementation with the latest draft of the OAuth Status List specification (draft 21). The matrix is organized by specification sections, showing which components have been implemented, partially implemented, or are not yet started.

## Compliance Matrix

| Spec Section | Feature | Status | Notes |
|--------------|---------|--------|-------|
| [1](#section-1) Introduction | Full specification read and understood | Implemented | All sections reviewed, including examples, rationale, and design considerations |
| [2](#section-2) Conventions and Definitions | All terms defined and consistently used | Implemented | Terms like "Issuer", "Status", "Client" are properly defined and used throughout |
| [3](#section-3) Terminology | All terminology matches specification | Implemented | Terms like "Status Issuer", "Status Provider", "Holder", "Relying Party" are correctly implemented |
| [4](#section-4) Status List | Core data structure implemented | Implemented | Supports compressed byte array, JSON, and CBOR formats as specified |
| [5](#section-5) Status List Token | JWT and CWT token formats implemented | Partial | JWT tokens fully implemented; CWT tokens require verification of tagging (see issue #1) |
| [6](#section-6) Referenced Token | Status claim mechanism implemented | Implemented | Status claim structure correctly implemented in JWT and CWT formats |
| [7](#section-7) Status Types | All standard status types implemented | Implemented | Supports VALID (0x00), INVALID (0x01), SUSPENDED (0x02), and APPLICATIONSPECIFIC (0x03) |
| [8](#section-8) Verification and Processing | Core validation logic implemented | Partial | Referenced Token validation is implemented; some edge cases need testing |
| [9](#section-9) Status List Aggregation | Not yet implemented | Not Started | This is a major missing feature that requires significant work |
| [10](#section-10) X.509 Certificate EKU | OID registration and EKU handling implemented | Implemented | OID `id-kp-oauthStatusSigning` is registered in config; EKU handling via `rcgen` |
| [11](#section-11) Security Considerations | Core security practices implemented | Implemented | JWT and CWT use `ES256` signatures; MAC support not implemented (as per spec) |
| [12](#section-12) Privacy Considerations | Privacy considerations documented | Implemented | Privacy guidance is documented but not enforced in code |
| [13](#section-13) Operational Considerations | All operational aspects implemented | Implemented | Token lifecycle, caching, update intervals, and linkability mitigation are all working |
| [14](#section-14) IANA Considerations | IANA registrations referenced | Implemented | All IANA references are properly documented and referenced |

## Work Items

The following gaps need to be addressed to achieve full compliance:

1. **Status List Aggregation** - Not implemented at all (Section 9)
2. **CWT Tagging Verification** - Need to verify CWT tokens use tag 18 (COSE_Sign1_Tagged) as required (Section 5.2)
3. **Content Negotiation** - Accept header handling needs to support RFC 9110 content negotiation patterns (Section 8.1)
4. **Gzip Scoping** - Gzip should only apply to JWT responses, not CWT (Section 8.2)
5. **Historical Resolution** - `time=` query parameter support is missing (Section 8.4)
6. **CWT Claim Key Verification** - Need to verify `65533` claim key matches spec IANA registration (Section 14.3)

## Priority Summary

### High Priority (Must Fix)
1. Status List Aggregation (Section 9) - Core functionality missing
2. CWT Tagging Verification (Section 5.2) - Critical for spec compliance
3. Content Negotiation (Section 8.1) - Required by RFC 9110
4. Gzip Scoping (Section 8.2) - Out of spec compliance

### Medium Priority
1. CWT Claim Key Verification (Section 14.3) - Needs validation against spec
2. Historical Resolution (Section 8.4) - Optional but valuable feature
3. Status Types Expansion - Consider adding custom status types

### Low Priority
1. Privacy Considerations - Mostly documentation, no code changes needed
2. Operational Considerations - All implemented and working

## Next Steps

1. Create GitHub issues for each high-priority gap
2. Link issues in the compliance matrix
3. Implement the missing functionality
4. Create a PR with all changes

## Work Items Details

### 1. Status List Aggregation (Section 9)
- **Status:** Not Started
- **Files to touch:** `src/web/handlers/status_list/`, `src/database/`
- **Description:** Implement mechanism to retrieve aggregated status lists from multiple tokens/issuers
- **Priority:** High

### 2. CWT Tagging Verification (Section 5.2)
- **Status:** Partial
- **Files to touch:** `src/web/handlers/status_list/get_status_list.rs`
- **Description:** Verify CWT tokens use tag 18 (COSE_Sign1_Tagged) and not tag 61 (CWT tag)
- **Priority:** High
- **Issue:** #1 (to be created)

### 3. Content Negotiation (Section 8.1)
- **Status:** Partial
- **Files to touch:** `src/web/handlers/status_list/get_status_list.rs`
- **Description:** Implement RFC 9110 content negotiation for Accept header
- **Priority:** Medium
- **Issue:** #2 (to be created)

### 4. Gzip Scoping (Section 8.2)
- **Status:** Partial
- **Files to touch:** `src/web/handlers/status_list/get_status_list.rs`
- **Description:** Make gzip conditional on JWT format only
- **Priority:** Medium
- **Issue:** #3 (to be created)

### 5. Historical Resolution (Section 8.4)
- **Status:** Not Started
- **Files to touch:** `src/web/handlers/status_list/get_status_list.rs`
- **Description:** Implement `time=` query parameter support with proper error handling
- **Priority:** Medium

### 6. CWT Claim Key Verification (Section 14.3)
- **Status:** Partial
- **Files to touch:** `src/web/handlers/status_list/constants.rs`
- **Description:** Verify `65533` claim key matches spec IANA registration
- **Priority:** Medium
- **Issue:** #4 (to be created)

## Implementation Plan

1. **Create GitHub Issues** - One for each high-priority item
2. **Link Issues** - Add issue numbers to Notes column in matrix
3. **Implement Status List Aggregation** - Start with database schema changes
4. **Fix CWT Tagging** - Write unit tests and modify CWT builder
5. **Fix Content Negotiation** - Update Accept header handling
6. **Fix Gzip Scoping** - Make gzip conditional on JWT format
7. **Implement Historical Resolution** - Add `time=` parameter parsing
8. **Verify CWT Claim Key** - Validate against spec IANA registration
9. **Final Review** - Ensure all sections are properly covered

## References

- [draft-ietf-oauth-status-list-21](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
- [draft-ietf-oauth-status-list-11.diff.html](https://github.com/adorsys/status-list-server/blob/main/draft-ietf-oauth-status-list-11.diff.html)
- [draft-11-to-draft-21-gap-analysis.md](https://github.com/adorsys/status-list-server/blob/main/docs/draft-11-to-draft-21-gap-analysis.md)

---

*This document is a living document. Updates should be made as the implementation progresses.*