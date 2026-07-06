# OAuth Token Status List — draft-11 → draft-21 Gap Analysis

**Source:** `draft-ietf-oauth-status-list-11.diff.html` (rfcdiff, draft-11 vs draft-21)
**Spec reference (draft-21):** https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21 — section links in the tables below jump to the relevant anchor.
**Baseline:** our implementation targets draft-11 (published). This document tracks what changed on the way to draft-21 and what work is implied.

**Status legend:**
- `Implemented` — our code already conforms; no action needed.
- `Partial` — existing code satisfies part of the new requirement; needs verification or a small change.
- `Not Started` — new/changed normative behavior not yet in our code; a work item is needed.
- `N/A` — editorial/wording/renumbering only, or client-side requirement that doesn't apply to our Status Provider role.

**Note structure:** Each actionable row's Notes field is formatted as:
- **Current:** what our code does today (with file:line reference)
- **Action:** the concrete change to make (or "none — already conformant")
- **Verify:** how to confirm the change is correct

Draft-11 → draft-21 spans 10 published revisions, so most of the diff is prose cleanup. The items below are every change with actual normative or structural weight; purely cosmetic rewording is grouped as N/A so nothing is silently skipped.

---

## 1–3. Introduction, Terminology

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-1) / [§6.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2) / [§6.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3) | Add RFC 9901 (SD-JWT) as a reference; add SD-CWT (`I-D.ietf-spice-sd-cwt`) as a new Referenced Token format alongside CWT/mdoc | Not Started | **Current:** No reference to SD-JWT (RFC 9901) or SD-CWT in code or docs. **Action:** If any code/docs cite `SD-JWT.VC` draft, update to RFC 9901. SD-CWT support is not required for our server but should be noted for future interoperability. **Verify:** `grep -r "SD-JWT.VC"` / `grep -r "SD-CWT"` across the repo. |
| [§1.5](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-1.5) | Clarifies two separate "Status Mechanisms" registries exist (JOSE-based and COSE-based) | N/A | Registry structure unchanged from draft-11; wording only. No code impact. |
| [§3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-3) | New terms: "Status" (formal definition) and "Client" (app fetching on behalf of Holder/RP) | N/A | Vocabulary only. No code impact. |
| [§3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-3) | `Issuer` now also known as "Provider"; Referenced Token examples narrowed to "SD-JWT and ISO mdoc" | N/A | Terminology only. No code impact. |
| [§1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-1), [§1.1–1.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-1.1), [§3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-3) (remainder) | General prose rewording throughout | N/A | No behavioral change. |

---

## 4. Status List (byte array / JSON / CBOR encoding)

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§4.1–4.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.1) | Byte array construction, `bits`/`lst`/`aggregation_uri` fields, JSON and CBOR encoding | N/A | **Unchanged from draft-11.** Examples reformatted (binary `0b` notation, ASCII-art diagrams) but wire format and field semantics are identical. **Action:** none. Our `lst_gen.rs` already implements this. |

---

## 5. Status List Token (JWT / CWT)

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§5.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1) | `exp` claim strength raised from OPTIONAL to **RECOMMENDED** | Implemented | **Current:** `issue_jwt()` (`src/web/handlers/status_list/get_status_list.rs:277`) always sets `exp: Some(exp)` where `exp = iat + TOKEN_EXP` (900s). **Action:** none — we already exceed RECOMMENDED by making it mandatory. **Verify:** Confirm `TOKEN_EXP` in `constants.rs:17` is still `900`. |
| [§5.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1) | `ttl` claim strength raised from OPTIONAL to **RECOMMENDED** | Implemented | **Current:** `issue_jwt()` (`get_status_list.rs:273-281`) always sets `ttl: Some(ttl)` where `TOKEN_TTL = 300`. **Action:** none — already mandatory in our code. **Verify:** Confirm `TOKEN_TTL` in `constants.rs:18` is still `300`. |
| [§5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.2) | CWT Status List Token **MUST NOT** be tagged with CWT tag (61); COSE message **MUST** be `COSE_Sign1_Tagged` (18) or `COSE_Mac0_Tagged` (17) | Partial | **Current:** `issue_cwt()` (`get_status_list.rs:219-233`) uses `CoseSign1Builder` from `coset` and serializes with `.to_vec()`. It is unknown whether `coset` emits the COSE_Sign1 tag (18, byte `0xd2`) or a raw untagged structure. **Action:** (1) Write a unit test that inspects the first byte(s) of the CWT output — assert it starts with `0xd2` (tag 18) and does NOT start with `0x3f` (tag 61). (2) If `coset` emits untagged, wrap the output with CBOR tag 18 before returning. (3) If `coset` emits tag 61 (CWT tag), remove that wrapping. **Verify:** Test against the draft-21 [§5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.2) hex example which starts with `d2 84` (tag 18, array of 4). |
| [§5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.2) | `exp` (claim 4) and `ttl` (claim 65534) in CWT raised from OPTIONAL to RECOMMENDED | Implemented | **Current:** `issue_cwt()` (`get_status_list.rs:178-186`) always pushes `exp` (claim 4) and `ttl` (claim 65534) into the CWT claims map. **Action:** none. **Verify:** Test `test_get_status_list_success_cwt` already validates `ttl` is present with value 300. |
| [§5.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1)/[§5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.2) | Wording: "rules outlined in" → "structure defined in" for `status_list` claim | N/A | Wording precision only. No code impact. |

---

## 6. Referenced Token

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§6.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1) | `status_list` is clarified as "one possible member" of the `status` object (extension point) | N/A | No behavior change — already how it works. |
| [§6.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2) | `idx` simplified to "non-negative Integer" | N/A | Same constraint, tighter wording. No code impact. |
| [§6.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2) | Referenced Token in JOSE may be SD-JWT (RFC 9901) or SD-JWT VC, not just bare JWT | N/A | Framing only. Our server doesn't issue Referenced Tokens. |
| [**§6.3**](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3) | **Major restructuring:** draft-11's ISO-mdoc-specific status-embedding text (status label in MSO, mDL/IssuerAuth example) is **removed**. Replaced by a single generic **"Status CBOR structure"** (CBOR map keyed by status-mechanism identifier) shared across all CBOR-based Referenced Tokens (CWT, SD-CWT, ISO mdoc). CWT claim 65535 is now one usage of that generic structure. | Not Started | **Current:** Our server is a Status Provider (issues Status List Tokens), not a Referenced Token issuer. We don't embed status claims into mdocs/CWTs. **Action:** None for our server directly. **For downstream consumers:** if any integration encodes status per the old draft-11 mdoc-specific text (status label directly in MSO), it must be re-pointed to the generic Status CBOR structure. **Key clarification:** Our `STATUS_LIST = 65533` constant (`constants.rs:12`) is the claim key inside a Status List Token for the list *contents*. The spec's `65535` is the claim key inside a *Referenced Token's* CWT Claims Set for the `status` object. These are different claims in different contexts — they are NOT in conflict. **Verify:** Confirm no downstream consumer code references the removed draft-11 mdoc embedding pattern. |
| [§6.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3) | "COSE Web Token" → "CBOR Web Token" (typo fix) | N/A | Editorial. No code impact. |

---

## 7. Status Types

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§7](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7) | Status List conveys **exactly one status value** per token even when `bits` > 1 (whole multi-bit value = one status, not independent flags) | Implemented | **Current:** `decode_status_array()` (`lst_gen.rs:132-160`) reads a contiguous multi-bit value as a single integer and maps it to one `Status` enum variant. Does not treat individual bits as flags. **Action:** none. **Verify:** `test_create_lst_with_2_bit_statuses` confirms 2-bit values decode as single statuses (VALID/INVALID/SUSPENDED/APPLICATIONSPECIFIC). |
| [§7.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1) | Applications **MUST** use registered Status Type values when semantics match registered values | Partial | **Current:** `Status` enum (`models.rs:96-101`) defines `VALID` (0x00), `INVALID` (0x01), `SUSPENDED` (0x02), `APPLICATIONSPECIFIC` (0x03). All four match registered values. **Action:** If we add custom status types beyond these, register them with IANA per [§14.5](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.5). **Verify:** Confirm no ad-hoc numeric status values are used outside the enum. |
| [§7.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1) | Reserved application-specific range corrected from `0x0B–0x0F` to **`0x0C–0x0F`** (off-by-one fix) | Implemented | **Current:** `determine_bits()` (`lst_gen.rs:25-31`) computes bit width purely from max status value (0–1 → 1 bit, 2–3 → 2 bits, 4–15 → 4 bits, 16–255 → 8 bits). No hardcoded `0x0B` boundary. **Action:** none. **Verify:** `grep -r "0x0B\|0x0b\|11"` in status-list logic — no matches expected in boundary logic. |

---

## 8. Verification and Processing

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§8.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1) | Request model changed from "RP MUST send a specific Accept header" to **general HTTP content-negotiation per RFC 9110**; Status Provider MUST return the Status List Token unless alternative distribution exists | Partial | **Current:** `get_status_list()` (`get_status_list.rs:34-56`) checks `Accept` header, defaults to JWT if absent, but rejects any other value with `406 Not Acceptable` (`StatusListError::InvalidAcceptHeader`). **Action:** Loosen the handler to accept RFC 9110 content-negotiation patterns: `*/*`, `application/*`, and quality-factor suffixes (e.g. `Accept: application/statuslist+jwt;q=0.9, application/statuslist+cwt;q=0.1`). Specifically: (1) parse the Accept header per RFC 9110, (2) match against our two supported media types, (3) default to JWT if no preference or wildcard is given, (4) return 406 only if the client explicitly requests only unsupported types. **Verify:** Test with `Accept: */*` (should return JWT), `Accept: application/statuslist+cwt` (should return CWT), `Accept: application/xml` (should return 406). |
| [§8.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2) | HTTP response body is the **raw binary encoding** (RFC 8392 §9.2.1 binary CWT for CWT, JWS Compact Serialization for JWT) — **not** hex | Partial | **Current:** JWT path returns JWS Compact Serialization text (`issue_jwt` → `String`). CWT path returns raw CBOR bytes (`issue_cwt` → `Vec<u8>` via `sign1.to_vec()`). Both are gzipped in `build_response_from_record` (`get_status_list.rs:130-139`). **Action:** Raw binary is met for both formats. The only concern is the gzip wrapping (see next row). **Verify:** Confirm `test_get_status_list_success_cwt` deserializes the decompressed body directly as `CoseSign1::from_slice` (raw bytes, not hex). |
| [§8.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2) | `gzip` Content-Encoding "SHOULD" now scoped to **JWT-format responses only** (was general in draft-11) | Not Started | **Current:** `build_response_from_record` (`get_status_list.rs:130-139`) applies `GzEncoder` to both JWT and CWT responses unconditionally, and always returns `Content-Encoding: gzip` header (`get_status_list.rs:150-152`). **Action:** Make gzip conditional — only apply `GzEncoder` and the `Content-Encoding: gzip` header when `accept == ACCEPT_STATUS_LISTS_HEADER_JWT`. For CWT responses, return the raw bytes without gzip and without the `Content-Encoding` header. **Verify:** (1) CWT test: assert `Content-Encoding` header is absent and body is raw (not gzipped). (2) JWT test: assert `Content-Encoding: gzip` and body decompresses correctly. |
| [§8.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2) | Redirect handling (3xx) moved to new [§11.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4) with stronger MUST | N/A | **Current:** Our server does not issue 3xx redirects. This is a client-side requirement for following redirects. No action for our server. |
| [§8.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3) | Referenced Token validation (sig, exp, etc.) **MUST precede** status evaluation; if Referenced Token validation fails, status-list procedures **MUST NOT** be performed | N/A | **Current:** This is a client/RP-side requirement. Our server is a Status Provider, not an RP. We don't validate Referenced Tokens or fetch Status List Tokens. **Action:** none. |
| [§8.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3) step 6 | Out-of-bounds index: changed from "Fail if index is out of bounds" to **MUST reject** the Referenced Token | Partial | **Current:** `apply_updates()` (`lst_gen.rs:72-74`) returns `Error::Generic("Index out of bounds")` when `byte_index >= status_array.len()`. This is a fail path but the error type is generic, not a specific "reject" semantic. **Action:** If we add an RP/validation role in the future, add a specific `Error::IndexOutOfBounds` variant and ensure the caller treats it as an explicit Referenced Token rejection. **Verify:** For now, this only affects our internal status-list update path, not client-side validation. |
| [§8.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3) | Sub-step numbering changed; "custom policies" → "local policies" | N/A | Cosmetic. No code impact. |
| [§8.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.4) | Historical resolution: unsupported-timestamp error code changed from **406 → 404** | Not Started | **Current:** Our server does not implement the `time=` query parameter for historical resolution. The handler (`get_status_list.rs:34-56`) ignores all query params. **Action:** If we add `time=` support: (1) Parse the `time` query param, (2) if the requested timestamp is not supported, return `404 Not Found` (not 406), (3) if the server doesn't support the feature at all, return `501 Not Implemented`. **Skip if** we decide not to support historical resolution. **Verify:** Test with `GET /statuslists/1?time=999999999` → expect 404 or 501. |
| [§8.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.4) | Client **MUST reject** a historical-resolution response unless the requested timestamp is within the returned token's `iat`/`exp` window | Not Started | **Current:** Not applicable — this is a client-side requirement and we don't support `time=` queries. **Action:** None unless we add a client-side fetcher. **Skip if** we don't support historical resolution. |

---

## 9. Status List Aggregation

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§9](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-9) | Error handling: "continue processing other valid Status Lists" kept; draft-11's "retrying later" fallback dropped | N/A | **Current:** We don't implement Status List Aggregation fetching. Minor tightening, no new requirement. |
| [§9.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-9.1) | Issuer metadata: explicit RFC 8414 citation; Issuer **MAY** scope a Status List Aggregation to a particular Referenced Token type | N/A | Optional capability, not a MUST. No action. |
| [§9.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-9.3) | Section renamed "...in JSON Format" → "...Data Structure"; `status_lists` array field unchanged | N/A | Renumbering/renaming only. No code impact. |

---

## 10. X.509 Certificate Extended Key Usage Extension

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§10](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-10) | OID symbolic name renamed: `id-kp-oauthStatusListSigning` → **`id-kp-oauthStatusSigning`** | Partial | **Current:** Our config (`config.rs:144`) defaults EKU to `vec![1, 3, 6, 1, 5, 5, 7, 3, 30]` — the trailing `30` is a placeholder pending IANA's real TBD value. We use the numeric arc via `rcgen`'s `ExtendedKeyUsagePurpose::Other(eku.to_vec())` in `cert_manager.rs:455-456`, not the symbolic name. **Action:** (1) The rename is doc-only since we reference the OID numerically. Update any comments/docs/Helm charts that mention the old name. (2) Once IANA assigns the real TBD value, replace `30` in `config.rs:144` with the correct arc number. **Verify:** `grep -r "oauthStatusListSigning"` across repo (including Helm charts and comments) — should return zero matches after update. |
| [§10](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-10) | Other specs MAY reuse this OID for other status mechanisms if registered | N/A | Informative. No action. |
| [Appendix A](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#appendix-A) (new) | Formal ASN.1 module (`OauthStatusSigning-EKU`) defining the EKU OID per X.680/X.690 | N/A | **Current:** We set the EKU via `rcgen`'s `ExtendedKeyUsagePurpose::Other(eku.to_vec())` with a numeric OID vector — no ASN.1 module parsing. **Action:** none. Only relevant if we adopt an ASN.1 toolchain for certificate generation. |

---

## 11. Security Considerations

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§11.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.2) | JWT/CWT security guidance strengthened from "should follow" to **MUST follow** RFC 7519/RFC 8725 (JWT) and RFC 8392 (CWT) | Partial | **Current:** JWT path uses `jsonwebtoken` with pinned `Algorithm::ES256` — no `alg: none` risk. CWT path uses `CoseSign1Builder` with `Algorithm::ES256`. **Action:** Verify we meet RFC 8725 BCPs: (1) no `alg: none` acceptance on any verification path, (2) algorithm allow-listing on decode, (3) `kid` handling is robust if used, (4) `x5c` chain validation on the receiving side if applicable. **Verify:** Audit `jsonwebtoken::decode` calls and any future CWT verification code for algorithm pinning. |
| [**§11.4**](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4) (new) — Redirection 3xx | HTTP clients following 3xx redirects MUST guard against infinite redirect loops (DoS vector) per RFC 9110 §15.4 | N/A | **Current:** Our server doesn't issue 3xx redirects or follow them. **Action:** Only relevant if we add a client-side fetcher (e.g., for Status List Aggregation). Then implement a max-hop-count guard. |
| [**§11.5**](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5) (new) — Expiration and Caching | Clients SHOULD sanity-check `exp`/`ttl` values are within reasonable bounds before scheduling refetches (DDoS mitigation) | N/A | **Current:** Our `TOKEN_EXP = 900` (15 min) and `TOKEN_TTL = 300` (5 min) are reasonable. This is client-side guidance. **Action:** none for our server. If we add an RP client, implement min/max bounds on `exp`/`ttl` before scheduling refetches. |
| [**§11.6**](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.6) (new) — Status List Token Protection | Implementers SHOULD default to digital signatures over MACs | Implemented | **Current:** We exclusively use `ES256` digital signatures (both JWT and CWT paths). No MAC support. **Action:** none. **Verify:** Confirm `Algorithm::ES256` is hardcoded in both `issue_jwt` and `issue_cwt`; no `COSE_Mac0` usage. |

---

## 12. Privacy Considerations

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§12.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-12.2) | Renamed "Malicious Issuers" → "Issuer Tracking of Referenced Tokens"; adds tracking vector via unique URIs per token | N/A | Informative privacy-design guidance. No normative requirement on our server. |
| [§12.5.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-12.5.1) | "Colluding Relying Parties" → "Cross-party Collusion"; old §12.5.2 removed (folded into 12.5.1) | N/A | Reorganization. No code impact. |
| [§12.8](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-12.8) | Trimmed driver's-license example; generalized privacy statement about status types | N/A | Prose only. No code impact. |

---

## 13. Operational Considerations *(renamed from "Implementation Considerations")*

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§13.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-13.2) (new) | "Linkability Mitigation" split into own subsection; clarifies batch re-issuance doesn't prevent Issuer-side traceability | N/A | Guidance only. Other §13 subsections renumbered by +1 but unchanged in substance. |
| [§13.7](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-13.7) (renumbered) | Update-interval/caching guidance cross-references new [§11.5](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5) | N/A | Same underlying item as §11.5. Our `TOKEN_EXP`/`TOKEN_TTL` constants are already set. No action. |

---

## 14. IANA Considerations

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [§14.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.2) / [§14.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.4) / [§14.5](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.5) | Registration process citations updated to RFC 8126; designated-expert review criteria added | N/A | IANA process only — not implementer-facing. |
| [§14.5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.5.2) | Status Type reserved range typo fix `0x0B-0x0F` → `0x0C-0x0F` in registry table | Implemented | Same fix as [§7.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1). Our code doesn't hardcode this boundary. No action. |
| [§14.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.3) | CWT Claims Registration: `status` claim key requested as TBD (assignment 65535) | Partial | **Current:** Our `constants.rs:12` uses `STATUS_LIST = 65533` for the Status List Token's `status_list` claim (the list contents). The spec's §14.3 requests `65535` for the `status` claim (the referencing claim inside a Referenced Token's CWT Claims Set) — a different claim in a different context. **Action:** Verify our `STATUS_LIST = 65533` matches the spec's IANA registration for the Status List Token's own `status_list` claim in [§14.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.3.1). If the spec assigns a different number, update `constants.rs:12` and any CWT encoding/tests. **Verify:** Cross-check `65533` against draft-21 [§14.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.3.1) Registry Contents table. |
| [§14.7](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.7) | Media-type registration contact changed to OAuth WG mailing list | N/A | Administrative. No code impact. |
| [§14.9](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.9) | X.509 OID registration description updated to new name `id-kp-oauthStatusSigning` | N/A | Consequence of [§10](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-10) rename. No separate action. |

---

## Appendices

| Spec Section | Feature | Status | Notes |
|---|---|---|---|
| [Appendix A](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#appendix-A) (new) | ASN.1 module for the EKU OID | N/A | See [§10](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-10) row. We use numeric OID vectors, not ASN.1 module parsing. |
| [Appendix B](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#appendix-B) | "Size Comparison" renumbered; cites RFC 9562 (UUIDs); tables unchanged | N/A | Informative only. |
| [Appendix C](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#appendix-C) | Test vectors formalized as "Appendix C" | N/A | **Action:** After the [§5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.2) CWT-tagging fix lands, re-run our encoding tests against these vectors to confirm no regression. **Verify:** Compare our `encode_compressed` output for 1-bit, 2-bit, 4-bit, and 8-bit test cases against [Appendix C](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#appendix-C) hex values. |

---

## Work items for our draft-11 → draft-21 migration

### Work items needed (Not Started / Partial → action required)

| # | Spec | Work item | Files to touch | Effort |
|---|---|---|---|---|
| 1 | [§5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.2) | **Verify CWT COSE tagging** — Write a unit test asserting the first byte of CWT output is `0xd2` (tag 18, `COSE_Sign1_Tagged`). If `coset` emits untagged, wrap with tag 18. If it emits tag 61, remove it. | `src/web/handlers/status_list/get_status_list.rs` (test module) | Small |
| 2 | [§8.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2) | **Scope gzip to JWT only** — Make `GzEncoder` and `Content-Encoding: gzip` header conditional on `accept == ACCEPT_STATUS_LISTS_HEADER_JWT`. For CWT, return raw bytes without gzip. | `src/web/handlers/status_list/get_status_list.rs:130-152` | Small |
| 3 | [§8.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1) | **Loosen Accept header handling** — Support RFC 9110 content negotiation including `*/*` wildcards and quality factors. Return 406 only when the client explicitly requests only unsupported types. | `src/web/handlers/status_list/get_status_list.rs:34-56` | Medium |
| 4 | [§14.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.3) | **Verify CWT claim key 65533** — Cross-check `STATUS_LIST = 65533` against draft-21 [§14.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14.3.1) Registry Contents. If the spec assigns a different number, update `constants.rs` and all CWT encoding/tests. | `src/web/handlers/status_list/constants.rs:12` | Small (verify only) |
| 5 | [§10](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-10) | **Update EKU OID placeholder** — Once IANA assigns the real TBD value for `id-kp-oauthStatusSigning`, replace `30` in the config default with the real arc number. Update any docs/comments referencing the old symbolic name `id-kp-oauthStatusListSigning`. | `src/config.rs:144`, Helm charts, comments | Small (pending IANA) |
| 6 | [§8.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.4) | **Historical resolution (optional)** — If we decide to support `time=` query param: implement parsing, return `404 Not Found` for unsupported timestamps, return `501 Not Implemented` if the feature is unsupported entirely. | `src/web/handlers/status_list/get_status_list.rs` | Medium (optional) |
| 7 | [§6.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3) | **Track mdoc/CBOR restructuring for downstream compat** — Our server doesn't issue Referenced Tokens, but verify any downstream consumer isn't using the removed draft-11 mdoc-specific embedding pattern. | No code change; audit downstream integrations | Audit only |

### Already conformant (no action needed)

| Spec | Why |
|---|---|
| [§5.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1) / [§5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.2) `exp`/`ttl` RECOMMENDED | Always emitted in both JWT and CWT paths (`get_status_list.rs:273-281`, `178-186`). |
| [§7](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7) single multi-bit status value | `decode_status_array` (`lst_gen.rs:132-160`) reads contiguous bits as one value, not independent flags. |
| [§7.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1) reserved range `0x0C–0x0F` | No hardcoded `0x0B` boundary; bit-width logic is arithmetic (`lst_gen.rs:25-31`). |
| [§11.6](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.6) signatures over MACs | Uses `ES256` exclusively; no MAC code. |
| [§4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4) wire format | Unchanged from draft-11. |

### N/A for our server (client-side or editorial only)

| Spec | Why |
|---|---|
| [§8.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3) processing order | RP-side requirement; we're a Status Provider. |
| [§8.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.4) historical resolution client validation | Client-side; only relevant if we add an RP client. |
| [§11.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4) redirect loop guard | Client-side; our server doesn't follow redirects. |
| [§11.5](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5) exp/ttl bounds-checking | Client-side guidance. |
| [§12](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-12) privacy renumbering | Editorial reorganization. |
| [§13](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-13) operational renumbering | Renumbering only. |
| [§14](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-14) IANA process text | Not implementer-facing. |