# OAuth Token Status List - draft-21 Compliance Matrix

Audit of the status-list issuer/hosting implementation against
[draft-ietf-oauth-status-list-21](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/21/)
(Token Status List, expires 23 December 2026). All findings below were checked directly
against the primary IETF text. Complements the application-specific status value work tracked in #152.

Status legend:

- **Compliant** - behavior matches the spec, verified against implementation behavior.
- **Fixed** - deviated from the spec; corrected in this change.
- **Deviation (documented)** - intentional gap; the spec marks the feature OPTIONAL and no
  ticket deliverable requires it.
- **Out of scope** - belongs to another tracked ticket or component.
- **Hardening note** - not a draft-21 violation (SHOULD-level or unspecified), but worth
  tracking as a follow-up.

| #   | Spec §      | Requirement                                                                                                                                | Status                 | Notes / evidence                                                                                                                                                                                     |
| --- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | §4.1        | Byte array compressed with DEFLATE ([RFC 1951]) in the ZLIB ([RFC 1950]) container                                                         | Compliant              | Status lists are encoded with zlib-wrapped DEFLATE, including the required zlib header and checksum trailer.                                                                                         |
| 2   | §4.1        | Highest compression level RECOMMENDED                                                                                                      | Compliant              | Status-list compression uses the highest available compression level.                                                                                                                                |
| 3   | §4.1        | Bits packed LSB (bit "0") → MSB (bit "7") within each byte                                                                                 | Compliant              | Status entries are packed from the least significant bit toward the most significant bit within each byte, matching the draft examples.                                                              |
| 4   | §4.2 / §4.3 | `bits` ∈ {1, 2, 4, 8}                                                                                                                      | Compliant              | New status lists use the draft-supported bit widths, and compatible existing lists are preserved or repacked without emitting unsupported widths.                                                    |
| 5   | §4.2        | `lst` is base64url of the compressed array, no padding                                                                                     | Compliant              | `jwt_get_conforms_with_and_without_aggregation_uri` checks unpadded base64url and decompresses the served list to expected bytes.                                                                    |
| 6   | §4.2 / §9   | `aggregation_uri` (OPTIONAL)                                                                                                               | Compliant              | `jwt_get_conforms_with_and_without_aggregation_uri` and `cwt_get_conforms_with_and_without_aggregation_uri` assert the configured value and absence when unset (§9.2).                               |
| 7   | §5.1        | JWT `typ` header MUST be the abbreviated `statuslist+jwt`                                                                                  | Compliant              | `jwt_get_conforms_with_and_without_aggregation_uri` asserts `typ=statuslist+jwt`, `alg=ES256`, the fixture x5c certificate, and a signature verified with its public key.                            |
| 8   | §5.1        | `sub` MUST be the URI of the Status List Token, equal to the Referenced Token's `status_list.uri`                                          | Compliant              | `aggregation_body_and_list_uris_conform` resolves each listed URI and asserts that the verified token subject is exactly that request URI.                                                           |
| 9   | §5.1        | `iat` REQUIRED; `exp` / `ttl` RECOMMENDED                                                                                                  | Compliant              | Both GET conformance tests assert `iat < exp` and positive `ttl` in decoded tokens.                                                                                                                  |
| 10  | §5.2        | CWT protected header label `16` (type) MUST be the full media type `application/statuslist+cwt` (or the registered CoAP Content-Format ID) | Compliant              | `cwt_get_conforms_with_and_without_aggregation_uri` decodes the protected map and asserts literal labels `1=-7`, `16="application/statuslist+cwt"`, and `33` with the fixture certificate.           |
| 11  | §5.2        | CWT MUST NOT carry the CWT tag ([RFC 8392] §6); the COSE message MUST be `COSE_Sign1_Tagged` (18) or `COSE_Mac0_Tagged` (17)               | Compliant              | `cwt_get_conforms_with_and_without_aggregation_uri` asserts leading byte `0xd2`, decodes tagged COSE Sign1 and a bare claims map (no tag 61), and verifies the signature with the certificate key.   |
| 12  | §5.2        | CWT claim keys: `2` (sub), `6` (iat), `4` (exp), `65534` (ttl), `65533` (status_list)                                                      | Compliant              | `cwt_get_conforms_with_and_without_aggregation_uri` asserts literal claim labels `2`, `6`, `4`, `65534`, and `65533`; TTL is an unsigned integer greater than zero.                                  |
| 13  | §4.3 / §5.2 | CBOR `status_list.lst` MUST be a CBOR byte string (major type 2) of the raw compressed bytes; `bits` MUST be a CBOR unsigned integer       | Compliant              | The CWT GET test asserts unsigned `bits` in {1,2,4,8} and a byte-string `lst` that decompresses to expected bytes. `draft21_section_4_3_cbor_vector` checks the exact CBOR hex.                      |
| 14  | §7.1        | Status Type registry: `0x03` and `0x0C`-`0x0F` permanently reserved as application-specific; all others reserved for future registration   | Compliant              | The API accepts the draft-defined standard and application-specific values and rejects reserved values.                                                                                              |
| 15  | §8.1        | Media types `application/statuslist+jwt` / `application/statuslist+cwt` for content negotiation and `Content-Type`                         | Compliant              | Both GET conformance tests assert literal JWT/CWT Content-Type values. `aggregation_body_and_list_uris_conform` asserts `application/json`.                                                          |
| 16  | §8.2        | Successful response MUST use a 2xx status code                                                                                             | Compliant              | Successful status-list retrieval returns a 2xx response.                                                                                                                                             |
| 17  | §8.2        | `Content-Encoding` (e.g. gzip) via RFC 9110 negotiation, RECOMMENDED for Status List Tokens **in JWT format**                              | Compliant              | `cwt_get_conforms_with_and_without_aggregation_uri` checks identity and gzip requests: CWT is never gzipped. Existing GET encoding-negotiation tests cover JWT gzip.                                 |
| 18  | §8.4        | Historical resolution via a `?time=` query parameter                                                                                       | Compliant              | Historical status-list retrieval is supported for retained snapshots; unavailable times return not found. This optional feature retains timing data and therefore carries the §12.7 privacy warning. |
| 19  | -           | Publish/update REST endpoints                                                                                                              | Out of scope           | This server's management API is issuer-internal tooling; draft-21 governs the status-list token format and retrieval behavior, not issuer-internal management workflows.                             |
| 20  | §13.2/§13.3 | Prevent double allocation                                                                                                                  | **Fixed**              | The management API provides fixed-size list allocation, records reservations durably, and rejects updates to unallocated fixed-size indices with `409 index_not_allocated`.                          |
| 21  | §13.3       | Duplicate index in a single request                                                                                                        | **Fixed**              | Publish and update requests containing the same `index` more than once are rejected with `400 duplicate_index` before any status-list write is applied.                                              |
| 22  | §10         | X.509 EKU for the signing certificate                                                                                                      | Out of scope (#136)    | Certificate provisioning is a separately shipped component.                                                                                                                                          |
| 23  | §5.1 / §5.2 | `ttl` MUST be a positive number; lifetimes must be positive (`>= 1`) with `ttl < exp` within the configured maximum token lifetime         | **Fixed**              | Configuration validation now rejects zero, non-positive, inverted, or excessive token lifetimes at startup, and token expiry construction fails closed on overflow.                                  |

[RFC 1951]: https://www.rfc-editor.org/rfc/rfc1951
[RFC 1950]: https://www.rfc-editor.org/rfc/rfc1950
[RFC 8392]: https://www.rfc-editor.org/rfc/rfc8392

## Conformance test evidence (#577)

The Tokens, Content-Type, CORS and Aggregation checks run in the normal CI
Rust test suite; no network service is needed for these tests. Wire tests live in
`src/server/handlers/status_list/conformance_tests.rs`; vector and multi-algorithm
signature tests live in `src/server/handlers/status_list/utils/token.rs`.

| Group        | Checks                                                                                                                                    | Tests                                                                                                              |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Tokens       | Served JWT headers, certificate, signature, subject, times, bits, encoding; optional aggregation URI                                      | `jwt_get_conforms_with_and_without_aggregation_uri`                                                                |
| Tokens       | Served CWT tag, literal protected labels and claims, unsigned TTL/bits, byte-string list, certificate signature; optional aggregation URI | `cwt_get_conforms_with_and_without_aggregation_uri`                                                                |
| Tokens       | ES256, ES384, EdDSA and RS256 headers and signatures                                                                                      | `test_dynamic_jwt_alg_header`, `test_dynamic_cwt_alg_header` (already ported from `feat/support-multi-curve-keys`) |
| Tokens       | Exact §4.3 CBOR and Appendix C.1/C.2 strings                                                                                              | `draft21_section_4_3_cbor_vector`, `draft21_appendix_c_1_and_c_2_vectors`                                          |
| Content-Type | JWT, CWT and aggregation media types; no CWT gzip even when requested                                                                     | All three GET conformance tests                                                                                    |
| CORS         | OPTIONS allows any origin and GET on both public routes                                                                                   | `cors_preflight_allows_public_get`                                                                                 |
| CORS         | Browser clients can read ETag for conditional requests                                                                                    | `jwt_get_conforms_with_and_without_aggregation_uri`; production `cors_layer()` exposes `ETag`                      |
| Aggregation  | Exact terminal-page JSON object, empty array, resolving URIs with matching subjects                                                       | `aggregation_body_and_list_uris_conform`                                                                           |

Aggregation retains its existing pagination extension: nonterminal pages include
`next_cursor` and a `Link` header. Terminal pages omit `next_cursor`, yielding
exactly `{"status_lists":[…]}` (including the empty case).

The Appendix C tests construct 2^20 entries using `StatusList::create`, including
an explicit VALID entry at index 1_048_575. The zlib backend at maximum compression
matches the published bytes; the previous miniz backend produced equivalent
uncompressed content but different compressed output. This backend change may
change token bytes and ETags, while existing compressed lists remain readable.

Documentation follow-up for #8: Appendix C.3 and C.4 use reserved status values
rejected since #557. These vectors cannot be reproduced through the supported
status model; they are intentionally excluded, without bypassing validation.
