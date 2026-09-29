# OAuth Token Status List - draft-21 Compliance Matrix

Audit of the status-list issuer/hosting implementation against
[draft-ietf-oauth-status-list-21](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
(Token Status List, expires 23 December 2026). All findings below were checked directly
against the primary IETF text. Complements the `Status::ApplicationSpecific` enum work
tracked in #152.

Status legend:

- **Compliant** - behavior matches the spec, verified by reading the code (and, where noted, a test).
- **Fixed** - deviated from the spec; corrected in this change.
- **Deviation (documented)** - intentional gap; the spec marks the feature OPTIONAL and no
  ticket deliverable requires it.
- **Out of scope** - belongs to another tracked ticket or component.
- **Hardening note** - not a draft-21 violation (SHOULD-level or unspecified), but worth
  tracking as a follow-up.

| #  | Spec §      | Requirement                                                                                                                                | Status                 | Notes / evidence                                                                                                                       |
| -- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 1  | §4.1        | Byte array compressed with DEFLATE ([RFC 1951]) in the ZLIB ([RFC 1950]) container                                                         | Compliant              | Status lists use zlib-wrapped DEFLATE compression as required by the draft.                                                            |
| 2  | §4.1        | Highest compression level RECOMMENDED                                                                                                      | Compliant              | Compression is configured to use the strongest available compression level.                                                            |
| 3  | §4.1        | Bits packed LSB (bit "0") → MSB (bit "7") within each byte                                                                                 | Compliant              | Status bits are packed in least-significant-bit order within each byte and covered by spec-vector tests.                               |
| 4  | §4.2 / §4.3 | `bits` ∈ {1, 2, 4, 8}                                                                                                                      | Compliant              | Generated lists use draft-supported bit widths only; legacy wider rows are normalized when possible and rejected when unrepresentable. |
| 5  | §4.2        | `lst` is base64url of the compressed array, no padding                                                                                     | Compliant              | The compressed status byte array is encoded with unpadded base64url; empty lists are represented by a valid compressed empty stream.   |
| 6  | §4.2 / §9   | `aggregation_uri` (OPTIONAL)                                                                                                               | Deviation (documented) | Not implemented. This feature is optional in the draft and not part of this change.                                                    |
| 7  | §5.1        | JWT `typ` header MUST be the abbreviated `statuslist+jwt`                                                                                  | Compliant              | JWT status-list tokens use the abbreviated status-list media type in the protected header.                                             |
| 8  | §5.1        | `sub` MUST be the URI of the Status List Token, equal to the Referenced Token's `status_list.uri`                                          | Compliant              | Published tokens use the served status-list URI as the subject so referenced tokens resolve to the hosted list.                        |
| 9  | §5.1        | `iat` REQUIRED; `exp` / `ttl` RECOMMENDED                                                                                                  | Compliant              | Status-list tokens include issued-at, expiration, and time-to-live claims.                                                             |
| 10 | §5.2        | CWT protected header label `16` (type) MUST be the full media type `application/statuslist+cwt` (or the registered CoAP Content-Format ID) | **Fixed**              | CWT status-list tokens use the full status-list CWT media type in the protected header.                                                |
| 11 | §5.2        | CWT MUST NOT carry the CWT tag ([RFC 8392] §6); the COSE message MUST be `COSE_Sign1_Tagged` (18) or `COSE_Mac0_Tagged` (17)               | **Fixed**              | CWT responses are emitted as tagged COSE messages, matching the draft requirement.                                                     |
| 12 | §5.2        | CWT claim keys: `2` (sub), `6` (iat), `4` (exp), `65534` (ttl), `65533` (status_list)                                                      | Compliant              | CWT claims use the draft-registered integer claim keys.                                                                                |
| 13 | §4.3 / §5.2 | CBOR `status_list.lst` MUST be a CBOR byte string (major type 2) of the raw compressed bytes; `bits` MUST be a CBOR unsigned integer       | **Fixed**              | CWT status lists encode the compressed list as raw bytes and the bit width as an unsigned integer.                                     |
| 14 | §7.1        | Status Type registry: `0x03` and `0x0C`-`0x0F` permanently reserved as application-specific; all others reserved for future registration   | Compliant              | The API accepts the draft-defined status values and rejects reserved values outside the supported registry range.                      |
| 15 | §8.1        | Media types `application/statuslist+jwt` / `application/statuslist+cwt` for content negotiation and `Content-Type`                         | Compliant              | Status-list responses use the registered JWT and CWT media types for content negotiation and response content type.                    |
| 16 | §8.2        | Successful response MUST use a 2xx status code                                                                                             | Compliant              | Successful status-list retrieval returns a 2xx response.                                                                               |
| 17 | §8.2        | `Content-Encoding` (e.g. gzip) via RFC 9110 negotiation, RECOMMENDED for Status List Tokens **in JWT format**                              | Hardening note         | Compression behavior for served tokens should be reviewed separately against content negotiation and token-format guidance.            |
| 18 | §8.4        | Historical resolution via a `?time=` query parameter                                                                                       | Compliant              | Historical status-list resolution is supported for timestamps covered by retained snapshots; unavailable times return not found.       |
| 19 | -           | Publish/update management endpoints                                                                                                        | Out of scope           | The management API is issuer-internal tooling and is outside the draft wire-format requirements.                                       |
| 20 | §13.2/§13.3 | Prevent double allocation                                                                                                                  | **Fixed**              | The management API provides a durable allocation flow that reserves unused entries before they are assigned to referenced tokens.      |
| 21 | §13.3       | Duplicate index in a single request                                                                                                        | **Fixed**              | Publish and update requests containing the same index more than once are rejected before any write is applied.                         |
| 22 | §10         | X.509 EKU for the signing certificate                                                                                                      | Out of scope (#136)    | Certificate provisioning is a separately shipped component.                                                                            |

[RFC 1951]: https://www.rfc-editor.org/rfc/rfc1951
[RFC 1950]: https://www.rfc-editor.org/rfc/rfc1950
[RFC 8392]: https://www.rfc-editor.org/rfc/rfc8392
