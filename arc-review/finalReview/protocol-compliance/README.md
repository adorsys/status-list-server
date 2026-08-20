<!-- markdownlint-disable MD013 MD060 -->

# Protocol Compliance

**Baseline:** `adbe8fdacae5edb1ce655a14a5f5f2120ea229e3` (`HEAD`). The primary source is the archived [Token Status List draft-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html).

## Areas

| Area | Finding and impact |
|---|---|
| Signed Status-List Representation | The API accepts status `256`, emits `bits=9`, and emits `lst=""` for an empty list. Draft-21 [§4.1](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-4.1), [§4.2](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-4.2), and [§4.3](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-4.3) permit only 1/2/4/8 bits and require DEFLATE/ZLIB. [§7](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-7) limits status values to 0-255. See [Application Functional Bugs](../application-functional-bugs/README.md). **PoC:** [PoC 2: unsupported width](#poc-2-unsupported-bit-width) and [PoC 3: empty non-ZLIB representation](#poc-3-empty-non-zlib-list). |
| Index Allocation | No local record binds a Referenced Token to a unique `(uri,idx)`. Duplicate indexes in one management request are last-write-wins. The server stores only index-to-value mappings; there is no reference from an index to a user ID or token ID. A relying party uses the `(uri,idx)` in its Referenced Token, but the service cannot prove that the index is bound to the intended token. If allocation changes or an index is reused, the wrong token can receive the status, including a blocked user receiving `VALID`. A payload with two identical indexes and different statuses lets the last status win. Who owns the allocation of an index to a user? Draft-21 [§4.1](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-4.1) requires a distinct index per Referenced Token; [§13.3](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-13.3) requires prevention of unintended double allocation and explains default `VALID` entries. **PoC:** [PoC 4: duplicate index](#poc-4-duplicate-index) proves last-write-wins behavior; it does not prove end-to-end double allocation. |
| Certificate Encoding | In non-ACME mode, JWT copies PEM text into `x5c`. CWT issuance fails while trying to convert the PEM before an `x5chain` is emitted. RFC 7515 [§4.1.6](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6) requires base64 DER `x5c`; RFC 9360 [§2](https://www.rfc-editor.org/rfc/rfc9360.html#section-2) defines DER-byte `x5chain`. **PoC:** [PoC 6: non-ACME certificate encoding](#poc-6-non-acme-certificate-encoding) proves PEM in JWT `x5c` and the CWT failure. |

## Additional Protocol Findings

| Area | Finding and impact | Official basis and classification | PoC coverage |
|---|---|---|---|
| Management JWT profile | The private management API accepts a signed JWT containing only `iss` and `exp` with an unrelated `typ`. This proves permissive application authentication, not a draft-21 violation or production token-substitution exploit. | **Not governed by draft-21; assessed under RFC 8725 and application policy.** RFC 8725 requires an application algorithm policy ([§3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1)) and, when issuers serve multiple audiences or JWT kinds, audience checks and mutually exclusive validation rules ([§3.9](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.9), [§3.12](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.12)); explicit typing is recommended ([§3.11](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.11)). | [PoC 1: minimal management token](#poc-1-minimal-management-token) |
| HTTP revalidation | The ETag represents only the stored status-list version. It does not represent the expiry of the signed JWT returned to the client. The server evaluates `If-None-Match` before it creates a new JWT. Therefore, if the status list has not changed but the client's JWT has expired, the server returns `304` with no body. The client has no usable token and must make an unconditional GET to receive a fresh JWT. | RFC 9110 [§8.8.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.1) says a weak validator should change when the old representation is no longer an acceptable substitute. Draft-21 [§8.2](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.2) and [§8.3](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3) define token validity and HTTP caching. | [PoC 5: expired JWT revalidation](#poc-5-expired-jwt-revalidation) proves an expired JWT receives `304` with no replacement body. |
| Historical status-list tokens | A snapshot stores the list's `updated_at` value as `iat`. `updated_at` is a logical clock: two updates in the same real second receive different values, so one can be assigned a future second. When a client later requests `GET /api/v1/status-lists/{list-id}?time=...`, the server creates a new signature but uses the stored snapshot `iat` and `exp`. The returned JWT therefore says it was issued when the snapshot was written, not when the server actually signed it. | Draft-21 [§5.1](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-5.1) requires `iat` to be the time at which the Status List Token was issued. [§8.4](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.4) defines historical resolution. | [PoC 7: historical token `iat`](#poc-7-historical-status-list-token) proves a response signed in a later second retains the snapshot's older `iat`. It does not force the separate same-second logical-clock case. |

## Proof of Concept

Run only against the disposable local environment below. The PoC generates an ephemeral P-256 issuer key, writes synthetic credentials/lists, and uses no production material. Requirements are Docker, Python 3.10+, and OpenSSL.

### PoC 1: Minimal Management Token

Code: [`poc_1_minimal_management_token()`](poc_protocol_compliance.py).
Publishes a list using a signed token with only `iss` and `exp`, plus an unrelated `typ`; the API accepts it with HTTP 201. This is an application-profile check outside draft-21.

### PoC 2: Unsupported Bit Width

Code: [`poc_2_unsupported_bit_width()`](poc_protocol_compliance.py).
Publishes status value `256`, decodes the returned JWT, and compares the emitted `bits=9` with the draft-21 allowed set `{1,2,4,8}`.

### PoC 3: Empty Non-ZLIB List

Code: [`poc_3_empty_non_zlib_list()`](poc_protocol_compliance.py).
Publishes an empty list, extracts `lst=""` from the returned JWT, and confirms that an independent ZLIB decoder rejects it.

### PoC 4: Duplicate Index

Code: [`poc_4_duplicate_index()`](poc_protocol_compliance.py).
Publishes conflicting values for index 0 and confirms that the request succeeds with the final value silently winning. It does not prove that two Referenced Tokens were allocated the same index.

### PoC 5: Expired JWT Revalidation

Code: [`poc_5_expired_jwt_revalidation()`](poc_protocol_compliance.py).
Retains a JWT and ETag past signed expiration, revalidates it, and confirms HTTP 304 with no replacement body. An HTTP cache can reuse the bytes, but a conforming Status List verifier must reject them as expired.

### PoC 6: Non-ACME Certificate Encoding

Code: [`poc_6_non_acme_certificate_encoding()`](poc_protocol_compliance.py).
Confirms that JWT `x5c` contains PEM text rather than base64 DER and that an equivalent CWT request fails with HTTP 500.

### PoC 7: Historical Status-List Token

Code: [`poc_7_historical_token_issued_at()`](poc_protocol_compliance.py).
Publishes a list, waits into the next second, then requests its historical representation. The returned JWT retains the earlier snapshot `iat` even though the server creates the response later. It does not force the separate same-second logical-clock case.

```bash
docker compose -p protocol-compliance \
  -f arc-review/finalReview/protocol-compliance/docker-compose.yml up -d --build

python3 arc-review/finalReview/protocol-compliance/poc_protocol_compliance.py \
  --confirm-disposable-target
```

The expected vulnerable result is:

```text
[1/7] Minimal management token accepted: HTTP 201
[2/7] Unsupported status representation: bits=9 (allowed: 1,2,4,8)
[3/7] Empty status representation: lst=""; ZLIB decode failed
[4/7] Duplicate index accepted: final status[0]=2 (last write wins)
[5/7] Expired JWT revalidation: HTTP 304 with no replacement body
[6/7] Non-ACME certificate path: JWT x5c contains PEM; CWT HTTP 500
[7/7] Historical JWT uses snapshot iat: iat=<snapshot time>; signed_at>=<later time>

RESULT: documented protocol and assurance findings reproduced
```

Tear down the environment and delete its database volume:

```bash
docker compose -p protocol-compliance \
  -f arc-review/finalReview/protocol-compliance/docker-compose.yml down -v
```

The PoC proves the listed behavior at the HTTP boundary and independently applies the draft width set and Python's ZLIB decoder. It does not claim a production cross-context token exploit, end-to-end double allocation, unauthorized signer acceptance, or independent signature-chain validation; those outcomes depend on production issuer, allocator, and relying-party policies that were not supplied.
