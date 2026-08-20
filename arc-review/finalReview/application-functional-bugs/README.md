<!-- markdownlint-disable MD013 MD060 -->

# Application Functional Bugs

**Baseline:** `adbe8fdacae5edb1ce655a14a5f5f2120ea229e3` (`HEAD`). This is the umbrella runtime suite. Six failures below were reproduced through the HTTP boundary and disposable PostgreSQL state. The archived primary protocol baseline is [Token Status List draft-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html).

## Areas

| Area | Finding and impact |
|---|---|
| OpenAPI Spec and Implementation | The [OpenAPI Spec](https://github.com/adorsys/status-list-server/blob/adbe8fdacae5edb1ce655a14a5f5f2120ea229e3/docs/openapi.yaml#L481-L525) specifies string status values, but the server rejects them. It accepts undocumented integers instead. Generated clients cannot publish. **PoC:** [`poc_1_openapi_status_contract_mismatch`](#poc_1_openapi_status_contract_mismatch) proves that documented `"VALID"` is rejected while undocumented `0` is accepted. |
| Signed Representation | Input with status `256` returns `bits=9`, but according to [Token Status List (TSL)](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html), only 1, 2, 4, or 8 bits are allowed. An empty status list produces signed `lst=""`, not a ZLIB stream. Consumers might not be able to consume this because they expect ZLIB. **PoC:** [`poc_2_invalid_signed_status_representation`](#poc_2_invalid_signed_status_representation) proves both representations. |
| Status Inconsistency when Multi-Pod + Local Cache | See [Multi-POD Operation](../multi-pod-operation/README.md). Multi-pod operation is not safely possible with a local status cache. **PoC:** [`poc_3_stale_cache_after_acknowledged_update`](#poc_3_stale_cache_after_acknowledged_update) proves that pod A can freshly sign cached `VALID` data after pod B has acknowledged `INVALID`. |
| HTTP Revalidation | The server does not account for whether the client's JWT token from `GET /api/v1/status-lists/{list-id}` has expired. A call with an ETag whose JWT is expired returns `304` with an empty body. The client still has only the expired JWT. **PoC:** [`poc_4_expired_token_revalidation`](#poc_4_expired_token_revalidation) reproduces this with an expired token and `If-None-Match`. |
| Empty PATCH | `{"statuses":[]}` leaves status bytes unchanged but advances `updated_at` and appends another full snapshot. Is that expected? **PoC:** [`poc_5_empty_patch_writes_full_snapshot`](#poc_5_empty_patch_writes_full_snapshot) proves the redundant version and snapshot write. |
| `/health` is 200 when key material is wrong | When the signer is broken, the application returns 500. However, the application appears to be fully functional. When no certificate chain is available, the signed GET returns 503 instead. **PoC:** [`poc_6_health_ignores_signing_failure`](#poc_6_health_ignores_signing_failure) proves `/health=200` while the signed GET fails. |

### HTTP Revalidation

```text
GET status list
   ↓
200 + JWT
exp = 10:00
ETag = abc
Time passes -> 10:05
   ↓
cached JWT on client is expired
GET with If-None-Match: abc
   ↓
server checks status data
status has not changed
   ↓
304, no body
Client still only has
the expired JWT
```

## Executable PoC

Requirements: Docker with Compose, Python 3.10+, and OpenSSL. The stack binds only to loopback, uses a disposable database volume and checked-in test-only signer fixtures, and the script generates an ephemeral issuer key and UUID data. It refuses non-loopback targets and all writes unless `--confirm-disposable-target` is present.

```bash
docker compose -p application-functional-bugs \
  -f arc-review/finalReview/application-functional-bugs/docker-compose.yml up -d --build

python3 arc-review/finalReview/application-functional-bugs/poc_application_functional_bugs.py \
  --confirm-disposable-target
```

Expected failing/vulnerable output:

```text
[1/6] poc_1_openapi_status_contract_mismatch: documented "VALID" -> HTTP 422; numeric 0 -> HTTP 201
[2/6] poc_2_invalid_signed_status_representation: bits=9; lst="" is not ZLIB
[3/6] poc_3_stale_cache_after_acknowledged_update: pod B=INVALID; pod A freshly signed cached VALID
[4/6] poc_4_expired_token_revalidation: expired JWT -> HTTP 304/no body; unconditional GET -> fresh HTTP 200
[5/6] poc_5_empty_patch_writes_full_snapshot: updated_at advanced; history rows 1->2; payload variants=1
[6/6] poc_6_health_ignores_signing_failure: /health=HTTP 200; signed GET=HTTP 500

RESULT: six functional failures reproduced at baseline adbe8fdacae5edb1ce655a14a5f5f2120ea229e3
```

### poc_1_openapi_status_contract_mismatch

Code: [`poc_1_openapi_status_contract_mismatch()`](poc_application_functional_bugs.py). Proves the documented string fails while an undocumented numeric value succeeds; it does not test every generated client.

### poc_2_invalid_signed_status_representation

Code: [`poc_2_invalid_signed_status_representation()`](poc_application_functional_bugs.py). Cryptographically verifies the JWTs and independently checks width/ZLIB; it does not exercise CWT or every verifier.

### poc_3_stale_cache_after_acknowledged_update

Code: [`poc_3_stale_cache_after_acknowledged_update()`](poc_application_functional_bugs.py). Proves post-acknowledgement stale status is newly signed across two processes; it does not establish the production topology or single-process race probability.

### poc_4_expired_token_revalidation

Code: [`poc_4_expired_token_revalidation()`](poc_application_functional_bugs.py). Proves post-expiry `304` and recovery by unconditional GET; it does not prove every cache/client retains the old body or a false status value.

### poc_5_empty_patch_writes_full_snapshot

Code: [`poc_5_empty_patch_writes_full_snapshot()`](poc_application_functional_bugs.py). Proves one redundant version and full-payload history row; it does not claim disk/WAL exhaustion or production capacity impact.

### poc_6_health_ignores_signing_failure

Code: [`poc_6_health_ignores_signing_failure()`](poc_application_functional_bugs.py). Proves health/core-read divergence with missing test signer material; Kubernetes routing follows from the linked probe configuration, not this local HTTP run.

Tear down every container, network, and database volume:

```bash
docker compose -p application-functional-bugs \
  -f arc-review/finalReview/application-functional-bugs/docker-compose.yml down -v --remove-orphans
```
