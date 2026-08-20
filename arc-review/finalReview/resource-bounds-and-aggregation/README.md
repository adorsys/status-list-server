<!-- markdownlint-disable MD013 MD060 -->

# The REST

**Baseline:** `adbe8fdacae5edb1ce655a14a5f5f2120ea229e3` (`HEAD`).

## Areas

| Area | Finding and Consequences |
|---|---|
| Aggregation Endpoint Pollution | Empty lists or spammed lists, including the fake issuer lists described in [Authentication And Tenant Trust](../auth-tenant-trust/README.md), are shown in the aggregation endpoint. The endpoint loads every distinct status-list URI and returns all of them in one public response. **PoC:** [PoC 1: spammed lists](#poc-1-spammed-lists) and [PoC 2: aggregation endpoint pollution](#poc-2-aggregation-endpoint-pollution). |
| Missing Pagination | The aggregation endpoint has no cursor or page-size input. If there are 100,000 lists, one aggregation call always returns 100,000 entries. Add pagination, cursors, queries, and limits for filtering. What purpose does this endpoint serve? Lock it down so spam does not pollute it. **PoC:** [PoC 3: ignored limit](#poc-3-ignored-limit) and [PoC 4: missing pagination metadata](#poc-4-missing-pagination-metadata). |
| Return values are sometimes strings and sometimes JSON | Rate limiting returns a text response. Application errors return JSON. Health and root success responses are strings, while successful status mutations have an empty body. Use one documented JSON response format with properties and values for management and control endpoints. Do not change status-list `GET` responses to JSON:  |
| Rate Limit | A rate-limited client can send requests again after the configured rate-limit period; the bucket is not permanent. The default period is 60 seconds. However, rate limits are process-local and keyed by immediate peer IP or forwarded IP headers. Clients behind the same proxy can share one bucket, so one client can rate-limit unrelated clients. **PoC:** Not covered by this aggregation PoC. |

This is a bounded demonstration, not a destructive capacity test. It creates 128 empty lists by default, enough to prove the missing controls without filling disk or measuring production limits.

## Executable PoC

Requirements: Docker with Compose, Python 3.10+, and OpenSSL. The stack binds only to loopback and uses disposable PostgreSQL state.

```bash
docker compose -p resource-bounds-and-aggregation \
  -f arc-review/finalReview/resource-bounds-and-aggregation/docker-compose.yml up -d --build

python3 arc-review/finalReview/resource-bounds-and-aggregation/poc_resource_bounds_and_aggregation.py \
  --confirm-disposable-target
```

Expected vulnerable output:

```text
[1/4] Published 128 empty lists for one issuer without a list-count quota
[2/4] Public aggregation returned all 128 created URIs in one response
[3/4] Aggregation ignored illustrative ?limit=1 and still returned the complete set
[4/4] Aggregation had no cursor/page metadata; response bytes grew to ... (... with ?limit=1)

RESULT: REST and aggregation gaps reproduced at baseline adbe8fdacae5edb1ce655a14a5f5f2120ea229e3
```

### PoC 1: Spammed Lists

Publishes 128 empty lists for one issuer without an active-list count quota.

### PoC 2: Aggregation Endpoint Pollution

The public aggregation endpoint returns all 128 created URIs in one response.

### PoC 3: Ignored Limit

An illustrative `?limit=1` query does not change the aggregation response.

### PoC 4: Missing Pagination Metadata

The response has no cursor or page metadata and grows with the number of lists.

Tear down every container, network, and database volume:

```bash
docker compose -p resource-bounds-and-aggregation \
  -f arc-review/finalReview/resource-bounds-and-aggregation/docker-compose.yml down -v --remove-orphans
```
