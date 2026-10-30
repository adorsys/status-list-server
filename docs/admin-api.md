# Admin issuer API

The admin listener (default `localhost:8002`) serves the admin issuer API:
`GET /admin/v1/issuers` and `GET /admin/v1/issuers/{issuer_id}` for reads,
and `PATCH` on `/admin/v1/issuers/{issuer_id}` and
`/admin/v1/issuers/{issuer_id}/keys/{kid}` for lifecycle changes
(suspend, resume, key revocation). The public and management listeners
return 404 for these routes. Keep the admin listener on a private network.
The [Admin OpenAPI contract](openapi-admin.yaml) describes the response fields;
`POST /admin/v1/issuers/{issuer_id}/keys` (adding a key) is not implemented
yet.

## Authentication and configuration

Add an admin principal with public keys and `issuers:read` in the registry's
`admins` array. The registry file is selected by
`APP_MANAGEMENT_AUTH__ISSUERS_FILE`; admin and issuer keys share that file but
are resolved separately. Follow the [registry schema](schemas/issuers.v1.schema.json)
for key and principal fields. Never put private keys in the registry.

Set `APP_ADMIN_AUTH__AUDIENCES` to comma-separated values accepted for admin
requests. These values must not overlap `APP_MANAGEMENT_AUTH__AUDIENCES`.
Startup fails on overlap in every environment. In production, defining any
admins with no admin audience also fails startup. With no admin audiences,
admin authentication rejects every token, including in development.

`APP_ADMIN_AUTH__MAX_TOKEN_LIFETIME_SECS` defaults to 300 and must be positive.
`APP_ADMIN_AUTH__LEEWAY_SECS` defaults to 60. Helm deployments can supply these
through `statuslist.env`; the chart includes the admin audience setting.

Sign tokens using an admin's registered key. Set `typ: statuslist-admin+jwt`,
`kid` to that key's ID, and `alg` to its registered algorithm. Include `iss`
equal to the admin ID, a matching `aud`, and integer `iat` and `exp` claims.
`exp` must exceed `iat`, with their difference within the configured lifetime.
Future `iat` and optional `nbf` must be within the leeway. Scopes come only
from the registry; a token's `scope` claim grants nothing. Admin tokens cannot
be used on management routes, and management tokens cannot be used here.

Missing credentials return `401 missing_token`; rejected tokens return the
same `401 invalid_token` body. A valid admin without `issuers:read` receives
`403 insufficient_scope` with the required scope in `WWW-Authenticate`.
Successful responses use `Cache-Control: no-store`; API errors use
`Cache-Control: no-store, max-age=0`.

## Pagination and filters

The private profile returns static registry issuers. The hosted profile also
returns portal issuers from SQL. Filter with `source`, `tier`, `state`, or
`owner`. Owner values use `<provider>|<subject>` and must be URL encoded.
The default page size is 50; `limit` must be between 1 and 100.

Follow `next_cursor` or the `Link` header with the same filters. Ordering is
ascending by issuer ID. Issuers present at the start that remain present and
matching when their page is read appear exactly once. Concurrent inserts
before the current cursor are not included; inserts after it may be included.
This is a forward traversal, not a database snapshot. Start another traversal
to observe insertions behind the cursor.

## Usage and validators

Usage reports the actual number of persisted lists, including during a quota
transition, and the configured per-issuer list limit. Key usage counts active
(non-revoked) keys, including keys outside their validity windows.
`keys_limit: null` explicitly means no key-count quota is enforced. This is an
intentional extension of the earlier integer-only API schema; clients must
accept null and must not treat it as zero. Tier-specific key caps are outside
this read-endpoint implementation.

The detail ETag identifies the complete JSON representation for either source.
It changes when returned keys, usage, metadata, or derived expiry state change.
It is opaque and is not the database version. The reads do not provide a
transactional snapshot across issuer metadata, keys, and usage.

## Lifecycle changes

Suspending, resuming, and revoking are `PATCH` requests requiring
`issuers:write` and an `If-Match` header with the issuer's current `ETag`:

```bash
curl -X PATCH "$admin/admin/v1/issuers/$issuer_id" \
  -H "Authorization: Bearer $admin_token" \
  -H "If-Match: \"$etag\"" \
  -H "Content-Type: application/json" \
  -d '{"state":"suspended"}'
```

Read the `ETag` from `GET /admin/v1/issuers/{issuer_id}` first. Without
`If-Match` the server answers `428 precondition_required`; with a stale tag,
`412 precondition_failed` and the current `ETag` in the response — re-read and
retry. A successful response returns the updated representation (the revoked
key for `keys/{kid}`) and the new `ETag`.

Behavior to expect:

- Static (registry) issuers answer `409 issuer_managed_by_configuration`;
  change them through the registry file instead.
- `state: active` never lifts an expiry: reactivating an issuer past its
  `expires_at` answers `422 invalid_expiry`.
- Re-applying the stored state is a no-op: the issuer is returned unchanged,
  without a version bump or audit event.
- Revocation is permanent and idempotent: revoking an already revoked key
  returns `200` unchanged. A revoked `kid` is never reused.
- Each committed change is stored together with its actor audit event in one
  database transaction. The recorded actor is the admin principal from the
  token (the portal backend's admin id, not the end user behind it).
- The admin routes have their own rate-limit tier (`admin_burst_size`,
  `admin_period_secs`, defaults 30 per 60s per IP, `APP_RATE_LIMIT__*`).

Suspension and revocation take effect on the next request on every replica
sharing the database, but a write that authenticated before the change can
still commit; confirm the effect by sending an issuer token to each pod's
management listener (`GET /api/v1/credentials` must answer `401`).

Run the [admin demo](../demo/README.md#admin-issuer-reads) to list issuers and
inspect a detail response without placing the bearer token in shell history.
