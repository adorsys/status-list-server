# Admin issuer API

The admin listener (default `localhost:8002`) serves issuer reads and writes.
The public and management listeners return 404 for these routes. Keep the admin
listener on a private network.
The [Admin OpenAPI contract](openapi-admin.yaml) describes the response fields.

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
Registry reloads that introduce admins while the admin audience overlaps
management audiences are rejected in every environment; in production, a
missing admin audience also rejects the reload. The last valid registry
remains active. Configure the audience before adding admin principals.

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
The admin issuer API has a separate per-peer-IP budget, configured by
`APP_RATE_LIMIT__ADMIN_BURST_SIZE` (default 100) and
`APP_RATE_LIMIT__ADMIN_PERIOD_SECS` (default 1 second per replenished request).
Excess reads or writes return JSON `429 too_many_requests` with `Retry-After`.

## Pagination and filters

The private profile returns static registry issuers. The hosted profile also
returns portal issuers from SQL. Filter with `source`, `tier`, `state`, or
`owner`. Owner values use `<provider>|<subject>` and must be URL encoded.
The default page size is 50; `limit` must be between 1 and 100.

Follow `next_cursor` or the `Link` header with the same filters. Ordering is
ascending by issuer ID. The cursor keeps independent positions for static and
portal issuers, so database collation cannot change their merged order. Issuers
present at the start that remain present and matching when their page is read
appear exactly once. Concurrent inserts after a source position may appear once;
inserts before that position are observed on a new traversal.

## Usage and validators

Usage reports the actual number of persisted lists, including during a quota
transition, and the issuer tier's `max_lists`. Key usage counts the keys that
hold one of the tier's `max_keys` slots: active keys whose `not_after` has not
passed, including keys staged for rotation. `keys_limit` is the tier's
`max_keys`.

For static issuers, the detail ETag identifies the complete JSON representation.
For hosted issuers, the ETag and `Issuer-Version` derive from the persisted
issuer version. Mutations use exactly one of `If-Match` or
`If-Issuer-Version`, so ordinary list publishes and derived expiry state do
not invalidate writes. The reads do not provide a transactional snapshot
across issuer metadata, keys, and usage.

## Hosted issuer writes

An admin with `issuers:write` can create a portal issuer with its first public
key, add a key, suspend or resume an issuer, renew its expiry, and revoke a key.
Static issuers remain managed through the registry. Creation is available only
in the hosted profile; it assigns the issuer and aggregation identifiers and
the key thumbprint. Other writes require the current issuer `ETag` or
`Issuer-Version`; stale values return 412 and missing values return 428.
Retrying an already revoked key returns 200 unchanged.

`APP_TIERS__SANDBOX__MAX_LIFETIME_SECS` defaults to 2592000 (30 days).
Creation defaults `expires_at` to that duration from now. Creation and renewal
accept an expiry strictly after now and no later than now plus the configured
duration. Renewal may restore an expired issuer; resuming a suspension alone
does not. Portal issuers stored with the `standard` tier do not expire and
reject renewal. Each change is recorded in the SQL audit log with its actor.

Hosted key writes and registry reloads share a database lock on PostgreSQL and
MySQL. Reloads also record static principal IDs, key IDs, and normalized key
material as durable claims. These claims are retained after a registry entry
is removed, so a lagging replica cannot admit a hosted key still trusted by
another replica. This reserves historical static identities from hosted use.

Run the [admin demo](../demo/README.md#admin-issuer-reads) to list issuers and
inspect a detail response without placing the bearer token in shell history.

## Hosted profile local setup

Hosted mode needs a SQL backend and an operator registry containing the portal
backend's admin principal with `issuers:read` and `issuers:write` scopes. For
a local single-node trial, use SQLite, the development signing material, and
a distinct admin audience:

```bash
APP_SERVER__PROFILE=hosted \
APP_DATABASE__BACKEND=sqlite \
APP_DATABASE__URL='sqlite://status-list.db?mode=rwc' \
APP_DATABASE__POOL__MAX_CONNECTIONS=1 \
APP_ADMIN_AUTH__AUDIENCES='http://localhost:8002/admin/v1' \
APP_MANAGEMENT_AUTH__ISSUERS_FILE=issuers.yaml \
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=test_data/certs/dev.crt \
APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=test_data/certs/dev.key \
cargo run --features sqlite
```

The portal backend calls `POST /admin/v1/issuers` with a developer's public
JWK and owner identity, then reads the assigned issuer and key IDs from the
response. The developer signs management tokens as described in the
[registry issuer onboarding steps](deployment-runbook.md#onboard-a-registry-issuer).
For overlap rotation, read the issuer's `ETag`, add the new public key with
`POST /admin/v1/issuers/{issuer_id}/keys` and `If-Match`, verify writes with
the new key, then revoke the old key with
`PATCH /admin/v1/issuers/{issuer_id}/keys/{kid}` and a fresh `If-Match`.
The portal backend must bind each developer's login identity to the `owner`
it submits and restrict issuer reads and writes to that owner; the server
authenticates the backend as an admin.
