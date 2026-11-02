# Admin issuer reads

The admin listener (default `localhost:8002`) serves `GET /admin/v1/issuers`
and `GET /admin/v1/issuers/{issuer_id}`. The public and management listeners
return 404 for these routes. Keep the admin listener on a private network.
The [Admin OpenAPI contract](openapi-admin.yaml) describes the response fields.
The server implements only the read operations in that contract.

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
transition, and the configured per-issuer list limit. Key usage counts active
(non-revoked) keys, including keys outside their validity windows.
`keys_limit: null` means no key-count quota is enforced; clients must not treat
it as zero.

The detail ETag identifies the complete JSON representation for either source.
It changes when returned keys, usage, metadata, or derived expiry state change.
`Issuer-Version` separately covers writable issuer metadata, lifecycle, and
key ID/state/validity windows. Future mutation endpoints use it through
`If-Issuer-Version`, so ordinary list publishes do not invalidate writes. The
reads do not provide a transactional snapshot across issuer metadata, keys,
and usage.

Run the [admin demo](../demo/README.md#admin-issuer-reads) to list issuers and
inspect a detail response without placing the bearer token in shell history.
