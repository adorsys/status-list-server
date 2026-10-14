# Issuer trust contract

**Status: planned.** This document turns [ADR-0002](adr/0002-issuer-trust-onboarding-and-access-control.md) into the interfaces that the EPIC [#187](https://github.com/adorsys/status-list-server/issues/187) implementation issues build against. Nothing here is served yet. [`openapi.yaml`](openapi.yaml) keeps describing what the server does today. When an issue ships its part, it moves that part into `openapi.yaml` and marks the matching section below **Implemented**. Anything in this document may change as long as it stays within the rules that ADR-0002 states with *must* or *never*.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

| Contract | Where | Implemented by |
|---|---|---|
| Listeners and route map | [§1](#1-listeners-and-route-map) | [#624](https://github.com/adorsys/status-list-server/issues/624) |
| Management token | [§2](#2-management-token) | [#240](https://github.com/adorsys/status-list-server/issues/240) |
| Admin token | [§3](#3-admin-token) | [#625](https://github.com/adorsys/status-list-server/issues/625) |
| Authentication errors | [§4](#4-authentication-errors) | [#240](https://github.com/adorsys/status-list-server/issues/240), [#625](https://github.com/adorsys/status-list-server/issues/625) |
| Admin API | [`openapi-admin.yaml`](openapi-admin.yaml) | [#625](https://github.com/adorsys/status-list-server/issues/625), [#626](https://github.com/adorsys/status-list-server/issues/626), [#373](https://github.com/adorsys/status-list-server/issues/373), [#627](https://github.com/adorsys/status-list-server/issues/627) |
| Issuer registry file | [§5](#5-issuer-registry-file), [`schemas/issuers.v1.schema.json`](schemas/issuers.v1.schema.json) | [#371](https://github.com/adorsys/status-list-server/issues/371) |
| Configuration | [§6](#6-configuration) | each issue named in the table |
| Breaking changes and migration | [§7](#7-breaking-changes-and-migration) | [#320](https://github.com/adorsys/status-list-server/issues/320) and the issues listed there |

## 1. Listeners and route map

The server binds three listeners. A route MUST be registered only on the listener named here; on any other listener it MUST return `404`. Startup MUST fail if two listeners resolve to the same `host:port`.

| Route | Listener | Authentication | Change from today |
|---|---|---|---|
| `GET /` | public | none | Returns the service document below instead of `text/plain` |
| `GET /health`, `GET /health/live` | public | none | — |
| `GET /api/v1/status-lists/{list_id}` | public | none | — |
| `GET /api/v1/aggregation/{aggregation_id}` | public | none | — |
| `GET /api/v1/aggregation` (deprecated since #595) | public | none | — |
| `PUT`, `PATCH /api/v1/status-lists/{list_id}/statuses` | management | management token | Moves listener |
| `POST /api/v1/status-lists/{list_id}/allocations` | management | management token | Moves listener |
| `GET /api/v1/credentials` | management | management token | Moves listener; answers from the issuer registry |
| `POST /api/v1/credentials` | management, only when `management_auth.open_registration` is `true` | none | Removed otherwise (§7) |
| `/admin/v1/issuers…` | admin | admin token | New ([`openapi-admin.yaml`](openapi-admin.yaml)) |
| `GET /health/ready` | admin | none | Moves listener |
| `GET /metrics` (when `server.enable_metrics`) | admin | none | Moves listener |

The public and management listeners may share a hostname. The edge then routes by path, and MUST NOT route any path to the admin listener. The management paths are `/api/v1/status-lists/{list_id}/statuses`, `/api/v1/status-lists/{list_id}/allocations` and `/api/v1/credentials`. The first two share the `/api/v1/status-lists/` prefix with the public read, so the edge needs patterns more specific than that prefix, such as a regular expression or a method match. A misrouted request fails safely: it reaches a listener where the route does not exist and gets `404`.

`GET /` service document, served as `application/json`:

```json
{
  "service": "status-list-server",
  "links": {
    "documentation": "https://github.com/adorsys/status-list-server",
    "portal": "https://portal.example.com"
  }
}
```

`links.portal` is present only when `server.links.portal` is set. The document MUST NOT contain a version string.

## 2. Management token

Sent as `Authorization: Bearer <JWS compact serialization>` on every management route.

| Element | Rule |
|---|---|
| Header `typ` | MUST be `statuslist-management+jwt`, compared case-insensitively with an optional `application/` prefix (RFC 7515 §4.1.9). |
| Header `kid` | MUST be present. It is the only way the key is selected. |
| Header `alg` | MUST be one of `ES256`, `ES384`, `EdDSA` (Ed25519), `PS256`, **and** equal to the `alg` registered for `kid`. |
| Header `crit` | A token that carries `crit` MUST be rejected; the server understands no extensions (RFC 7515 §4.1.11). |
| Headers `jwk`, `jku`, `x5u`, `x5c` | MUST be ignored. A key is never taken from the token (RFC 7515 §4.1.2–4.1.6, RFC 8725 §3.10). |
| `iss` | MUST equal the `id` of the issuer that owns `kid`. |
| `aud` | MUST be present, as a string or an array, and contain at least one value of `management_auth.audiences` (RFC 8725 §3.9). |
| `iat` | MUST be present, and MUST NOT be later than now + `leeway_secs`. |
| `exp` | MUST be present, later than `iat`, and not in the past beyond `leeway_secs`. |
| `exp - iat` | MUST NOT exceed `management_auth.max_token_lifetime_secs` (default 300). |
| `nbf` | Optional. If present, MUST NOT be later than now + `leeway_secs`. |
| `jti` | Optional and ignored. Reserved for an opt-in replay cache. |

**Verification order.** The server MUST perform these steps in this order and stop at the first failure:

1. Read the bearer token. If there is none, fail with `missing_token`.
2. Decode the protected header only. Check `typ`, `kid`, the `alg` allowlist and the absence of `crit`.
3. Resolve `kid` against the issuer registry (static file, then the dynamic store in `hosted`). The key's `alg` MUST equal the header `alg`. The key MUST be `active` and the current time within `[not_before, not_after]`. Its issuer MUST be `active` (not disabled, suspended or expired).
4. Verify the signature with the resolved key and the **registered** `alg`.
5. Validate the claims in the table above.
6. Apply the issuer's tier rate limit ([#627](https://github.com/adorsys/status-list-server/issues/627)).
7. Hand the verified issuer to the handler. List ownership is then checked per request, as today (`403 issuer_mismatch`).

No step may decode claims before step 4 to make a trust decision. The server's current `insecure_decode` of `iss` goes away.

## 3. Admin token

Same rules as §2, with these differences:

| Element | Rule |
|---|---|
| Header `typ` | MUST be `statuslist-admin+jwt`. A management token MUST NOT be accepted on the admin listener, and an admin token MUST NOT be accepted on the management listener (RFC 8725 §3.12). |
| `kid` | Resolves only against `admins[].keys` of the registry file. Admin keys never come from the dynamic store. |
| `iss` | MUST equal the admin principal's `id`. |
| `aud` | MUST contain a value of `admin_auth.audiences`. That list MUST NOT share any value with `management_auth.audiences`. |
| Lifetime | `admin_auth.max_token_lifetime_secs`, default 300. |
| Scopes | Taken from the principal's registry entry. A `scope` claim in the token, if any, MUST be ignored. |

## 4. Authentication errors

Both APIs use the existing `{error, error_description}` envelope.

| Situation | Status | `error` | `WWW-Authenticate` |
|---|---|---|---|
| No `Authorization` header, or a scheme other than `Bearer` | `401` | `missing_token` | `Bearer` (no error attribute, RFC 6750 §3.1) |
| A bearer token was sent and fails any check in §2 or §3 | `401` | `invalid_token` | `Bearer error="invalid_token"` |
| Valid admin token, principal lacks the scope | `403` | `insufficient_scope` | `Bearer error="insufficient_scope", scope="<needed>"` |
| Valid management token, list owned by another issuer | `403` | `issuer_mismatch` (unchanged) | — |
| Issuer tier rate limit exceeded | `429` | `too_many_requests` (with `Retry-After`) | — |

Every `invalid_token` response MUST be byte-identical whatever the cause: unknown `kid`, bad signature, wrong `typ`, `aud` or `iss`, expiry, revoked key, disabled or expired issuer. The cause is logged server-side with `kid` and `iss`, never the token. This removes the issuer-enumeration oracle of today's `issuer_not_found` versus `jwt_error`.

## 5. Issuer registry file

The file named by `management_auth.issuers_file`, in YAML (JSON is valid YAML). Its shape is defined by [`schemas/issuers.v1.schema.json`](schemas/issuers.v1.schema.json), with a complete example in [`schemas/issuers.v1.example.yaml`](schemas/issuers.v1.example.yaml). The loader MUST validate the file against the schema, and then MUST enforce these rules, which a JSON Schema cannot express:

1. Issuer and admin `id`s are unique across the whole file, issuers and admins together.
2. `aggregation_id`s are unique.
3. `kid`s are unique across every issuer and admin key in the file.
4. The same key material appears at most once. Keys are compared on their normalised public parameters (EC: `crv`, `x`, `y`; OKP: `crv`, `x`; RSA: `n`, `e` without leading zero bytes), never on thumbprints (RFC 7638 §7).
5. Every key parses as a valid public key: EC points lie on their curve, and RSA moduli are at least 2048 bits.
6. When a key has both `not_before` and `not_after`, `not_before` is earlier.
7. In `hosted`, no issuer `id`, `aggregation_id` or `kid` collides with the dynamic store.

The loader SHOULD warn, without failing, when an issuer has no key valid now, and when an issuer that owns status lists in the database is missing from the file.

**Loading and reloading.** At startup, an invalid file MUST stop the server with a non-zero exit. While running, the server watches the file. A valid new version replaces the active snapshot atomically. An invalid one MUST be rejected, keep the last valid snapshot active, increment `issuer_registry_reload_failures_total` and log the reason. Requests in flight keep the snapshot they started with.

## 6. Configuration

All keys follow the existing convention: `APP_` prefix and `__` between levels, so `server.admin.port` is `APP_SERVER__ADMIN__PORT`. Lists are comma-separated in environment variables, as `management_auth.audiences` already is.

### Server and listeners

| Key | Type | Default | Rules | Issue |
|---|---|---|---|---|
| `server.profile` | `private` \| `hosted` | `private` | `hosted` requires a SQL `database.backend`; startup fails with `memory`. | [#369](https://github.com/adorsys/status-list-server/issues/369) |
| `server.host`, `server.port` | — | `localhost`, `8000` | Unchanged; now the **public** listener. | — |
| `server.management.host` | string | `localhost` | | [#624](https://github.com/adorsys/status-list-server/issues/624) |
| `server.management.port` | u16 | `8001` | The three `host:port` pairs MUST differ. | [#624](https://github.com/adorsys/status-list-server/issues/624) |
| `server.admin.host` | string | `localhost` | | [#624](https://github.com/adorsys/status-list-server/issues/624) |
| `server.admin.port` | u16 | `8002` | | [#624](https://github.com/adorsys/status-list-server/issues/624) |
| `server.links.documentation` | URL | `https://github.com/adorsys/status-list-server` | Shown in the `GET /` document. | [#624](https://github.com/adorsys/status-list-server/issues/624) |
| `server.links.portal` | URL | unset | Shown in the `GET /` document when set. | [#624](https://github.com/adorsys/status-list-server/issues/624) |

### Authentication

| Key | Type | Default | Rules | Issue |
|---|---|---|---|---|
| `management_auth.issuers_file` | path | unset | Required unless `open_registration` is `true`. On Kubernetes, mount the ConfigMap as a directory: a `subPath` mount never receives updates. | [#371](https://github.com/adorsys/status-list-server/issues/371) |
| `management_auth.open_registration` | bool | `false` | Development only. Startup fails when `true` and `APP_ENV=production`. | [#320](https://github.com/adorsys/status-list-server/issues/320) |
| `management_auth.audiences` | list | `[]` | Startup fails when empty and `APP_ENV=production`. When empty in development, `aud` is not checked and a warning is logged. | [#240](https://github.com/adorsys/status-list-server/issues/240) |
| `management_auth.leeway_secs` | u64 | `60` | Unchanged. | — |
| `management_auth.max_token_lifetime_secs` | u64 | `300` (**was `3600`**) | Greater than 0. | [#240](https://github.com/adorsys/status-list-server/issues/240) |
| `admin_auth.audiences` | list | `[]` | Startup fails when the registry defines admins, this list is empty and `APP_ENV=production`. MUST NOT share a value with `management_auth.audiences`. | [#625](https://github.com/adorsys/status-list-server/issues/625) |
| `admin_auth.leeway_secs` | u64 | `60` | | [#625](https://github.com/adorsys/status-list-server/issues/625) |
| `admin_auth.max_token_lifetime_secs` | u64 | `300` | Greater than 0. | [#625](https://github.com/adorsys/status-list-server/issues/625) |

### Tiers

`tiers.standard` applies to static issuers unless their registry entry says otherwise; `tiers.sandbox` applies to portal issuers. The existing `limits.*` keys stay as global hard caps: no tier value may exceed them. Every `sandbox` value MUST be less than or equal to the `standard` value. `max_lists` MUST NOT exceed the aggregation page size (1000), per [#592](https://github.com/adorsys/status-list-server/issues/592). Startup fails on any violation. Implemented by [#627](https://github.com/adorsys/status-list-server/issues/627).

| Key (under `tiers.standard.` / `tiers.sandbox.`) | `standard` default | `sandbox` default |
|---|---|---|
| `max_lists` | `limits.max_lists_per_issuer` | `10` |
| `max_status_index` | `limits.max_status_index` (100 000) | `10000` |
| `max_statuses_per_request` | `limits.max_statuses_per_request` (5 000) | `1000` |
| `max_keys` (non-revoked) | `5` | `2` |
| `write_burst_size` | `100` | `10` |
| `write_period_secs` (one token replenished per period, per replica) | `1` | `6` |
| `max_lifetime_days` | — (never expires) | `30` |

### Portal (not server configuration)

These live in the portal's own configuration, in its ADORSYS-GIS repository, and are enforced by the portal backend through the admin API: at most **2** active sandbox issuers per account, at most **100** active sandbox issuers in total, manual approval of sign-ups **off**, and an OIDC provider (default GitHub).

## 7. Breaking changes and migration

These changes are breaking for issuers or operators. They SHOULD be released together, in one major version, so integrators migrate once. Each implementing PR marks its change with a `!` Conventional Commit type, so release-plz computes the major bump.

| # | Change | Who is affected | What to do | Issue |
|---|---|---|---|---|
| B1 | `POST /api/v1/credentials` is removed, except with `open_registration` in development | Issuers that self-register; operators | Operators list issuers in the registry. Run `cargo xtask issuer export --database-url …` to turn the existing `credentials` table into a registry draft that keeps every issuer `id` and `aggregation_id` | [#320](https://github.com/adorsys/status-list-server/issues/320) |
| B2 | Management tokens MUST carry `typ`, `kid` and `aud` | Issuer integrations | Set `typ: statuslist-management+jwt` and `kid` (from the registry or `cargo xtask issuer export`) in the header, and `aud` in the claims | [#240](https://github.com/adorsys/status-list-server/issues/240) |
| B3 | Default maximum token lifetime drops from 3600 s to 300 s | Issuers minting long-lived tokens | Mint a token per request or batch, valid at most 5 minutes | [#240](https://github.com/adorsys/status-list-server/issues/240) |
| B4 | `401` codes `invalid_auth_header`, `jwt_error`, `unsupported_algorithm` and `issuer_not_found` are replaced by `missing_token` and `invalid_token`. The `404 issuer_not_found` of `GET /api/v1/credentials` is removed | Clients that branch on those codes | Branch on `401` plus `missing_token` or `invalid_token` | [#240](https://github.com/adorsys/status-list-server/issues/240) |
| B5 | Management routes move to the management listener (port 8001). `/health/ready` and `/metrics` move to the admin listener (port 8002) | Operators: ingress, probes, Prometheus scrape configs, `NetworkPolicy`. Issuers send management requests to wherever the operator publishes the management listener, on the public hostname or a separate one | Update the Helm values; the chart ships the new ports. On a shared hostname, route the management paths to the management listener (§1) | [#624](https://github.com/adorsys/status-list-server/issues/624) |
| B6 | `GET /` returns a JSON service document instead of `text/plain` | Anything that reads `/` | Read `application/json`, or stop reading `/` | [#624](https://github.com/adorsys/status-list-server/issues/624) |
| B7 | A registry file is required in production. Symmetric JWKs and JWKs with private members are rejected | Operators | Provide `management_auth.issuers_file`; replace rejected keys | [#371](https://github.com/adorsys/status-list-server/issues/371) |
| B8 | `management_auth.audiences` is required in production | Operators and issuers | Configure one audience value and have issuers send it | [#240](https://github.com/adorsys/status-list-server/issues/240) |

**Not breaking:** the admin API, `server.profile = hosted`, tiers (the `standard` defaults equal today's global limits), `cargo xtask issuer` commands, and `GET /api/v1/credentials`, which keeps its response shape.

**Migration order for an existing deployment:**

1. Before upgrading, export the registry draft from the running database, review it, and commit it to the deployment repository.
2. Agree an audience value with every issuer and configure it. Issuers add `typ`, `kid` and `aud` to their tokens; the current server ignores the extra fields, so this can happen before the upgrade.
3. Upgrade the server and the Helm chart together (new ports, probes and scrape targets).
4. Verify that each issuer can `GET /api/v1/credentials` on the management listener and that its `aggregation_uri` is unchanged.
