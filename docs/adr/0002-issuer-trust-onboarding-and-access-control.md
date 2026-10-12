# 2. Issuer trust, onboarding, and access control

- **Status:** Accepted
- **Date:** 2026-10-12
- **Issue:** [#372](https://github.com/adorsys/status-list-server/issues/372), part of EPIC [#187](https://github.com/adorsys/status-list-server/issues/187). Supersedes the design proposal in [#587](https://github.com/adorsys/status-list-server/issues/587).

## Context

### The problem

Anyone who can reach the server can become an issuer. `POST /api/v1/credentials` is unauthenticated (`src/startup.rs`, `api_v1_routes`: the `credentials` router sits outside `route_layer(auth)`), and it binds a caller-chosen identifier to a caller-chosen JWK, first come first served. The whole API is served from one listener, and the Helm ingress forwards a single path prefix to it, so that endpoint is on the internet.

Everything else about issuer identity follows from that gap:

| # | Weakness | Where | STRIDE |
|---|---|---|---|
| W1 | Unauthenticated registration lets a caller claim any unused issuer id | `startup.rs`, `handlers/issue_credential.rs` | Spoofing, Elevation |
| W2 | One listener: registration and management routes are internet-reachable and protected only by ingress path rules | `startup.rs` (single `TcpListener`), `deploy/helm/.../ingress.yaml` | All of the below, remotely |
| W3 | One key per issuer, insert-only, no `kid`, no revocation; a compromised key needs manual database surgery | `CredentialRepo::insert`, `CredentialError::AlreadyExists` | Spoofing after compromise |
| W4 | The JWT `alg` comes from the attacker-controlled header; `PublicJwk::try_new` accepts `kty: oct` and JWKs with private members | `server/auth/mod.rs`, `domain/models/credential.rs`; [#240](https://github.com/adorsys/status-list-server/issues/240) | Defence in depth (RFC 8725 §2.1) |
| W5 | `issuer_not_found` and `jwt_error` are distinguishable, so issuer ids can be enumerated | `server/auth/errors.rs` | Information disclosure |
| W6 | `aud` optional; tokens may live 3600 s; no explicit token type | `ManagementAuthConfig::default` | Replay, cross-JWT confusion |
| W7 | No record of who trusted which key, when | — | Repudiation |
| W8 | No way to list or inspect registered issuers without database access | — | Operability |
| W9 | No per-issuer limits: rate buckets are per IP (and spoofable, [#540](https://github.com/adorsys/status-list-server/issues/540)), so one tenant can starve others on a shared server | `server/rate_limit.rs` | Denial of service |

**What is sound and stays:** issuers authenticate each write with a short-lived, asymmetrically signed JWT, and list ownership is checked on every write (`domain/service.rs` rejects `existing.issuer != issuer`). The weak part is how a public key becomes trusted, not how a token is checked.

**What must be preserved:** since [#595](https://github.com/adorsys/status-list-server/pull/595), the server assigns every issuer an `aggregation_id` (UUID) at registration. Every Status List Token carries it in `aggregation_uri` (`/api/v1/aggregation/{aggregation_id}`), and those tokens live as long as the credentials that reference them. An issuer's `aggregation_id` must therefore survive any change of trust source or key, unchanged.

### Requirements from the team (meeting of 2026-10-05, and follow-up)

1. Keep it simple and secure. [#587](https://github.com/adorsys/status-list-server/issues/587) (UUIDs, OAuth client credentials, DNS proof, challenge flows) was judged too heavy for what it buys: nothing outside the server reads a verified domain. The Status List Token identifies an issuer only through an opaque, server-assigned `aggregation_id`, never through a domain.
2. **Constrained organisations** run the server privately. Only the retrieval surface defined by the Token Status List spec faces the internet.
3. The **live, adorsys-hosted server** must not be usable anonymously by external issuers.
4. External issuers **sign up through a portal** and receive **credentials for testing**.
5. Those credentials carry **usage limits and quotas**, so one tenant cannot abuse or overload the shared server.
6. A **protected endpoint lists and queries** existing issuers.
7. Issuer keys can be **rotated and revoked** without downtime.

Requirements 2 and 3–4 contradict each other if they are read as one deployment. They are **two deployment profiles of the same binary**, and the decision below is built around that.

## Decision

### 1. Two deployment profiles

| | `private` (default) | `hosted` |
|---|---|---|
| Who runs it | Constrained organisations | adorsys (shared live / sandbox server) |
| Who can become an issuer | Only operator-listed issuers (static registry) | Operator-listed issuers **and** portal-registered sandbox issuers |
| Internet-facing | Public read routes only | Public read routes **and** the management API, on a separate hostname |
| Portal | None | Separate deployment on its own origin |
| Required storage | Any backend, including `memory` | A SQL backend (portal issuers persist) |

`server.profile` selects the profile. Every other setting below has a profile-dependent default and a startup check, so an operator cannot half-enable `hosted` by accident.

### 2. Three listeners, three route sets

The server binds three listeners. Each router is built from its own route set, so a route **does not exist** on a listener it does not belong to. Exposure is decided by which port is reachable, and `NetworkPolicy` enforces that. Ingress path matching, which is easy to get wrong, no longer decides it.

| Listener | Routes | `private` | `hosted` |
|---|---|---|---|
| **public** (`server.port`) | `GET /api/v1/status-lists/{list_id}`, `GET /api/v1/aggregation/{aggregation_id}` (spec §9.3), the deprecated cross-issuer `GET /api/v1/aggregation` until it is removed, `GET /health/live`, `GET /` | Internet, via ingress | Internet, `status.<domain>` |
| **management** (`server.management.port`) | `PUT`/`PATCH /api/v1/status-lists/{list_id}/statuses`, `POST /api/v1/status-lists/{list_id}/allocations`, `GET /api/v1/credentials` (the calling issuer's own registration) | Private network only | Internet, `api.<domain>`, separate ingress, auth always required |
| **admin** (`server.admin.port`) | `/admin/v1/issuers…`, `GET /health/ready`, `GET /metrics` | Private network only | Private network only: portal backend and operators |

Why three listeners rather than two: in `hosted`, the management API must face the internet so external issuers can write. Admin operations must never face it. If admin routes shared a listener with management routes, they would be one ingress mistake away from exposure.

Startup refuses to run if two listeners resolve to the same `host:port`. The Helm chart adds `ClusterIP` Service ports `management` and `admin`. `NetworkPolicy` gets one rule per port, and an empty `from:` on the management or admin port means **deny all**. This fails closed, unlike today's public-port rule.

### 3. Issuer trust: one verifier, two sources

Authentication depends on one narrow port, so the handlers and the token contract do not change when the source of trust does:

```rust
/// Resolves a token `kid` to the key and issuer that are trusted *right now*.
pub trait IssuerKeyResolver: Send + Sync {
    async fn resolve(&self, kid: &str) -> Result<Option<ResolvedKey>, ResolveError>;
    // ResolvedKey { issuer, source, tier, alg, decoding_key, state, not_before, not_after }
}
```

Two implementations are composed: the static registry is consulted first, then the dynamic store if it is enabled. Issuer ids, `aggregation_id`s and `kid`s are unique **across both**, and any collision fails closed.

#### 3a. Static registry (both profiles): operator-trusted issuers

The operator declares trusted issuers and their **public** keys in a file mounted from a ConfigMap. The server validates it at startup and hot-reloads it:

```yaml
# issuers.yaml — public keys only; integrity-critical, not confidential.
version: 1
issuers:
  - id: "6f1c2a9e-0b7d-4c1e-9a53-2f8d7e4b1c00"   # `cargo xtask issuer add` generates a UUIDv4; legacy ids are preserved on migration
    aggregation_id: "0b8ef1c4-3c6a-4d2e-9f1a-5b7c9d2e4f60"  # generated once, then immutable; preserved on migration
    display_name: "Acme Wallet Issuer"
    tier: standard
    keys:
      - kid: "acme-2026-10"                      # default: RFC 7638 thumbprint
        alg: ES256                               # pinned; the header `alg` must equal this
        jwk: { kty: EC, crv: P-256, x: "…", y: "…" }
        not_after: "2027-04-01T00:00:00Z"
admins:                                          # principals allowed on the admin listener
  - id: "portal-backend"
    scopes: ["issuers:read", "issuers:write"]
    keys:
      - { kid: "portal-2026-10", alg: ES256, jwk: { kty: EC, crv: P-256, x: "…", y: "…" } }
  - id: "ops-oncall"
    scopes: ["issuers:read"]
    keys:
      - { kid: "ops-2026-10", alg: EdDSA, jwk: { kty: OKP, crv: Ed25519, x: "…" } }
```

- **Fail closed at load:** the version must be known; issuer and admin ids must be unique; `aggregation_id`s must be unique UUIDs; `kid`s must be globally unique. Each `jwk` must parse, `kty`/`crv` must match `alg`, `kty: oct` is rejected, and any private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) is rejected. This catches a pasted private JWK. At startup an invalid file means the server refuses to start. On reload (`utils::file_watcher::FileWatcher`, which compares SHA-256 of the content) an invalid file is rejected, the last good snapshot stays active, and `issuer_registry_reload_failures_total` is incremented. A valid file is swapped in atomically through `ArcSwap`.
- **Audit trail (W7):** the file lives in a GitOps repository, so every trust change is a reviewed commit.

#### 3b. Dynamic store (`hosted` only): portal-registered sandbox issuers

These live in SQL tables (`issuers`, `issuer_keys`) and are written **only** through the admin API (§5). Nothing on the public or management listener can create or modify them. Each row records `source = portal`, `tier = sandbox`, `owner` (the portal account subject), `aggregation_id` (assigned at creation), `state`, `expires_at`, and per-key `state`, `not_before` and `not_after`. Lookups go to the database by primary key on every authenticated write, with no cache. Revocation therefore takes effect on the next request on every replica, and writes are far rarer than reads.

#### 3c. Identifiers and keys

- Portal issuers get a **server-generated UUIDv4** issuer id. Clients never choose an identifier, which was the consensus in #587, and that ends squatting (W1).
- The issuer id and the `aggregation_id` are **separate values on purpose**. The `aggregation_id` is public, because it appears in every token's `aggregation_uri`. The issuer id is the `iss` of management tokens, and keeping it out of public documents means knowing a public URI reveals nothing usable for authentication. Both are immutable.
- An issuer has several keys (a maximum per tier; 2 for `sandbox`). The key states are `active` and `revoked`; revocation is permanent. The issuer states are `active`, `suspended` and `expired`. Any non-active state rejects writes immediately.
- Revocation does **not** rely on JWK thumbprints to block re-enrolment of a revoked key. RFC 7638 §7 warns that thumbprints are unreliable for exclusion, as raised in #587. A revoked `kid` is never reused, and reusing the same key material across issuers is rejected on the canonical, normalised key parameters.

### 4. Token contract (management and admin requests)

`Authorization: Bearer <JWT>`. Every token carries an explicit type, so a token minted for one purpose cannot be replayed for another (RFC 8725 §3.11 and §3.12):

| Element | Management token | Admin token |
|---|---|---|
| header `typ` | `statuslist-management+jwt` | `statuslist-admin+jwt` |
| header `kid` | required; resolves to an **issuer** key | required; resolves to an **admin** key |
| header `alg` | in `{ES256, ES384, EdDSA, PS256}` **and** equal to the key's pinned `alg` | same |
| `iss` | equals the owning issuer id | equals the admin principal id |
| `aud` | required; one of `management_auth.audiences` | required; one of `admin_auth.audiences`, which must not overlap with the management audiences |
| `iat`, `exp` | required; `exp − iat ≤ 300 s` by default (was 3600) | required; `≤ 300 s` |
| `jti` | optional; a replay cache is a later, opt-in addition | optional |
| scope | — | taken from the registry entry, not from the token; tokens cannot widen their own scope |

**Verification order:** decode the header only, then check `typ`, the allowlist, and that `kid` is present. Resolve `kid`, then reject on an `alg` mismatch, an inactive key or issuer, or a time outside `[not_before, not_after]`. Verify the signature and claims with the **pinned** `alg`. Check that `iss` equals the owner, apply the tier rate limit (§6), and insert the principal. This removes today's `insecure_decode` of `iss` before verification.

**Uniform failure (W5):** every authentication failure returns `401` with `{"error":"invalid_token"}` and `WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750 §3 and §3.1). The specific reason is logged server-side with `kid` and `iss`, never the token. An admin token on the management listener, or a management token on the admin listener, fails the same way.

### 5. Admin API (protected issuer list, query and lifecycle)

This API is served only on the **admin listener**. It returns the existing `{error, error_description}` envelope, and every response carries `Cache-Control: no-store`.

| Method and path | Scope | Contract |
|---|---|---|
| `GET /admin/v1/issuers?source=&tier=&state=&owner=&cursor=&limit=` | `issuers:read` | Cursor-paginated (`limit` ≤ 100, default 50), ordered by `id`; static and portal issuers together |
| `GET /admin/v1/issuers/{issuer_id}` | `issuers:read` | Issuer, keys, quota usage; `ETag` |
| `POST /admin/v1/issuers` | `issuers:write` | Creates a **portal** sandbox issuer from `{display_name, owner, public_key, alg}`; the server assigns `id`, `aggregation_id` and `kid`; `201` + `Location` |
| `POST /admin/v1/issuers/{issuer_id}/keys` | `issuers:write` | Adds a key (up to the tier maximum); `201` |
| `PATCH /admin/v1/issuers/{issuer_id}` | `issuers:write` | `{state: active\|suspended}` or `{expires_at}` (capped by the tier); `If-Match` required |
| `PATCH /admin/v1/issuers/{issuer_id}/keys/{kid}` | `issuers:write` | `{state: revoked}` only; `If-Match` required |

Representation:

```json
{
  "id": "6f1c2a9e-…", "aggregation_id": "0b8ef1c4-…", "aggregation_uri": "https://status.<domain>/api/v1/aggregation/0b8ef1c4-…",
  "display_name": "…", "source": "static|portal", "tier": "standard|sandbox",
  "state": "active|suspended|expired", "owner": "github|12345 or null", "created_at": 0, "expires_at": 0,
  "keys": [{ "kid": "…", "alg": "ES256", "state": "active|revoked", "not_before": 0, "not_after": 0, "public_key": { } }],
  "usage": { "lists": 3, "lists_limit": 10 }
}
```

- **Static issuers are read-only through the API.** Writes to them return `409 issuer_managed_by_configuration`, because the file is their source of truth and a second write path would let the two drift.
- Unknown issuer ids return `404`. A `403` is reserved for a valid admin principal that lacks the required scope. The API never returns private material; it has none.
- Every write appends an audit event (actor, action, target, before and after state) in the same transaction.

### 6. Usage limits and quotas, layered from the edge inwards

| Layer | Keyed on | What it protects | Where |
|---|---|---|---|
| Edge rate limit | Client IP | Whole cluster; cheap rejection before the app | Ingress (cluster-wide). Per #540's direction: the edge owns global caps |
| Pre-auth write gate | Client IP (trusted-proxy aware, #540) | Signature verification and key lookup cost | App, before `auth` |
| **Per-issuer rate limit** | Verified `AuthenticatedIssuer` | Fairness between tenants (W9) | App, after `auth`; limits per **tier** |
| **Resource quotas** | Issuer | Storage and response size | App/DB: max lists (existing `list_quota`), max `status_index`, statuses per request, max keys — per tier |
| **Credential lifetime** | Issuer | Abandoned test credentials | `sandbox` issuers expire, renewable in the portal |
| **Sign-up caps** | Portal account / global | Mass sign-up | Portal: max sandbox issuers per account, global active cap, optional manual approval |

Tiers are configured centrally (`tiers.standard`, `tiers.sandbox`), and each issuer references one, so a limit is never set per issuer. This respects [#592](https://github.com/adorsys/status-list-server/issues/592): the per-issuer list quota cannot exceed the aggregation page size, so `sandbox` may only be **lower** than `standard`. A rate limit returns `429 too_many_requests` with `Retry-After` (#540 contract). An exhausted quota returns the existing `list_quota_exceeded`.

**Default `sandbox` tier**, agreed on 2026-10-12. Each value is an operator-overridable default, never a hard-coded constant. `standard` keeps today's global limits.

| Limit | `sandbox` default | `standard` default (today's global value) |
|---|---|---|
| Status lists per issuer | 10 | `limits.max_lists_per_issuer` (≤ 1000) |
| Highest `status_index` | 10 000 | 100 000 |
| Statuses per request | 1 000 | 5 000 |
| Active keys | 2 | operator-defined |
| Write rate, per issuer, per replica | burst 10, then 1 every 6 s | operator-defined |
| Credential lifetime | 30 days, renewable | no expiry |
| Sandbox issuers per portal account | 2 | — |
| Active sandbox issuers, global | 100 | — |
| Manual approval of sign-ups | off | — |

### 7. Developer portal: separate origin, not the server's root

**Serving the portal UI from `/` of the status list server is not sound.** It is rejected for these reasons:

1. **Origin coupling.** The portal is a human-facing web app with sessions, cookies, forms and third-party login redirects. On the same origin as the API, any XSS or dependency compromise in the portal's JavaScript runs with that origin's authority. The API, its CORS and CSP rules, and every cookie scoped to that host then become the portal's attack surface. A JSON API and an HTML app need opposite security headers.
2. **The status host is a long-lived public contract.** Status list URIs (`sub`) and `aggregation_uri`s on this host are embedded in credentials that live for years. That host should serve a minimal, read-only, cache-friendly surface whose availability does not depend on a UI's release cadence, bundle size or bugs (Hyrum's law).
3. **It defeats the listener split.** The public listener is reduced to read-only `GET` routes on purpose. Adding a UI, login callbacks and session endpoints there undoes that reduction.
4. **Private deployments must not carry it.** Constrained organisations run no portal. Building it into the server binary ships unused code, a JavaScript toolchain and its CVE surface to every deployment.
5. **Different scaling and caching.** Status reads are CDN-cacheable and spike with relying-party traffic. Portal traffic is low-volume and session-bound.

**Instead, the portal is a separate deployment on its own origin** (for example `portal.<domain>`), built as a backend-for-frontend:

```text
browser ──(OIDC login; httpOnly, Secure, SameSite=Lax session cookie; CSRF token)──▶ portal BFF
portal BFF ──(statuslist-admin+jwt, scope issuers:read/write, private network)──▶ admin listener
external issuer code ──(statuslist-management+jwt)──▶ api.<domain> (management listener)
relying parties ──(anonymous GET)──▶ status.<domain> (public listener)
```

- **Code location:** a **separate repository in the [ADORSYS-GIS](https://github.com/ADORSYS-GIS) GitHub organization**, with its own CI, release cycle and dependency audits. Its name is chosen when the portal work ([#628](https://github.com/adorsys/status-list-server/issues/628)) starts. It depends on this server only through the admin API contract.
- **Human login** uses **generic OIDC**: the portal accepts any OpenID Connect provider through configuration (issuer URL, client id, client secret). The hosted sandbox ships with **GitHub as the default provider**, because its audience is developers. Keycloak or another provider is a configuration change, not a code change. The portal account subject, qualified by the provider (`<provider>|<sub>`), becomes the issuer's `owner`.
- **Keys:** the portal offers **in-browser key generation** (WebCrypto ES256; the private key is downloaded as a file and **never sent anywhere**), or the developer pastes an existing public JWK. The server and portal hold public keys only. Sandbox issuers therefore use **the same authentication mechanism as production**, which is what a test environment exists to exercise. Issuing API keys for testing would mean testers integrate against a mechanism they cannot use in production.
- **The portal shows** the issuer id, `aggregation_uri`, `kid`, audience, management base URL, a token-minting snippet, quota usage and expiry. Owners can add a key, revoke a key, renew, or delete (suspend) their own sandbox issuers. The BFF enforces owner scoping on every call.
- **The portal's own admin key** lives in a secret store (Kubernetes Secret via External Secrets, or KMS). It is rotated through the static registry like any other key.
- **`GET /` on the public listener** returns a minimal JSON service document: `{"service":"status-list-server","links":{"documentation":"…","portal":"…"}}`. The portal link is present only when configured. There is no version string, no HTML and no redirect.

**Rotation authority**, answering the concern raised on #587 that a bearer token alone can add keys:

- **Static issuers:** only the operator, through a reviewed commit.
- **Portal issuers:** the authenticated portal owner. A compromised portal account can therefore enrol a key for that owner's sandbox issuers. This is **accepted because the blast radius is bounded**: those issuers are `sandbox` only, quota-limited, expiring, and served under a non-production signing identity (§8). Production issuers are never onboarded through the portal; moving to production means being added to a registry by an operator.

### 8. The `hosted` server is a non-production trust domain

The server signs every Status List Token with **its own** key, not the issuer's (see [#133](https://github.com/adorsys/status-list-server/issues/133) and [#177](https://github.com/adorsys/status-list-server/issues/177)). On a multi-tenant sandbox, that means the server vouches for content written by anyone who signs up. Therefore:

- The `hosted` sandbox uses its **own hostname and signing certificate**, distinct from any production deployment, and both are documented as test-only.
- Production relying parties must not trust that certificate. The trust-model document (#177) must say so.

### 9. Retiring `POST /api/v1/credentials`

- The registration route is removed from both profiles. A temporary `management_auth.open_registration = true` exists for local development and the `demo/` notebooks only. It is served only on the management listener, logs a warning, and **startup refuses it when `APP_ENV=production`**.
- `GET /api/v1/credentials` stays. It moves to the management listener and keeps its response shape. It now reads the calling issuer's registration from the resolver instead of the `credentials` table.
- **Migration:** `cargo xtask issuer export --database-url …` writes the existing `credentials` rows into an `issuers.yaml` draft. It preserves each legacy issuer id and its `aggregation_id`, so list ownership and every `aggregation_uri` already embedded in issued tokens stay valid. It sets each `kid` to the key's RFC 7638 thumbprint. Operators review and commit it. Issuers must then send `kid`, `typ` and `aud`.
- The `credentials` table becomes read-only legacy and is dropped in a later migration.
- Removing a route and requiring new token fields are observable contract changes, so this ships as a **major** version, with `CHANGELOG` and `docs/openapi.yaml` updated.

## Considered options

### Issuer credential type

| | Static API keys | **Signed JWT + registered public keys (chosen)** | mTLS client certificates | OAuth2 client credentials ([#587](https://github.com/adorsys/status-list-server/issues/587)) |
|---|---|---|---|---|
| Secrets held by the server | Key hashes; needs a secret store | **None** | CA bundle (public) | None, but trusts an external authority |
| Impact of a leak | Bearer value replayable until rotated; often ends up in logs and proxies | One token: ≤ 300 s, one audience, one type. The private key never leaves the issuer | Impersonation until revoked | Token until expiry; client secret = full takeover |
| Proof of possession | No | Yes | Yes | No |
| New infrastructure | None | **None** | Internal CA, certificate lifecycle, TLS passthrough at ingress | IdP, client provisioning, availability dependency |
| Reuse of existing code | Little | **High** (`auth/mod.rs` claim policy, `FileWatcher`, `ArcSwap`) | Low | Medium |
| Effort for the issuer | Trivial | Low: credential issuers already sign JWTs | Medium | Medium |

API keys are the simplest option on paper. But they add a server-side secret store, give up the proof of possession the server already has, and would make the sandbox credential different from the production one. mTLS stays available as **optional defence in depth** at the mesh or internal load balancer, outside the server. OAuth2 remains a future option: the `IssuerKeyResolver` port can gain an implementation for it without changing the token contract.

### Ownership proof (from #187 and #587)

| Option | Outcome |
|---|---|
| Operator pre-registration | **Chosen** for production issuers (static registry) |
| Server-assigned UUID | **Chosen** for portal issuers; recommended for static ones |
| Reverse-domain id + DNS / well-known proof | **Rejected.** Nothing outside the server reads the domain; the Status List Token names an issuer only by an opaque `aggregation_id`. Making a domain meaningful needs multi-vantage DNS or DNSSEC checks, and it adds a public-DNS dependency to private deployments. It can be reopened if #177 decides relying parties should see an issuer domain |
| DID proof | **Deferred.** Resolver risk without a consumer for the result |
| External trusted-issuer registry or federation (EUDI, OpenID Federation, EBSI) | **Deferred.** The static registry is that registry's local form, and an `IssuerKeyResolver` adapter can be added when a deployment needs one |
| Existing key authorises the next key | **Not adopted as a requirement.** Operator review (static) or owner session within sandbox limits (portal) is simpler and allows recovery when the old key is lost |
| Offline recovery key | **Rejected.** For static issuers the operator is the recovery path; for portal issuers the account owner is |

### Portal placement

| Option | Outcome |
|---|---|
| Portal UI served from `/` of the status list server | **Rejected** (§7) |
| Portal under a path on the same host (`/portal`) | **Rejected.** Same origin, so the same coupling as above |
| `portal/` directory inside this repository | **Rejected.** It would bring a JavaScript toolchain, its audits and CI jobs into this repository's supply chain |
| **Separate repository and deployment on its own origin; BFF calls the admin listener** | **Chosen** |
| Portal writes directly to the server's database | **Rejected.** It bypasses validation, audit and quotas, and couples two deployments to one schema |

## Security implications

| Threat | Mitigation |
|---|---|
| Anonymous use of the live server | No unauthenticated write route exists on any listener. Only public `GET` routes are anonymous |
| Issuer squatting or impersonation | No self-chosen identifiers. Portal ids are server-generated; static ids are operator-assigned |
| Stolen management token | `exp − iat ≤ 300 s`; `aud` and `typ` bound; no scope widening |
| Stolen issuer private key | Never held by the server or portal. Revoke the `kid` (static: commit and reload; portal: immediate) |
| Algorithm confusion, symmetric or private JWKs | Asymmetric allowlist, `alg` pinned per key, `oct` and private members rejected at load and on create |
| Issuer enumeration | Uniform `401 invalid_token`; the admin API lives only on the private listener; the public `aggregation_id` differs from the issuer id |
| Compromised portal account | Blast radius limited to that owner's `sandbox` issuers, which are quota-bounded, expiring, and on a non-production signing identity |
| Compromised portal backend | Its scope covers **portal** issuers only, not static ones. It cannot write status lists, because admin tokens are rejected on the management listener. It is reachable only on the private admin port. Rotate its key through the registry |
| Leaked admin credential | Admin listener not internet-reachable; scopes come from the registry; short token lifetime |
| Tampering with the registry file | GitOps review, read-only mount, Kubernetes RBAC on the ConfigMap. A bad file is rejected and the last good snapshot kept |
| Tenant starving the shared server | Edge rate limit, pre-auth IP gate, per-issuer tier limits, resource quotas, sign-up caps |
| Sandbox content mistaken for production | Separate hostname and signing certificate; documented as untrusted by production relying parties (§8) |
| Secrets in logs | Tokens, proofs and keys are never logged; only `kid`, `iss` and the outcome |

## Trade-offs

- **Onboarding is an operator action for production issuers.** A PR plus a ConfigMap rollout replaces an API call. This is intentional: production trust is a human decision with an audit trail.
- **Two sources of truth in `hosted`** (file and database). This is contained by a single resolver, global uniqueness checks, and API writes being refused for static issuers.
- **Breaking release:** `POST /api/v1/credentials` goes away, and `kid`, `typ` and `aud` become required.
- **More ports and Helm surface:** three Service ports, three `NetworkPolicy` rules, and two ingresses in `hosted`.
- **Per-issuer rate limits are per replica,** so the effective limit is the configured value times the number of replicas. Cluster-wide caps stay at the edge. A shared counter (Redis) is a later option, only if measurements show it is needed.
- **A new deployable (the portal)** with its own repository, release cycle, OIDC application and secret. It is needed only for `hosted`.

## Operational constraints

- **Static revocation is not instant on Kubernetes.** A ConfigMap volume update reaches the pod after the kubelet sync period plus its cache TTL (typically up to about a minute). A `subPath` mount **never** updates, so the chart must mount the directory. For an emergency, also restart the rollout. Portal-issuer revocation is immediate.
- **`hosted` requires a SQL backend** (`postgres` recommended) for the dynamic store and audit events. Startup refuses `hosted` with `memory`.
- **Clock skew:** token lifetimes are short, so nodes need NTP; leeway defaults to 60 s.
- **Ingress (`hosted`):** `status.<domain>` maps to the public port only, and `api.<domain>` to the management port only. Neither may route to the admin port. Each has its own edge rate limits. The `X-Forwarded-For` overwrite is restored as part of #540.
- **Portal operations:** an OIDC client registration with the default provider (GitHub) for the hosted sandbox, the BFF admin key in a secret store, and the sign-up caps and sandbox expiry policy in §6.
- **Observability:** `issuer_registry_reload_failures_total`, `issuer_registry_keys{source}`, `management_auth_requests_total{outcome}` (issuer and `kid` labels only for the static source, to keep cardinality bounded), quota rejection counters, and admin audit events.

## Out of scope

- Signing Status List Tokens with issuer keys ([#133](https://github.com/adorsys/status-list-server/issues/133)).
- Retiring status lists and releasing quota ([#592](https://github.com/adorsys/status-list-server/issues/592)), although expired sandbox issuers will need it.
- IP-extraction and `429`-contract fixes in the rate limiter ([#540](https://github.com/adorsys/status-list-server/issues/540)). This ADR depends on them but does not own them.
- Removing the deprecated cross-issuer `GET /api/v1/aggregation`, which has its own deprecation path from #595.

## Review decisions

These open questions were answered on 2026-10-12, and are recorded in the sections above:

1. **Portal repository:** a separate repository in the ADORSYS-GIS organization (§7).
2. **Portal sign-in:** generic OIDC, with GitHub as the default provider for the hosted sandbox (§7).
3. **Default `sandbox` limits:** the values in §6.
