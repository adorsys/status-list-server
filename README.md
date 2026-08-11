# Status List Server

[![CI](https://github.com/adorsys/status-list-server/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/adorsys/status-list-server/actions/workflows/CI.yml?query=branch%3Amain)
[![CD](https://github.com/adorsys/status-list-server/actions/workflows/deploy.yml/badge.svg?branch=main)](https://github.com/adorsys/status-list-server/actions/workflows/deploy.yml?query=branch%3Amain)
[![dependencies](https://deps.rs/repo/github/adorsys/status-list-server/status.svg)](https://deps.rs/repo/github/adorsys/status-list-server)
[![License](https://img.shields.io/github/license/base-org/node?color=blue)](LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE-APACHE)

The **Status List Server** manages and publishes status lists for credential issuers.  
It allows issuers to register, publish, and update status lists, and verifiers to retrieve and validate them securely.

## Overview

This service implements the [Token Status List specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/).  
It supports both **JWT** and **CWT** formats, with cryptographic signing using multiple algorithms (ECDSA, EdDSA, RSA with SHA-256, SHA-384, SHA-512 digest algorithms).

For a detailed explanation of the architecture, see the [hexagonal architecture documentation](docs/hexagonal-architecture.md).

## Feature Implementation Status

| Feature                         | Status         | Notes                                                               |
| ------------------------------- | -------------- | ------------------------------------------------------------------- |
| Issuer Registration             | ✅ Implemented | Public key registration via `POST /api/v1/credentials`              |
| Status List Publishing          | ✅ Implemented | JWT-signed publishing via `PUT /api/v1/status-lists/{id}/statuses`  |
| Status List Updates             | ✅ Implemented | Partial updates via `PATCH /api/v1/status-lists/{id}/statuses`      |
| JWT Status List Format          | ✅ Implemented | JWS Compact Serialization with `exp`/`ttl`                          |
| CWT Status List Format          | ✅ Implemented | COSE_Sign1_Tagged (tag 18) with `exp`/`ttl`                         |
| Gzip Compression                | ✅ Implemented | Applied to JWT responses only (draft-21 section 8.2)                |
| HTTP Content Negotiation        | ⚠️ Partial     | Exact match only; RFC 9110 patterns (`*/*`, `q=`) not yet supported |
| Historical Resolution (`time=`) | ✅ Implemented | Optional feature for time-based status queries                      |
| Status List Aggregation         | ✅ Implemented | `GET /api/v1/aggregation` + optional `aggregation_uri` token member |
| X.509 Certificate EKU           | ⚠️ Partial     | Placeholder OID (`...3.30`); rename pending spec finalization       |

## Quick Start

### Prerequisites

Before running the server, ensure you have the following tools installed:

- [Rust & Cargo](https://www.rust-lang.org/tools/install) (Latest stable).
- A supported database backend: PostgreSQL, MySQL, or SQLite.
- [Redis](https://redis.io/download): The in-memory data structure store used for caching.
- [Docker](https://www.docker.com/get-started/) (optional, for local testing).

### Run locally

**Clone the Repository:**

```bash
git clone https://github.com/adorsys/status-list-server.git
cd status-list-server
```

**Environment Variables:**

Create a `.env` file in the root directory. Take a look at the [.env.template](.env.template) file for an example of the required variables.

#### Running with Docker Compose

The simplest way to run the project is with [docker compose](https://docs.docker.com/compose/):

- Execute the command below at the root of the project:

```sh
docker compose up --build
```

This command will pull all required images and start the server compiled with default compose features (`postgres,redis,aws,acme`).

To pass custom Cargo feature flags during build, specify the `FEATURES` environment variable:

```sh
FEATURES="mysql,redis,aws,acme" docker compose up --build
```

#### Running Manually

To start the server in zero-infrastructure default in-memory mode, execute:

```bash
cargo run
```

By default, the server will listen on `http://localhost:8000` using in-memory repositories, Moka cache, and store-based certificate management. No external databases, Redis, or cloud services are required for development.

## Cargo Feature Matrix

The crate uses modular Cargo feature flags to gate optional production backend drivers:

| Feature    | Description                                                                                                                                        | Default    |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `memory`   | In-memory repositories (`MemoryStatusLists`, `MemoryCredentials`, `MemoryStatusListHistory`), Moka TTL cache, and store-based certificate storage. | ✅ Default |
| `postgres` | SeaORM PostgreSQL database driver.                                                                                                                 | ❌ Opt-in  |
| `sqlite`   | SeaORM SQLite database driver.                                                                                                                     | ❌ Opt-in  |
| `mysql`    | SeaORM MySQL database driver.                                                                                                                      | ❌ Opt-in  |
| `redis`    | Redis storage and certificate cache driver.                                                                                                        | ❌ Opt-in  |
| `aws`      | AWS S3 object storage and AWS Secrets Manager drivers.                                                                                             | ❌ Opt-in  |
| `acme`     | ACME DNS-01 certificate manager driver.                                                                                                            | ❌ Opt-in  |

To build with specific backend drivers, pass the matching feature flag(s):

```bash
# Run with PostgreSQL and Redis support
cargo run --features postgres,redis

# Run with all AWS and ACME production integrations
cargo run --features postgres,redis,aws,acme
```

For deployment guidance and backend tradeoffs, see [`docs/database-backends.md`](docs/database-backends.md).

## API Documentation

The public API is documented with an OpenAPI 3.1 specification. See [`docs/openapi.yaml`](docs/openapi.yaml) for the complete API contract.

### Retrieve Status List Aggregation

- **Endpoint:** `GET /api/v1/aggregation`
- **Description:** Returns all Status List Token URIs hosted by this server in a single response (Token Status List draft-21 §9), enabling consumers to pre-fetch or keep an offline mirror of every list. The endpoint is publicly accessible with no authentication required. The aggregation is **issuer-agnostic** — every hosted status list URI is included regardless of which issuer owns it.
- **Responses:**
  - `200 OK`

  ```json
  {
    "status_lists": [
      "https://statuslist.example.com/api/v1/status-lists/30202cc6-1e3f-4479-a567-74e86ad73693",
      "https://statuslist.example.com/api/v1/status-lists/755a0cf7-8289-4f65-9d24-0e01be92f4a6"
    ]
  }
  ```

  - `500 INTERNAL SERVER ERROR`: System incurred an error

When the optional `APP_SERVER__AGGREGATION_URI` configuration is set, every emitted Status List Token (JWT and CWT) includes it as the optional `aggregation_uri` member (draft-21 §4.2 / §4.3), allowing a consumer to discover the aggregation link directly from any single list token. When unset, the member is omitted entirely.

## Configuration

All runtime behavior is controlled via environment variables prefixed with `APP_` and using `__` as a nested separator (e.g. `APP_SERVER__PORT=8000`). Sensible defaults are built in, so only non-default values need to be set. See [`.env.template`](.env.template) for a complete example.

For deployment guidance and backend tradeoffs, see [`docs/database-backends.md`](docs/database-backends.md).

### Validation

The following constraints are validated at startup and will cause the server to fail fast if violated:

- `server.port` must be between 1 and 65535 (the `u16` type enforces the upper bound)
- `server.cert.renewal_cron_schedule` must be a valid 6-field cron expression (seconds required)
- `aws.s3_bucket` must not be empty

## Security

### Authentication

The server uses JWT-based authentication with the following requirements:

1. Issuers must provide valid public key during registration using the `/api/v1/credentials` endpoint
2. All authenticated requests must include a JWT token in the Authorization header:

   ```http
   Authorization: Bearer <jwt_token>
   ```

3. The JWT token must:
   - Be signed with the private key corresponding to the registered public key
   - Have `iss` (issuer) claim matching the registered issuer
   - Have valid `exp` (expiration) and `iat` (issued at) claims

Example JWT token header:

```json
{
  "alg": "ES256"
}
```

Example JWT token claims:

```json
{
  "iss": "test-issuer",
  "exp": 1752515200,
  "iat": 1752515200
}
```

### Certificate Provisioning and Renewal

The Status List Server is provisioned with a cryptographic certificate that is embedded into all issued status list tokens. This certificate ensures the authenticity and integrity of the tokens distributed by the server.

- Certificate issuance and renewal are managed according to the configured renewal strategy.
- Every day, a cron job checks whether the certificate should be renewed based on this strategy.
- If the certificate is still considered valid according to the configured strategy, no renewal occurs; renewal is only triggered when necessary.
- Parsed certificate chains are cached in memory for `APP_SERVER__CERT__CHAIN_CACHE_TTL` seconds (default: `3600`). A value of `0` keeps entries indefinitely. In multi-replica deployments, replicas that did not perform renewal rely on this TTL to refresh their in-memory chain.

**Provisioning Modes:**

- `server.cert.provisioning_strategy = "acme"` requests and renews certificates through ACME.
- `server.cert.provisioning_strategy = "store"` loads externally managed certificate material and persists it into the configured certificate/secrets storage.
- Store provisioning supports `server.cert.store.source = "filesystem"` with `certificate_path` and `signing_key_path`.
- Store provisioning also supports `server.cert.store.source = "storage"` for the configured certificate/secrets storage backends, or `"aws_secrets_manager"` when both PEM values are stored in the configured secrets backend, using `certificate_key` and `signing_key_key`.
- Filesystem store inputs may be PEM text or raw DER. Storage-backed store inputs may be PEM text or base64/base64url-encoded DER. Private keys must be PKCS#8 in PEM or DER form.
- The renewal cron schedule is configured with `server.cert.renewal_cron_schedule`. For store provisioning, each scheduled run reloads the configured source and refreshes persisted material only when it changed.

**Certificate Manager Builder Defaults:**

- `CertManager::builder()` defaults to ACME provisioning.
- The default renewal strategy is `PercentageOfLifetime(None)`, which renews at 2/3 of the certificate lifetime.
- ACME uses `DefaultHttpClient` unless `.acme_http_client(...)` is supplied.
- Store provisioning does not create ACME HTTP client state unless explicitly configured.
- `email` defaults to an empty string, `organization` defaults to none, and `eku` defaults to none.
- `domains`, `cert_storage`, and `secrets_storage` must always be provided.
- ACME additionally requires `challenge_handler` and `acme_directory_url`.

```rust
let manager = CertManager::builder()
    .domains(["statuslist.example.com"])
    .email("support@example.com")
    .organization(Some("example.com"))
    .acme_directory_url("https://acme-v02.api.letsencrypt.org/directory")
    .cert_storage(cert_storage)
    .secrets_storage(secrets_storage)
    .challenge_handler(challenge_handler)
    .eku(&[1, 3, 6, 1, 5, 5, 7, 3, 30])
    .acme_strategy()
    .build()?;
```

```rust
let manager = CertManager::builder()
    .domains(["statuslist.example.com"])
    .cert_storage(cert_storage)
    .secrets_storage(secrets_storage)
    .store_strategy(StoreProvisioningStrategy::filesystem(
        "/etc/status-list/tls.crt",
        "/etc/status-list/tls.key",
    ))
    .build()?;
```

**DNS Providers:**

ACME DNS-01 challenges are solved through a configurable DNS provider. AWS Route53, Cloudflare, Google Cloud DNS, Azure DNS and self-hosted ACME-DNS are supported, selected via `APP_SERVER__CERT__DNS__PROVIDER`. See the [DNS Provider Documentation](docs/dns-providers.md) for setup instructions.

## Error Handling

The server implements proper error handling and returns appropriate HTTP status codes:

- `400 BAD REQUEST`: Invalid input data
- `401 UNAUTHORIZED`: Missing or invalid authentication token
- `403 FORBIDDEN`: Insufficient permissions
- `404 NOT FOUND`: Resource not found
- `406 NOT ACCEPTABLE`: Requested format not supported
- `409 CONFLICT`: Resource already exists
- `500 INTERNAL SERVER ERROR`: Server-side error

## Deployment

The server can be deployed using a containerization platform such as Docker.

### Helm Chart Deployment

A Helm chart is provided for easy deployment on Kubernetes. For detailed instructions, see the [Helm Deployment Guide](helm/README.md).

### Rate limiting and network topology

> **The server will not start until you set `APP_RATE_LIMIT__CLIENT_IP_SOURCE`.**
> This setting has no default on purpose — see [Choosing a client IP source](#choosing-a-client-ip-source).

Rate limiting is tiered by how strong the identity behind a request is.

| Tier          | Routes                                                     | Keyed on                                                               | Budget           |
| ------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------- | ---------------- |
| `issuer`      | `PUT`/`PATCH` `/api/v1/status-lists/{id}/statuses`         | The credential issuer, **after** its token signature has been verified | `issuer_*`       |
| `write_gate`  | the same write routes, in front of authentication          | Derived client IP                                                      | `write_gate_*`   |
| `credentials` | `POST /api/v1/credentials`                                 | Derived client IP                                                      | `credentials_*`  |
| `reads`       | `GET /api/v1/aggregation`, `GET /api/v1/status-lists/{id}` | Derived client IP                                                      | `reads_*`        |

Each budget is a pair, `APP_RATE_LIMIT__<TIER>_BURST_SIZE` and
`APP_RATE_LIMIT__<TIER>_PERIOD_SECS`. Every tier has its own, so retuning one
route group never silently retunes another.

> **Read a budget as a token bucket, not a per-window quota.** `burst_size` is
> the bucket's capacity; **one token is replenished every `period_secs`**. So
> `burst_size = 100, period_secs = 60` allows 100 requests immediately and then
> a sustained **one request per minute** — not 100 per minute. Pick
> `period_secs` from the sustained rate you want
> (`period_secs = 60 / requests_per_minute`) and `burst_size` from how much
> bunching you will tolerate.

The `issuer` tier is the only one keyed on something a client cannot choose: the
issuer is read from the request only after the token has been verified against
the issuer's registered public key. Changing the `iss` claim in a token does not
select a different bucket — it fails authentication.

`write_gate` exists because keying on a verified identity means authentication —
and therefore a credential lookup — has to run before the per-issuer limiter. It
is a coarse, generous gate so that anonymous traffic cannot drive those lookups
without limit. Keep `write_gate_burst_size` comfortably above the issuer budget:
every issuer behind a shared source IP passes through it.

Rejections name the tier that fired in `error_description`, so a client can tell
"you are writing too fast" from "this source IP is".

> **Note on the `credentials` tier.** It is keyed on the *derived* client IP, so
> a wrong `client_ip_source` does more than skew throttling accuracy — it makes
> the gate on credential registration client-influenced. On `main` this tier
> used the raw peer address, which was coarse but unforgeable. That is a
> deliberate trade for topology-correctness, and one more reason the setting is
> required rather than guessed.

Global caps on connections, request concurrency and body size are an ingress
concern and are not handled here.

#### Choosing a client IP source

The IP-keyed tiers can only be as correct as the client IP they derive, and the
right way to derive it depends entirely on what sits in front of the server.
There is no safe default: guessing wrong either lets clients forge the key
(unbounded buckets, no effective limit) or collapses every client into one
bucket (a self-inflicted denial of service). So the value is required, and an
unset value stops the server with an explanatory error.

| `APP_RATE_LIMIT__CLIENT_IP_SOURCE` | Use when                                                         | Notes                                                                          |
| ---------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `connect_info`                     | Nothing sits between clients and the server                      | Unforgeable. Behind any proxy this collapses all clients into a single bucket. |
| `rightmost_x_forwarded_for`        | One or more reverse proxies that **append** to `X-Forwarded-For` | Also set `APP_RATE_LIMIT__TRUSTED_HOPS` — see below.                           |
| `x_real_ip`                        | A proxy that unconditionally **overwrites** `X-Real-IP`          | Only safe if the overwrite is guaranteed on every request path.                |

**`trusted_hops` is how many `X-Forwarded-For` entries to skip, counting from
the right — not how many proxies are in the chain.** The innermost proxy writes
the *client's* address into the header, so a single reverse proxy needs `0`.
Each additional proxy in front of that one appends its own entry and adds `1`:

| Chain                       | `X-Forwarded-For` reaching the server | `trusted_hops` |
| --------------------------- | ------------------------------------- | -------------- |
| client → ingress            | `client`                              | `0`            |
| client → CDN → ingress      | `client, cdn`                         | `1`            |
| client → CDN → LB → ingress | `client, cdn, lb`                     | `2`            |

```bash
# Direct exposure
APP_RATE_LIMIT__CLIENT_IP_SOURCE=connect_info

# Behind one reverse proxy that appends to X-Forwarded-For
APP_RATE_LIMIT__CLIENT_IP_SOURCE=rightmost_x_forwarded_for
APP_RATE_LIMIT__TRUSTED_HOPS=0

# Behind a CDN in front of that proxy: one more entry to skip
APP_RATE_LIMIT__TRUSTED_HOPS=1
```

Because entries are counted from the right, anything a client prepends is
ignored. Setting `trusted_hops` higher than the real chain is rejected at
startup above `16`; below that it makes every request fall back to the peer
address, visible as `rate_limit_ip_source_fallback{reason="chain_too_short"}`.
If instead the header is absent altogether — this source selected on a
deployment with no proxy in front of it — the reason is `header_absent`, and
`trusted_hops` is not the setting to change. `trusted_hops` is also rejected
outright unless the source is `rightmost_x_forwarded_for`, rather than being
silently ignored.

If the configured header is missing or unusable, the server falls back to the
peer address. That is coarse but never forgeable, so a misconfiguration degrades
into over-throttling rather than into a bypass.

#### Kubernetes / ingress-nginx

Keep `use-forwarded-headers` at its default of `"false"` in the ingress-nginx
controller ConfigMap. Despite the name, `"false"` is the setting you want: NGINX
then **ignores** any `X-Forwarded-For` the client sent and writes what it
observed itself. Setting it to `"true"` makes NGINX *trust and forward* the
client's header, which is what allows spoofing.

```yaml
# ingress-nginx controller ConfigMap (cluster-wide, not a per-Ingress annotation)
data:
  use-forwarded-headers: "false"   # NGINX overwrites X-Forwarded-For
```

If a CDN or another L7 proxy sits in front of ingress, that proxy becomes the
trust boundary instead. In that case set `use-forwarded-headers: "true"` *and*
`proxy-real-ip-cidr` to the upstream's ranges, and raise
`APP_RATE_LIMIT__TRUSTED_HOPS` by one for the extra hop. The two must change
together: adding a proxy without updating both reintroduces the problem.

This ingress configuration is defence in depth. It is not load-bearing on its
own — it lives in cluster config rather than in the shipped binary, so a
deployment behind a different ingress, a service mesh, or no proxy at all is
covered by `client_ip_source` instead.

#### Bucket bounds

No key in any tier can be chosen freely by a client, which is what stops the
limiter's own state from becoming a denial-of-service vector:

- the `issuer` tier only accepts keys that verified against a **registered**
  credential;
- the IP tiers bucket IPv6 clients by `/64`, so one residential allocation
  cannot mint unlimited distinct keys, and unwrap IPv4-mapped addresses so a
  dual-stack listener keys IPv4 clients the same way an IPv4-only one does.

Two honest caveats. First, `POST /api/v1/credentials` is unauthenticated, so the
set of registered issuers is **not fixed** — an attacker can grow it, bounded by
the `credentials` tier's rate but persistent across restarts. The issuer key
space is therefore bounded by a rate, not by a ceiling. Second, if
`client_ip_source` is wrong for the topology, the IP tiers inherit that error;
that is the whole reason the setting is required rather than defaulted.

On top of that, each tier sweeps buckets that have returned to their starting
state every `APP_RATE_LIMIT__BUCKET_EVICTION_INTERVAL_SECS` seconds (default
`60`), reclaiming map capacity only when a sweep actually freed a meaningful
share of it. `APP_RATE_LIMIT__MAX_BUCKETS` (default `100000`) is the count above
which the server logs at `ERROR` after a sweep. `governor` offers no admission
control, so this is an alerting threshold — a signal that one of the bounds
above is not holding — and not a cap that rejects new keys.

#### Observability

| Metric                             | Type    | Labels           |
| ---------------------------------- | ------- | ---------------- |
| `rate_limit_buckets`               | gauge   | `tier`           |
| `rate_limit_rejected`              | counter | `tier`           |
| `rate_limit_key_extraction_failed` | counter | `tier`           |
| `rate_limit_ip_source_fallback`    | counter | `tier`, `reason` |

`rate_limit_ip_source_fallback` is the signal that `client_ip_source` does not
match the deployment: the configured header could not be used, so the tier fell
back to the peer address and is keying more coarsely than intended. Nothing else
is observable — the request still succeeds and the response is unchanged — so a
steady rate here means the setting is wrong while everything looks healthy.

`reason` says which remedy applies. Note that they are not interchangeable —
`header_absent` and `chain_too_short` point at different settings:

- **`header_absent`** — the configured header was not on the request at all.
  Either no proxy is in front of this server, or the one that is does not set
  the header. The fix is `client_ip_source`; **`trusted_hops` cannot help**,
  because there is no chain to count into. Emitted by both header sources.
- **`chain_too_short`** — the header was present, but had fewer entries than
  `trusted_hops` requires. This is the one case where lowering `trusted_hops` to
  match the real chain is the fix. Only `rightmost_x_forwarded_for` emits it.
- **`unparseable`** — the selected entry was not an address, e.g. an RFC 7239
  obfuscated identifier. Check what the proxy actually writes. Emitted by both
  header sources.

`connect_info` never emits this metric: the connection address is always
available, so there is nothing to fall back from.

A non-zero `rate_limit_key_extraction_failed` means the limiter could not
identify the caller — it is always a deployment or wiring fault, never client
input. Rejections are returned as `429` with `retry-after` and `x-ratelimit-*`
headers.

## Testing

You can run the tests using the following command:

```bash
cargo test
```

To verify the infrastructure-free application composition (domain models, domain ports,
service container, and in-memory outbound adapters only), run:

```bash
cargo check --no-default-features --features memory
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
