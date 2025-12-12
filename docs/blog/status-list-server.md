# Building a Production‑Ready Status List Server in Rust

Modern ecosystems need a scalable way to check the status of tokens (valid, revoked, suspended) without hitting issuers for every validation. This is exactly what a Status List Server provides: compact, cacheable “status list tokens” that relying parties can fetch and use to verify token status at massive scale.

This post walks you through a Rust implementation that follows the IETF OAuth Status List draft. We’ll cover the stack, API, data model, security, certificate automation, and deployment.

## What is a Status List Server?

- A token issuer encodes status for many referenced tokens into a compact list.
- Relying parties fetch the status list token and look up the status by index.
- The server:
  - Hosts the status lists.
  - Lets issuers publish and update them.
  - Serves them to verifiers as JWT or CWT, gzip-compressed.

Spec: https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/

## Tech Stack Overview

- Web
  - axum (async router, middleware)
  - tower-http (CORS, tracing, panic catch)
- Runtime
  - tokio, hyper, rustls
- Data
  - PostgreSQL via sea-orm (+ migrations)
  - Redis (moka cache in-app; Redis for cert/secret cache layer)
- Formats & crypto
  - JWT: jsonwebtoken
  - CWT/COSE: coset
  - ECDSA (p256), AWS-LC-backed crypto
- Cert automation
  - instant-acme (ACME: Let’s Encrypt or Pebble in dev)
  - AWS Secrets Manager + S3 backends for secure storage
  - Route53 for DNS-01 challenges (prod)
- Observability
  - tracing + tracing-subscriber
- Build & deploy
  - Multi-arch static builds (musl), distroless runtime
  - Docker Compose for local; Helm for k8s

## Key Features

- Status List Token serving as JWT or CWT on the same endpoint, chosen via Accept:
  - application/statuslist+jwt
  - application/statuslist+cwt
- Compact representation:
  - Bit-packed array with dynamic bit width (1, 2, 4, or 8) based on required statuses
  - zlib-compressed and base64url-encoded
  - Responses are gzip-compressed at HTTP layer
- Publisher workflow
  - Register issuer public key (JWK)
  - Authenticated publish/update using JWT Bearer signed by the issuer’s private key
- Robust infra
  - Auto certificate provisioning/renewal via ACME
  - AWS S3 + Secrets Manager for durable cert/key storage
  - Daily renewal scheduler
- Performance
  - Moka in-memory TTL cache for status list records
  - Indices on database columns used for lookups

## API Overview

Base URL by default: http://localhost:8000

- GET /
  - Returns “Status list Server”
- GET /health
  - Quick liveness probe, returns 200 OK, body “OK”
- POST /credentials
  - Register an issuer’s public key
  - Request

```json
      {
        "issuer": "issuer-123",
        "public_key": {
          "kty": "EC",
          "crv": "P-256",
          "x": "...",
          "y": "..."
        }
      }
```

- POST /statuslists/publish (auth required)
  - Creates a new status list record for the authenticated issuer
  - Request

```json
      {
        "list_id": "30202cc6-1e3f-4479-a567-74e86ad73693",
        "status": [
          { "index": 1, "status": "INVALID" },
          { "index": 8, "status": "VALID" }
        ]
      }
```

- PATCH /statuslists/update (auth required)
  - Updates an existing status list for the authenticated issuer
- GET /statuslists/{list_id} (public)
  - Returns a gzip-compressed token (JWT or CWT) based on Accept
  - Headers
    - Accept: application/statuslist+jwt | application/statuslist+cwt
    - Content-Encoding: gzip
  - Claims include:
    - sub: URL of this status list
    - status_list: { bits, lst }
    - iat, exp (default 15 minutes), ttl (default 5 minutes)
    - JWT includes x5c; CWT includes x5chain

Authentication for publish/update:
- Authorization: Bearer <JWT>
- The server extracts alg and iss, fetches registered JWK for iss, and verifies signature and claims.

## Data Model

- credentials
  - issuer (PK)
  - public_key (JWK as JSON)
- status_lists
  - list_id (PK, UUID recommended)
  - issuer (FK → credentials.issuer, cascade on delete/update)
  - status_list (JSON: bits u8, lst base64url string)
  - sub (URL of this list)
- Indices
  - list_id (PK), issuer, sub

Status encoding
- `bits`: 1, 2, 4, or 8
- `lst`: base64url(zlib(bytes))
- Values:
  - 0 VALID
  - 1 INVALID
  - 2 SUSPENDED
  - 3 APPLICATIONSPECIFIC
- Bit width expands automatically as needed (e.g., introducing SUSPENDED bumps from 1→2 bits)

## Running Locally

- Docker Compose (recommended)
  - Postgres, Redis, LocalStack (S3/Secrets Manager), Pebble (ACME), app
  - Start:
```bash
docker compose up --build
```
  - App listens on 8000 by default

- Manual (ensure Postgres + Redis running)
  - .env based on .env.template (see repo)
  - Run:
```bash
cargo run
```

## Configuration

Defaults are sensible for local dev; override via env. The config library maps APP_ prefixed env vars with __ as nesting separator. Examples:

- Server
  - APP_SERVER__HOST=0.0.0.0
  - APP_SERVER__PORT=8000
  - APP_SERVER__DOMAIN=localhost
- Database
  - APP_DATABASE__URL=postgres://postgres:postgres@localhost:5432/status-list
- Redis
  - APP_REDIS__URI=redis://localhost:6379
  - APP_REDIS__REQUIRE_CLIENT_AUTH=false
- Certificates (ACME)
  - APP_SERVER__CERT__EMAIL=admin@example.com
  - APP_SERVER__CERT__ORGANIZATION=YourOrg
  - APP_SERVER__CERT__EKU=1,3,6,1,5,5,7,3,30
  - APP_SERVER__CERT__ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
- AWS
  - APP_AWS__REGION=us-east-1
- Cache
  - APP_CACHE__TTL=300
  - APP_CACHE__MAX_CAPACITY=100
- Environment switch
  - APP_ENV=production | development
    - production: DNS-01 via Route53
    - development: Pebble DNS

## Security & Auth

- Issuers must register (`POST /credentials`) before publishing/updating
- Auth middleware:
  - Extracts `iss` and `alg` from token header/payload
  - Loads JWK for `iss` from DB, verifies signature and issuer claim
- JWT/CWT tokens served include certificate chain (x5c/x5chain) for verification
- Strong error mapping:
  - 400 invalid input
  - 401/403 auth failures
  - 404 not found
  - 406 not acceptable (invalid Accept)
  - 409 conflict (duplicate)
  - 500 internal error

## Certificate Automation

- ACME flow with instant-acme
  - Daily renewal check via tokio_cron_scheduler
  - Renewal strategies supported (days before expiry, percentage of lifetime, fixed interval)
- DNS-01 via AWS Route53 (prod) or Pebble challtestsrv (dev)
- Storage
  - Secrets (server signing key, ACME account): AWS Secrets Manager (+ client-side caching)
  - Cert chain: AWS S3 (optional Redis cache layer)
- The JWT/CWT responses include the server’s certificate chain so verifiers can build trust

## Performance Notes

- Moka cache (TTL + capacity) for status list records → fewer DB hits
- SeaORM indices on issuer, sub, list_id
- Static musl build + distroless runtime image
- Gzip responses for both JWT and CWT payloads

## Deployment

- Docker image: multi-arch (amd64/arm64)
- Kubernetes: Helm chart provided (Postgres + Redis HA dependencies)
  - Local instructions in `docs/LOCAL_DEPLOYMENT.md`
  - Redis TLS and HAProxy guidance in `docs/REDIS_TLS_SETUP.md`

## Example Workflows

- Register an issuer

```bash
  curl -X POST http://localhost:8000/credentials \
    -H "Content-Type: application/json" \
    -d '{"issuer":"issuer-123","public_key":{"kty":"EC","crv":"P-256","x":"...","y":"..."}}'
```

- Publish a status list

```bash
  curl -X POST http://localhost:8000/statuslists/publish \
    -H "Authorization: Bearer <issuer-signed-jwt>" \
    -H "Content-Type: application/json" \
    -d '{"list_id":"<uuid>", "status":[{"index":1,"status":"INVALID"}]}'
```

- Retrieve as JWT

```bash
  curl -s http://localhost:8000/statuslists/<uuid> \
    -H "Accept: application/statuslist+jwt" \
    --output token.gz
  gzip -d token.gz && cat token
```

## Closing Thoughts

This Rust server demonstrates a production-grade implementation of the OAuth Status List draft, focusing on correctness, performance, and operational excellence: compact tokens, clean APIs, robust auth, aggressive automation for certs, and a deployment story that scales.
