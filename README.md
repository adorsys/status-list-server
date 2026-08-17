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
- A supported database backend: PostgreSQL, MySQL, or SQLite for persistent deployments. The default local mode uses in-memory repositories.
- [Redis](https://redis.io/download) is optional and only needed when you enable the distributed certificate-material cache.
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

This command will pull all required images and start the server compiled with default compose features (`postgres,aws-secrets,acme`). Redis is not part of the default path.

To pass custom Cargo feature flags during build, specify the `FEATURES` environment variable:

```sh
FEATURES="mysql,aws-secrets,acme" docker compose --profile mysql up --build
```

To test the optional Redis certificate-material cache locally, enable the Redis profile, compile the Redis feature, and provide a Redis URI:

```sh
FEATURES="postgres,redis,aws-secrets,acme" APP_REDIS__URI="redis://redis:6379" docker compose --profile redis up --build
```

#### Running Manually

To start the server in zero-infrastructure default in-memory mode, execute:

```bash
cargo run
```

By default, the server will listen on `http://localhost:8000` using in-memory repositories, Moka cache, and store-based certificate management. No external databases, Redis, or cloud services are required for development.

## Cargo Feature Matrix

The crate uses modular Cargo feature flags to gate optional production backend drivers:

| Feature       | Description                                                                                                                                        | Default    |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `memory`      | In-memory repositories (`MemoryStatusLists`, `MemoryCredentials`, `MemoryStatusListHistory`), Moka TTL cache, and store-based certificate storage. | ✅ Default |
| `postgres`    | SeaORM PostgreSQL database driver.                                                                                                                 | ❌ Opt-in  |
| `sqlite`      | SeaORM SQLite database driver.                                                                                                                     | ❌ Opt-in  |
| `mysql`       | SeaORM MySQL database driver.                                                                                                                      | ❌ Opt-in  |
| `redis`       | Redis storage driver for explicit cache/storage integrations.                                                                                      | ❌ Opt-in  |
| `aws-secrets` | AWS S3 object storage, Route53 DNS-01, and AWS Secrets Manager drivers.                                                                            | ❌ Opt-in  |
| `acme`        | ACME DNS-01 certificate manager driver.                                                                                                            | ❌ Opt-in  |

To build with specific backend drivers, pass the matching feature flag(s):

```bash
# Run with PostgreSQL and Redis support available
cargo run --features postgres,redis

# Run with AWS and ACME production integrations
cargo run --features postgres,aws-secrets,acme
```

## Redis Role

Redis is optional. The server does not use Redis for status-list persistence or status-list reads; those use the configured repository backend and the in-process status-list cache. Certificate and signing-key material are managed together by the selected cryptographic material backend; prefer the built-in material read-cache TTLs before adding Redis.

For single-replica deployments, local development, tests, or deployments where certificate material reads are inexpensive, leave `APP_REDIS__URI` unset and omit the `redis` Cargo feature.

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
- The server signing key and certificate chain are stored in one cryptographic-material backend selected by enabled Cargo features (`vault`, `aws-secrets`, or in-memory fallback).
- Certificate and signing-key reads can be cached with `APP_SERVER__CERT__MATERIAL_CACHE_TTL` and `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL`. Set the signing-key TTL to `0` to force private-key reads to bypass the material cache.
- Parsed certificate chains stay cached in memory until certificate provisioning or renewal replaces them.

**Provisioning Modes:**

- `server.cert.provisioning_strategy = "acme"` requests and renews certificates through ACME.
- `server.cert.provisioning_strategy = "store"` loads externally managed certificate material and persists it into the configured cryptographic-material backend.
- Store provisioning infers filesystem loading when `server.cert.store.certificate_path` and `signing_key_path` are configured.
- Store provisioning infers storage-backed loading when `server.cert.store.certificate_key` and `signing_key_key` are configured; those keys are read from the feature-selected cryptographic-material backend.
- Filesystem store inputs may be PEM text or raw DER. Storage-backed store inputs may be PEM text or base64/base64url-encoded DER. Private keys must be PKCS#8 in PEM or DER form.
- The renewal cron schedule is configured with `server.cert.renewal_cron_schedule`. For store provisioning, each scheduled run reloads the configured source and refreshes persisted material only when it changed.

**Certificate Manager Builder Defaults:**

- `CertManager::builder()` defaults to ACME provisioning.
- The default renewal strategy is `PercentageOfLifetime(None)`, which renews at 2/3 of the certificate lifetime.
- ACME uses `DefaultHttpClient` unless `.acme_http_client(...)` is supplied.
- Store provisioning does not create ACME HTTP client state unless explicitly configured.
- `email` defaults to an empty string, `organization` defaults to none, and `eku` defaults to none.
- `domains` and `crypto_storage` must always be provided.
- ACME additionally requires `challenge_handler` and `acme_directory_url`.

```rust
let manager = CertManager::builder()
    .domains(["statuslist.example.com"])
    .email("support@example.com")
    .organization(Some("example.com"))
    .acme_directory_url("https://acme-v02.api.letsencrypt.org/directory")
    .crypto_storage(material_storage)
    .challenge_handler(challenge_handler)
    .eku(&[1, 3, 6, 1, 5, 5, 7, 3, 30])
    .acme_strategy()
    .build()?;
```

```rust
let manager = CertManager::builder()
    .domains(["statuslist.example.com"])
    .crypto_storage(material_storage)
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

## Contributing

Contributions are welcome and encouraged. Before contributing, please review the [architecture documentation](./docs/architecture.md), which provides an overview of our architectural design. Also refer to the [contributing guide](./CONTRIBUTING.md) for more details.

## Releases

This project uses [release-plz](https://release-plz.dev/) with [Conventional Commits](https://www.conventionalcommits.org/) to automate versioning and changelog generation. Every push to `main` opens or updates a Release PR. Merging that PR creates a git tag and a GitHub Release automatically.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
