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

For a detailed explanation of the architecture and component design, see the [architecture documentation](docs/architecture.md).

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

### Deployment & Runtime Prerequisites

Prerequisites depend on how you run the server:

- **Local Development (Zero-Infrastructure Default):**
  - [Rust & Cargo](https://www.rust-lang.org/tools/install) (Latest stable).
  - No external services required! By default, the server runs completely in-memory using Moka for caching and store-based certificate mode. External databases and cloud service accounts are **not** needed.
- **Docker Compose Setup:**
  - [Docker](https://www.docker.com/get-started/) & Docker Compose plugin.
- **Production Deployment (Optional Integrations):**
  - Persistent database: PostgreSQL or MySQL (or single-node SQLite).
  - Secret Management Backend: HashiCorp Vault / OpenBao, AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault.
  - ACME DNS-01 Provider: AWS Route53, Cloudflare, Google Cloud DNS, Azure DNS, or ACME-DNS.
  - Telemetry: OpenTelemetry Collector (OTLP gRPC).

### Default Runtime Mode

By default, executing `cargo run` boots the server in a lightweight, infrastructure-free local mode:

- **Storage**: In-memory repositories (`memory` Cargo feature & `APP_DATABASE__BACKEND=memory`).
- **Caching**: In-process TTL caching via Moka (`APP_CACHE__*`).
- **Certificates**: Store-based certificate strategy (`APP_SERVER__CERT__PROVISIONING_STRATEGY=store`).

### Run Locally

**1. Clone the Repository:**

```bash
git clone https://github.com/adorsys/status-list-server.git
cd status-list-server
```

**2. Environment Variables (Optional):**

Create a `.env` file in the root directory. Refer to [.env.template](.env.template) for an example of all configurable variables.

**3. Running Manually (Lightweight / In-Memory Mode):**

To start the server in zero-infrastructure default mode:

```bash
cargo run
```

By default, the server listens on `http://localhost:8000`.

**4. Running with Docker Compose:**

To launch the full containerized environment (PostgreSQL, LocalStack for AWS Secrets Manager, Pebble ACME server, OpenTelemetry collector, Jaeger, and Prometheus):

```bash
docker compose up --build
```

To run with custom feature flags in Docker Compose (e.g. MySQL backend):

```bash
FEATURES="mysql,aws-secrets,acme" docker compose --profile mysql up --build
```

## Cargo Feature Matrix

The crate uses modular Cargo feature flags to compile optional production backend drivers and secret managers:

| Feature       | Description                                                                    | Default    |
| ------------- | ------------------------------------------------------------------------------ | ---------- |
| `memory`      | In-memory repositories, TTL cache (Moka), and store-based certificate storage. | ✅ Default |
| `postgres`    | SeaORM PostgreSQL database driver.                                             | ❌ Opt-in  |
| `sqlite`      | SeaORM SQLite database driver.                                                 | ❌ Opt-in  |
| `mysql`       | SeaORM MySQL database driver.                                                  | ❌ Opt-in  |
| `acme`        | ACME DNS-01 certificate manager driver (`instant-acme`, `rcgen`).              | ❌ Opt-in  |
| `aws-secrets` | Route53 DNS-01 challenge driver and AWS Secrets Manager integration.           | ❌ Opt-in  |
| `vault`       | HashiCorp Vault / OpenBao secrets backend integration.                         | ❌ Opt-in  |
| `gcp-secrets` | GCP Secret Manager secrets driver and Google Cloud DNS integration.            | ❌ Opt-in  |
| `azure-kv`    | Azure Key Vault secrets driver and Azure DNS integration.                      | ❌ Opt-in  |

To build or run with specific backend drivers, pass the matching feature flag(s):

```bash
# Run with PostgreSQL database support
cargo run --features postgres

# Run with SQLite database support
cargo run --features sqlite

# Run with AWS and ACME production integrations
cargo run --features postgres,aws-secrets,acme

# Run with HashiCorp Vault integration
cargo run --features postgres,vault
```

For detailed tradeoffs and operational recommendations, see [`docs/database-backends.md`](docs/database-backends.md) and [`docs/secrets-backends.md`](docs/secrets-backends.md).

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

All runtime settings can be configured via environment variables prefixed with `APP_` using `__` as a nested delimiter (e.g. `APP_SERVER__PORT=8000`). Sensible defaults are built-in for all options.

### Key Configuration Settings

| Prefix / Category | Key Setting                                 | Default                            | Description                                                          |
| ----------------- | ------------------------------------------- | ---------------------------------- | -------------------------------------------------------------------- |
| **Server**        | `APP_SERVER__HOST`                          | `localhost`                        | Server bind host address                                             |
|                   | `APP_SERVER__PORT`                          | `8000`                             | Server HTTP port                                                     |
|                   | `APP_SERVER__DOMAIN`                        | `localhost`                        | Primary server domain                                                |
|                   | `APP_SERVER__ENABLE_METRICS`                | `false`                            | Expose `/metrics` Prometheus endpoint                                |
|                   | `APP_SERVER__AGGREGATION_URI`               | `None`                             | Optional public aggregation URI emitted in tokens                    |
| **Database**      | `APP_DATABASE__BACKEND`                     | `memory`                           | Backend type (`memory`, `postgres`, `mysql`, `sqlite`)               |
|                   | `APP_DATABASE__URL`                         | `memory:`                          | Connection string or URI                                             |
|                   | `APP_DATABASE__POOL__MAX_CONNECTIONS`       | `5`                                | Connection pool size limit                                           |
| **Certificates**  | `APP_SERVER__CERT__PROVISIONING_STRATEGY`   | `store` (`acme` if feature active) | Provisioning mode (`store` or `acme`)                                |
|                   | `APP_SERVER__CERT__EMAIL`                   | `admin@example.com`                | Contact email for ACME certificate registration                      |
|                   | `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL`   | `0`                                | Private key cache TTL from backend (seconds; `0` disables)           |
|                   | `APP_SERVER__CERT__STORE__SIGNING_KEY_PATH` | `None`                             | Path to PKCS#8 private key file (filesystem store)                   |
|                   | `APP_SERVER__CERT__DNS__PROVIDER`           | Auto-resolved                      | DNS provider (route53/cloudflare/gcloud/azure/acmedns/pebble)        |
| **Cache**         | `APP_CACHE__TTL`                            | `300`                              | Status list item cache TTL (seconds; `0` disables)                   |
|                   | `APP_CACHE__MAX_CAPACITY`                   | `100`                              | Maximum cached status list entries                                   |
| **Status List**   | `APP_STATUS_LIST__TOKEN_EXP_SECS`           | `900`                              | Token expiration duration (seconds)                                  |
|                   | `APP_STATUS_LIST__TOKEN_TTL_SECS`           | `300`                              | Token time-to-live duration (seconds)                                |
|                   | `APP_STATUS_LIST__SNAPSHOT_RETENTION_SECS`  | `7776000`                          | Snapshot retention period (seconds; 90 days)                         |
| **Telemetry**     | `APP_TELEMETRY__ENVIRONMENT`                | `development`                      | Mode (`development` for stdout, `production` for OTLP)               |
|                   | `APP_TELEMETRY__OTLP_ENDPOINT`              | `http://localhost:4317`            | OTLP collector gRPC endpoint                                         |
|                   | `APP_TELEMETRY__ENABLED`                    | `true`                             | Enable OpenTelemetry tracing pipeline                                |
|                   | `APP_TELEMETRY__SAMPLER_RATIO`              | `1.0`                              | Sampling ratio (`0.0` to `1.0`)                                      |
| **Rate Limit**    | `APP_RATE_LIMIT__STRICT_BURST_SIZE`         | `10`                               | Burst size for write endpoints (strict tier)                         |
|                   | `APP_RATE_LIMIT__STRICT_PERIOD_SECS`        | `60`                               | Time window for strict tier (seconds)                                |
|                   | `APP_RATE_LIMIT__PERMISSIVE_BURST_SIZE`     | `100`                              | Burst size for read endpoints (permissive tier)                      |
|                   | `APP_RATE_LIMIT__PERMISSIVE_PERIOD_SECS`    | `60`                               | Time window for permissive tier (seconds)                            |
| **Limits**        | `APP_LIMITS__MAX_BODY_SIZE_BYTES`           | `2097152`                          | Maximum request body size (2 MiB)                                    |
|                   | `APP_LIMITS__MAX_STATUS_INDEX`              | `100000`                           | Maximum status list index value                                      |
|                   | `APP_LIMITS__MAX_STATUSES_PER_REQUEST`      | `5000`                             | Maximum statuses per update request                                  |
|                   | `APP_LIMITS__MAX_SERIALIZED_LIST_SIZE`      | `1048576`                          | Maximum serialized list size (1 MiB)                                 |

A complete sample configuration is available in [.env.template](.env.template).

### Validation Constraints

The application validates settings at startup and fails fast if invalid:

- `APP_SERVER__PORT` must be between `1` and `65535`.
- `APP_SERVER__CERT__RENEWAL_CRON_SCHEDULE` must be a valid 6-field cron expression (with seconds).
| [`openapi.yaml`](openapi.yaml)                             | Complete OpenAPI 3.1 REST API specification                                                      |
- `APP_TELEMETRY__SAMPLER_RATIO` must be a finite number between `0.0` and `1.0`.

## Documentation Index

Detailed documentation for architecture, storage backends, secret management, DNS providers, and deployment operations is available in the [`docs/`](docs/) directory and [`helm/`](helm/) folder:

| Document                                                   | Topic & Scope                                                                                    |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [`docs/architecture.md`](docs/architecture.md)             | High-level system architecture, component overview, and token workflows                          |
| [`docs/database-backends.md`](docs/database-backends.md)   | Database backends (PostgreSQL, MySQL, SQLite), pool tuning, and transaction isolation            |
| [`docs/secrets-backends.md`](docs/secrets-backends.md)     | Secret backends (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)      |
| [`docs/dns-providers.md`](docs/dns-providers.md)           | ACME DNS-01 provider configurations (Route53, Cloudflare, Google Cloud DNS, Azure DNS, ACME-DNS) |
| [`docs/observability.md`](docs/observability.md)           | OpenTelemetry integration, tracing, OTLP collector setup, Prometheus metrics, and Jaeger         |
| [`docs/deployment-runbook.md`](docs/deployment-runbook.md) | Operations, database migrations, backup/restore procedures, and zero-downtime upgrades           |
| [`docs/LOCAL_DEPLOYMENT.md`](docs/LOCAL_DEPLOYMENT.md)     | Local testing setups and Docker Compose instructions                                             |
| [`docs/compliance_matrix.md`](docs/compliance_matrix.md)   | Spec compliance matrix for OAuth Token Status List draft-21                                      |
| [`docs/openapi.yaml`](docs/openapi.yaml)                   | Complete OpenAPI 3.1 REST API specification                                                      |
| [`helm/README.md`](helm/README.md)                         | Kubernetes deployment using the official Helm chart                                              |

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
- Certificate material stays cached until provisioning or renewal invalidates it. Signing-key reads can be cached with `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL`; set it to `0` to force private-key reads to bypass the material cache.
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

For production deployments:

Run complete local CI checks using the [`local-ci.sh`](local-ci.sh) script (format, clippy, tests, and dependency checks):

```bash
# Requires cargo-nextest: cargo install cargo-nextest
./local-ci.sh
- **Operations & Runbooks**: Refer to the [Deployment Runbook](docs/deployment-runbook.md) for database migration, backup, and operational guidelines.

### Container Supply Chain

Release images are scanned by digest and carry an SBOM and SLSA provenance, and release tags are applied only after the scan. See the [Container Supply Chain guide](docs/supply-chain.md) for thresholds, verification commands, and how to triage findings.

## Testing & Local Quality Checks

Run unit and integration tests:

```bash
cargo test
```

Verify zero-infrastructure / in-memory composition:

```bash
cargo check --no-default-features --features memory
```

Run complete local CI checks (format, clippy, tests, and dependency checks):

```bash
# Requires cargo-nextest: cargo install cargo-nextest
./local-ci.sh
```

Run markdown linting:

```bash
npx --yes markdownlint-cli2 README.md
```

## Contributing

Contributions are welcome and encouraged. Before contributing, please review the [architecture documentation](./docs/architecture.md), which provides an overview of our architectural design. Also refer to the [contributing guide](./CONTRIBUTING.md) for more details.

## Releases

This project uses [release-plz](https://release-plz.dev/) with [Conventional Commits](https://www.conventionalcommits.org/) to automate versioning and changelog generation. Every push to `main` opens or updates a Release PR. Merging that PR creates a git tag and a GitHub Release automatically. The first Release PR creates the initial changelog entry.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
