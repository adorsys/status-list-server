# Status List Server

[![CI](https://github.com/adorsys/status-list-server/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/adorsys/status-list-server/actions/workflows/CI.yml?query=branch%3Amain)
[![CD](https://github.com/adorsys/status-list-server/actions/workflows/deploy.yml/badge.svg?branch=main)](https://github.com/adorsys/status-list-server/actions/workflows/deploy.yml?query=branch%3Amain)
[![Release](https://img.shields.io/github/v/tag/adorsys/status-list-server?label=release&sort=semver)](https://github.com/adorsys/status-list-server/releases)
[![Specification](https://img.shields.io/badge/IETF-OAuth_Status_List_Draft--21-orange.svg)](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
[![dependencies](https://deps.rs/repo/github/adorsys/status-list-server/status.svg)](https://deps.rs/repo/github/adorsys/status-list-server)
[![License: MIT / Apache 2.0](https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-blue.svg)](#license)

The Status List Server is an HTTP service that publishes and manages status lists for verifiable credential issuers and relying parties. It implements the [IETF OAuth Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) specification.

## Key Highlights

- **Standard Compliance**: Implements OAuth Token Status List with JWT and CWT formats, gzip compression on JWT responses, and optional historical status resolution (`?time=`). See the [Compliance Matrix](docs/compliance_matrix.md) for detailed spec alignment.
- **Zero-Infrastructure Local Mode**: Runs in-memory out of the box with zero external dependencies, allowing local development and testing in seconds.
- **Pluggable Persistence**: Supports SQL databases (PostgreSQL, MySQL, SQLite) as well as an in-memory repository for development. See [Database Backends](docs/database-backends.md).
- **Pluggable Status-List Cache**: Select an in-memory or Redis cache backend at runtime for local or multi-replica deployments.
- **Cloud Secret Management**: Fetches server signing keys from AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault or loads them statically from local files. See [Secret Backends](docs/secrets-backends.md).
- **Automated Token Signing Certificates**: Provisions and automatically renews X.509 token signing certificates via ACME DNS-01 challenges (Route53, Cloudflare, Google Cloud DNS, Azure DNS, ACME-DNS, Pebble), or loads certificates statically from local files. See [DNS Providers](docs/dns-providers.md).
- **Cloud-Native Observability**: OpenTelemetry distributed tracing (OTLP gRPC), Prometheus metrics, structured JSON logging, and Kubernetes health probes. See [Observability](docs/observability.md).
- **Hardened Security**: JWT-based issuer authentication, tiered token-bucket rate limiting, request body size enforcement, and container image supply chain verification (SBOM and SLSA provenance).

## Quick Start

### Option 1: Native Cargo Run (Fastest)

Run the server locally with default in-memory storage and certificate loading:

```bash
git clone https://github.com/adorsys/status-list-server.git
cd status-list-server
cargo run
```

The server binds to `http://localhost:8000` with no database or cloud configuration required.

Verify that the service is running:

```bash
curl -i http://localhost:8000/health/live
```

### Option 2: Docker Compose

Start the server with in-memory storage and the checked-in local test
certificate. Profiles start optional services beside the server; using one from
the application also requires its matching build feature and configuration:

```bash
docker compose up --build                       # Server only
docker compose --profile postgres up -d         # Server + PostgreSQL
docker compose --profile mysql up -d            # Server + MySQL
docker compose --profile redis up -d            # Server + Redis
APP_TELEMETRY__ENABLED=true \
  docker compose --profile observability up -d  # Server + telemetry stack
```

Set `GRAFANA_ADMIN_PASSWORD` before starting the observability profile. To use PostgreSQL, ACME, AWS, and telemetry in the server, select those profiles and their matching application settings. The compiled database feature selects the default database backend:

```bash
FEATURES=postgres,aws APP_TELEMETRY__ENABLED=true \
  docker compose --profile postgres --profile acme --profile aws \
    --profile observability up -d --build
```

The `aws` feature includes ACME certificate provisioning, so local AWS builds need both the `aws` and `acme` profiles.

See the [Local Deployment Guide](docs/LOCAL_DEPLOYMENT.md) for all profiles, including MySQL and filesystem certificates.

## API Overview

The server exposes endpoints for issuer credential registration, status list publishing and updates, public status list resolution, and list aggregation.

### Retrieving a Status List Token

Relying parties retrieve status list tokens using the following endpoint:

```http
GET /api/v1/status-lists/{list_id}
```

#### Example Request

```bash
curl -i http://localhost:8000/api/v1/status-lists/477121aa-b598-419e-916f-1e74654ff38b \
  -H "Accept: application/statuslist+jwt" \
  -H "Accept-Encoding: gzip"
```

#### Key Headers and Parameters

- `Accept`: Requested token representation:
  - `application/statuslist+jwt` (default): Signed JWT containing the base64url-encoded status list bitstring.
  - `application/statuslist+cwt`: COSE_Sign1 signed binary CWT token.
- `Accept-Encoding: gzip`: Compresses JWT responses using gzip. CWT tokens are binary and not gzip-compressed.
- `?time=<unix-timestamp>`: Optional query parameter for historical status resolution.

The complete OpenAPI 3.1 REST API specification is available at [OpenAPI Specification](docs/openapi.yaml).

## Cargo Feature Matrix

The server compiles with modular feature flags to gate database drivers and cloud secret providers:

| Feature    | Description                                                           | Default    |
| ---------- | --------------------------------------------------------------------- | ---------- |
| `memory`   | In-memory repository storage, in-process cache, and file certificates | ✅ Default |
| `postgres` | PostgreSQL database driver and migration runner                       | ❌ Opt-in  |
| `sqlite`   | SQLite database driver and migration runner                           | ❌ Opt-in  |
| `mysql`    | MySQL database driver and migration runner                            | ❌ Opt-in  |
| `aws`      | AWS Secrets Manager and Route53 DNS provider                          | ❌ Opt-in  |
| `gcp`      | GCP Secret Manager and Google Cloud DNS provider                      | ❌ Opt-in  |
| `azure`    | Azure Key Vault and Azure DNS provider                                | ❌ Opt-in  |
| `vault`    | HashiCorp Vault / OpenBao secret backend                              | ❌ Opt-in  |
| `redis`    | Redis status-list cache backend                                       | ❌ Opt-in  |

Examples:

```bash
# Build with PostgreSQL support and filesystem key + certificate chain loading 
cargo run --features postgres

# Build with PostgreSQL and AWS integration
cargo run --features postgres,aws
```

## Configuration

The server reads configuration from environment variables (or an optional `.env` file in the working directory):

- **Prefix**: All application settings are prefixed with `APP_`.
- **Hierarchy**: Nested settings use a double underscore (`__`) as a delimiter. For example, `APP_SERVER__PORT=8000` sets the server port, and `APP_DATABASE__BACKEND=postgres` selects the database driver.
- **Defaults**: Every setting includes a default value. The server starts in zero-infrastructure in-memory mode without any custom variables.

Refer to [`.env.template`](.env.template) for the complete configuration dictionary, data types, and default values. For backend-specific configuration, see [Database Backends](docs/database-backends.md), [Secret Backends](docs/secrets-backends.md), and [DNS Providers](docs/dns-providers.md).

## Deployment

For production deployments:

- **Kubernetes**: Refer to the [Helm Chart Guide](deploy/helm/README.md) for deploying with the official Helm chart, configuring Workload Identity (if you use AWS, GCP or Azure), and setting resource limits.
- **Operations and Runbooks**: Refer to the [Deployment Runbook](docs/deployment-runbook.md) for production checklists, database migrations, backup and restore procedures, and zero-downtime maintenance.
- **Troubleshooting**: Refer to the [Troubleshooting Guide](docs/troubleshooting.md) for fail-fast error descriptions and common operator error codes.
- **Container Supply Chain**: Official container images are published with SBOMs and SLSA provenance, and scanned for vulnerabilities by digest. See the [Supply Chain Guide](docs/supply-chain.md).

## Documentation

### Architecture and Specification

- [Architecture Guide](docs/architecture.md): Project organization and modularity, service container composition, and token signing workflows.
- [Compliance Matrix](docs/compliance_matrix.md): Implementation status against OAuth Token Status List draft-21 requirements.
- [OpenAPI Specification](docs/openapi.yaml): Complete REST API contract, request schemas, and error codes.

### Infrastructure and Backends

- [Database Backends](docs/database-backends.md): PostgreSQL, MySQL, and SQLite connection pooling, drivers, and isolation levels.
- [Secret Backends](docs/secrets-backends.md): Storing and rotating token-signing keys with Vault, AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault.
- [DNS Providers](docs/dns-providers.md): Configuring ACME DNS-01 challenge solvers for automated certificate issuance.

### Operations and Security

- [Helm Chart Guide](deploy/helm/README.md): Kubernetes packaging, pod autoscaling, ingress, and Workload Identity configuration.
- [Deployment Runbook](docs/deployment-runbook.md): Production operational procedures, migrations, and disaster recovery.
- [Troubleshooting Guide](docs/troubleshooting.md): Diagnosing runtime failures and common operator errors.
- [Observability Guide](docs/observability.md): OpenTelemetry collector setup, Prometheus metrics, and distributed tracing.
- [Container Supply Chain](docs/supply-chain.md): Image provenance, SBOM verification, and vulnerability triage.

## Development and Quality Checks

The repository provides a standard Cargo xtask entry point for common workflows:

```bash
cargo xtask check-profiles
cargo xtask build                         # defaults to postgres
cargo xtask build --profile sqlite --release
cargo xtask test --profile minimal
cargo xtask test --profile sqlite -- my_test --exact
cargo xtask lint
cargo xtask compose --profile redis
cargo xtask ci
```

`build`, `test`, and `compose` accept `--profile <name>`. The supported profiles and their Cargo features are:

| Profile    | Cargo feature selection                   | Compose services                       |
| ---------- | ----------------------------------------- | -------------------------------------- |
| `minimal`  | `--no-default-features --features memory` | app only                               |
| `postgres` | `postgres`                                | app and PostgreSQL                     |
| `mysql`    | `mysql`                                   | app and MySQL                          |
| `sqlite`   | `sqlite`                                  | app and SQLite volume initialization   |
| `aws`      | `postgres,aws`                            | app, PostgreSQL, and AWS               |
| `vault`    | `postgres,vault`                          | app and PostgreSQL                     |
| `gcp`      | `postgres,gcp`                            | app and PostgreSQL                     |
| `azure`    | `postgres,azure`                          | app and PostgreSQL                     |
| `redis`    | `postgres,redis`                          | app, PostgreSQL, and Redis             |

Vault, GCP, and Azure use externally configured provider endpoints and credentials, so those profiles do not start provider emulators. Configure them in `.env` before starting the profile.

`check-profiles` checks each library with `--no-default-features` and the listed features to detect dependence on other default features. It also checks all supported targets with the normal profile selection. Non-minimal builds and tests retain the default `memory` feature, which the binary and existing test helpers require. Every check runs, and failures are summarized at the end. The required CI profile-check job and the local CI pipeline run these checks.

`test` adds `postgres-tests` to every PostgreSQL-backed profile and also adds
`redis-tests` to the Redis profile. These profiles and MySQL require a running
Docker daemon for their container tests. `minimal` and SQLite tests need no
database containers. Cloud integration tests may require additional provider
configuration; see the contributing guide.

`test` uses installed `cargo-nextest` with the repository's test groups and timeouts, then runs doctests separately. If nextest is absent, it uses `cargo test`; that fallback has no nextest timeouts or process isolation.
A failing nextest run does not trigger a fallback. Arguments after `--` are passed to the selected runner and doctests; use options supported by both. For the same nextest version as CI, run `cargo install --locked cargo-nextest --version 0.9.101`.

`lint` runs formatting, Clippy for all targets and features, `cargo audit`, and
`cargo machete`, then summarizes all failures. Install its tools first:

```bash
rustup component add rustfmt clippy
cargo install --locked cargo-audit --version 0.22.2
cargo install --locked cargo-machete --version 0.9.2
```

`compose` selects the MySQL, SQLite, or Redis override file when needed. MySQL uses `MYSQL_USER`, `MYSQL_PASSWORD`, and `MYSQL_DATABASE` from the shell or `.env` for both the database service and application. SQLite stores its database in the `sqlitedata` named volume, preserving lists across container restarts; `down --volumes` deletes that data. Plain Compose continues to read database configuration from its environment files. The overrides can also be used directly:

```bash
docker compose -f docker-compose.yml -f compose/mysql.yml --profile mysql up -d --build
docker compose -f docker-compose.yml -f compose/sqlite.yml up -d --build
```

These local overrides select their connection mode. Remove incompatible
`APP_DATABASE__URL` or `APP_DATABASE__PASSWORD_FILE` entries from `.env` before using the MySQL override, and password-file entries before using SQLite.

`ci` delegates to the full [`local-ci.sh`](docs/local-ci.md) pipeline.

You can still invoke individual Cargo commands directly. For example, run unit and integration tests or verify the zero-infrastructure in-memory build with:

```bash
cargo test
cargo check --no-default-features --features memory
```

Run the daily local CI checks (formatting, builds, Clippy, tests, and documentation):

```bash
./local-ci.sh

# Add security, configuration, container, and coverage gates:
./local-ci.sh --full
```

Missing tools are bootstrapped locally. See [Local CI](docs/local-ci.md) for
prerequisites, the complete command inventory, and verification instructions.

Run markdown linting:

```bash
npx --yes markdownlint-cli2 README.md
```

## Releases

This project uses [release-plz](https://release-plz.dev/) with [Conventional Commits](https://www.conventionalcommits.org/) to automate semantic versioning and changelog generation. See [Changelog](CHANGELOG.md) for release notes.

## Contributing

Contributions are welcome. Please read the [Contributing Guide](CONTRIBUTING.md) and review the [Architecture Guide](docs/architecture.md) before submitting pull requests.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
