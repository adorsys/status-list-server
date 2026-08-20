# What's Good: Technical Overview

`status-list-server` has a clean Rust structure, strong request controls, and production deployment support. This review is based on source and configuration only; tests and workflows were not run.

## Architecture and Boundaries

- The domain uses clear ports for storage, cache, history, and certificates.
- HTTP handlers, application setup, and outbound adapters have separate roles.
- Cargo features keep memory, SQL, Redis, AWS, and ACME integrations optional.
- CI checks that domain code stays free of infrastructure imports.

## Types, Validation, and Request Controls

- Strong types separate issuers, public keys, statuses, lists, snapshots, and errors.
- Issuer JWKs are parsed before storage. Write routes verify signed Bearer tokens and issuer ownership.
- Request size, status count, status index, and list size limits are configurable.
- Rate limits differ for writes, issuer registration, and public reads. API errors use stable codes and are not cached.

## API and Protocol Design

- An OpenAPI 3.1 contract describes routes, security, errors, health, and metrics.
- Clients can request JWT or CWT status lists. Both outputs use ES256 and include certificate-chain data.
- Unsupported output types return `406 Not Acceptable`.
- Read responses support ETags, `304 Not Modified`, cache lifetimes, and gzip for JWTs.

## Tests and Reproducible Verification

- Tests sit next to the domain, HTTP, authentication, configuration, telemetry, cache, and SQL code they cover.
- Authentication tests cover missing, malformed, expired, and wrongly signed tokens.
- Database tests use fresh, migrated MySQL and PostgreSQL databases. They cover atomic writes, rollbacks, and concurrent updates.
- CI builds all features, runs tests and coverage, checks formatting and linting, and validates documentation. Local CI repeats the main checks.

## Deployment and Operations

- Docker builds locked release images for `amd64` and `arm64`. The runtime image is minimal and runs as a non-root user.
- Helm adds `/health` probes, resource limits, Prometheus scraping, and hardened container settings.
- Database migrations cover credentials, current lists, history, and retention. MySQL uses InnoDB for transaction and foreign-key support.
- The service supports structured logs, traces, and Prometheus metrics. Local Compose includes an OpenTelemetry collector, Jaeger, and Prometheus.

## Reliability and Code Quality

- Updates use timestamps to detect write conflicts. Snapshot writes use transactions when history is enabled.
- The cache has size and time limits. Cache failures fall back to storage, and entries are cleared after a successful write.
- Token signing and compression run outside the async request executor. Database pool timeouts and lifetimes are configurable.
- The codebase includes module docs, a configuration template, an API contract, operational guides, format checks, lint rules, and release conventions.
