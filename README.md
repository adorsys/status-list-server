# Status List Server

[![CI](https://github.com/adorsys/status-list-server/actions/workflows/CI.yml/badge.svg)](https://github.com/adorsys/status-list-server/actions/workflows/CI.yml)
[![CD](https://github.com/adorsys/status-list-server/actions/workflows/deploy.yml/badge.svg)](https://github.com/adorsys/status-list-server/actions/workflows/deploy.yml)
[![dependencies](https://deps.rs/repo/github/adorsys/status-list-server/status.svg)](https://deps.rs/repo/github/adorsys/status-list-server)
[![License](https://img.shields.io/github/license/base-org/node?color=blue)](LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE-APACHE)

The **Status List Server** manages and publishes status lists for credential issuers.  
It allows issuers to register, publish, and update status lists, and verifiers to retrieve and validate them securely.

## Overview

This service implements the [Token Status List specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/).  
It supports both **JWT** and **CWT** formats, with cryptographic signing using multiple algorithms (ECDSA, EdDSA, RSA with SHA-256, SHA-384, SHA-512 digest algorithms).

For a detailed explanation of the architecture, see the [hexagonal architecture documentation](docs/hexagonal-architecture.md).

## Quick Start

### Prerequisites

Before running the server, ensure you have the following tools installed:

- [Rust & Cargo](https://www.rust-lang.org/tools/install) (Latest stable).
- [PostgreSQL](https://www.postgresql.org/download/): The database system used for storing status lists.
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

- Execute the command below at the root of the project

```sh
docker compose up --build
```

This command will pull all required images and start the server.

#### Running Manually

To start the server, execute:

```bash
cargo run
```

By default, the server will listen on `http://localhost:8000`. You can modify the host and port in the configuration settings.

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

**Automatic Issuance and Renewal:**

- Certificate issuance and renewal are managed according to the configured renewal strategy.
- Every day, a cron job checks whether the certificate should be renewed based on this strategy.
- If the certificate is still considered valid according to the configured strategy, no renewal occurs; renewal is only triggered when necessary.

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

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
