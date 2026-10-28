# API Testing

This project ships ready-to-import Postman assets and an automated Newman
runner for checking the live HTTP API.

## Postman Quickstart

Import these files into Postman, Bruno, or another client that accepts Postman
Collection v2.1 exports:

- [`postman/status-list-server.postman_collection.json`](../postman/status-list-server.postman_collection.json)
- [`postman/status-list-server.postman_environment.json`](../postman/status-list-server.postman_environment.json)

The environment exposes these variables:

| Variable          | Default                                | Purpose                                                               |
| ----------------- | -------------------------------------- | --------------------------------------------------------------------- |
| `baseUrl`         | `http://localhost:8000`                | Running status-list-server endpoint.                                  |
| `list_id`            | generated at publish time | Status list UUID used by publish, update, and retrieve requests. |
| `issuer_id`          | `postman-test-issuer`     | Pre-registered non-production test issuer. |
| `issuer_kid`         | `postman-test-key`        | Trusted key ID used in the generated JWT header. |
| `token`              | empty                     | Generated short-lived JWT for protected management requests. |
| `managementAudience` | empty                     | Optional audience matching the server's configured value. |
| `historical_time`    | `1686925000`              | Unix timestamp used by historical resolution. |

The collection is organized into Health & Metrics, Issuer Management, Status
Lists, and Aggregation folders. Requests include Postman test scripts that check
status codes, content types, token response headers, and JSON response shapes.

### One-click Postman workflow

The interactive Postman collection uses the pre-registered, non-production
issuer in [`postman/test-issuer-registry.yaml`](../postman/test-issuer-registry.yaml).
Start a local server with that trust registry enabled:

```bash
APP_MANAGEMENT_AUTH__ISSUERS_FILE=postman/test-issuer-registry.yaml \
APP_SERVER__CERT__PROVISIONING_STRATEGY=store \
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=test_data/certs/dev.crt \
APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=test_data/certs/dev.key \
cargo run
```

Import the collection and environment, select the environment, then run the
collection in order. The collection includes a test-only private JWK paired
with the trust registry, signs a five-minute ES256 management JWT before each
request, and uses a fresh status-list UUID each time you publish. The first credential
registration returns `202`; later runs may return `409` because that test issuer
is already registered in the local database. Both responses are handled.

The collection intentionally contains a shared test-only private key so
nobody needs to create or paste a JWT. This key is public test material
embedded in the collection and is trusted only by the dedicated test registry. Never use it against production
or a shared server that serves real issuer data. For audience validation, set
`managementAudience` to a value configured in `APP_MANAGEMENT_AUTH__AUDIENCES`.
You can change `issuer_id` and `issuer_kid` in the selected Postman environment;
the values must identify a trusted issuer and key in the server's registry.
The included registry trusts only the default test issuer and key. Changing the
identifier does not register it with the server or change the signing key.

The collection is organized into Health & Metrics, Issuer Management, Status
Lists, and Aggregation folders. Requests include test scripts for status codes,
content types, token response headers, and JSON response shapes.

For fully automated local collection testing from the command line, use the
Newman script below; it creates a separate temporary issuer and can update a
temporary trust registry for the run.

## Local Prerequisites

The Postman/Newman runner expects these host tools:

- Rust/Cargo to start the local server with `cargo run`.
- Node.js for generating ephemeral issuer keys and JWTs.
- `curl` for readiness checks.
- Newman or Docker when running the Postman collection from the command line.
  The CI path uses the pinned Newman container by default.

## Newman Collection Check

Start the API first:

```bash
APP_SERVER__HOST=0.0.0.0 \
APP_SERVER__CERT__PROVISIONING_STRATEGY=store \
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=test_data/ed25519_cert.pem \
APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=test_data/ed25519_key.pem \
cargo run
```

Then run the same collection check used by CI:

```bash
./scripts/test-postman-collection.sh
```

The script generates a temporary P-256 issuer key, patches a temporary copy of
the collection so `POST /api/v1/credentials` registers the matching public JWK,
and runs Newman with a temporary environment containing `baseUrl`, `list_id`,
`issuer_id`, `token`, and `historical_time`. No generated collection or
environment is written into the repository. Set `NEWMAN_RUNNER=docker` to use
the pinned Newman container instead of a locally installed Newman binary.

Useful environment overrides:

| Variable                   | Default                             | Purpose                                                           |
| -------------------------- | ----------------------------------- | ----------------------------------------------------------------- |
| `API_ENDPOINT`             | `http://localhost:8000`             | Live API endpoint under test.                                     |
| `NEWMAN_API_READY_TIMEOUT` | `180`                               | Maximum seconds to wait for the live API before running Newman.   |
| `NEWMAN_RUNNER`            | `auto`                              | Newman runner selection: `auto`, `local`, or `docker`.            |
| `NEWMAN_DOCKER_IMAGE`      | `postman/newman@sha256:02dc...e04f` | Pinned Newman container used by CI and `NEWMAN_RUNNER=docker`.    |

Example against a deployed server:

```bash
API_ENDPOINT=https://statuslist.example.com \
NEWMAN_RUNNER=docker \
./scripts/test-postman-collection.sh
```
