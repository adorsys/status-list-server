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
| `list_id`         | `477121aa-b598-419e-916f-1e74654ff38b` | Status list UUID used by publish, update, and retrieve requests.      |
| `issuer_id`       | `gondwana-digital-pole`                | Issuer provisioned by the demo registry fixture.                      |
| `token`           | empty                                  | Signed issuer JWT for protected `PUT` and `PATCH` requests.           |
| `historical_time` | `1686925000`                           | Unix timestamp used by historical resolution.                         |

The collection is organized into Health & Metrics, Issuer Management, Status
Lists, and Aggregation folders. Requests include Postman test scripts that check
status codes, content types, token response headers, and JSON response shapes.

Protected management routes require a Bearer JWT signed by the private key that
matches a provisioned issuer key. Self-registration is not available. The local
Newman workflow uses a registry fixture and an issuer token from that fixture.

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
APP_MANAGEMENT_AUTH__ISSUERS_FILE=demo/issuers.yaml \
APP_SERVER__CERT__PROVISIONING_STRATEGY=store \
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=test_data/ed25519_cert.pem \
APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=test_data/ed25519_key.pem \
cargo run
```

Then run the same collection check used by CI:

```bash
./scripts/test-postman-collection.sh
```

The script signs a short-lived token with the demo fixture key and runs Newman
with a temporary environment containing `baseUrl`, `list_id`, `issuer_id`,
`token`, and `historical_time`. Configure the server with
`APP_MANAGEMENT_AUTH__ISSUERS_FILE=demo/issuers.yaml`. No generated collection
or environment is written into the repository. Set `NEWMAN_RUNNER=docker` to
use the pinned Newman container instead of a locally installed Newman binary.

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
