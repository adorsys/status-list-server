# API Testing

This project ships ready-to-import Postman assets and an automated Microcks
contract test runner for checking the live HTTP API against
[`docs/openapi.yaml`](openapi.yaml).

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
| `issuer_id`       | `my-issuer`                            | Issuer identifier used for credential registration.                   |
| `token`           | empty                                  | Signed issuer JWT for protected `PUT` and `PATCH` requests.           |
| `historical_time` | `1686925000`                           | Unix timestamp used by historical resolution.                         |

The collection is organized into Health & Metrics, Issuer Management, Status
Lists, and Aggregation folders. Requests include Postman test scripts that check
status codes, content types, token response headers, and JSON response shapes.

Protected management routes require a Bearer JWT signed by the private key that
matches the issuer public JWK registered through `POST /api/v1/credentials`.
For fully automated local contract testing, use the Microcks script below; it
generates and registers a temporary issuer for the run.

## Local Prerequisites

The Postman/Newman and Microcks runners expect these host tools:

- Rust/Cargo to start the local server with `cargo run`.
- Node.js for generating ephemeral issuer keys and JWTs.
- `curl` for readiness checks and issuer registration.
- `python3` plus PyYAML for the Microcks OpenAPI artifact generator. On
  Debian/Ubuntu install it with `sudo apt-get install python3-yaml`; in an
  isolated Python environment use `python3 -m pip install PyYAML`.
- Docker, unless a local `microcks` or `microcks-cli` binary is already
  installed.
- Newman, only when running the Postman collection from the command line.

## Newman Collection Check

Start the API first:

```bash
APP_SERVER__CERT__PROVISIONING_STRATEGY=store \
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=test_data/gcloud_test_cert.dummy.pem \
APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=test_data/gcloud_test_key.dummy.pem \
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
environment is written into the repository.

## Microcks Contract Conformance

Start the API first:

```bash
APP_SERVER__CERT__PROVISIONING_STRATEGY=store \
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=test_data/gcloud_test_cert.dummy.pem \
APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=test_data/gcloud_test_key.dummy.pem \
cargo run
```

Then run the conformance checks:

```bash
./scripts/test-microcks-conformance.sh
```

The script:

1. Generates an ephemeral P-256 issuer key and ES256 management JWT when
   `STATUS_LIST_AUTH_TOKEN` is not already set.
2. Registers that issuer against the live server.
3. Imports both the OpenAPI and Postman artifacts into Microcks.
4. Runs Microcks OpenAPI schema conformance against `docs/openapi.yaml`.

By default it uses a local Microcks CLI binary in dry-run mode when one is
available. If no local CLI exists, the script starts a disposable
`microcks-uber` container on `http://localhost:8585`, imports the OpenAPI and
Postman artifacts, and runs the CLI container against that explicit Microcks
instance. The fallback avoids running Testcontainers from inside another
container, which is fragile on some Docker hosts.

The Docker fallback pins both Microcks images by immutable digest. The CLI
container no longer forces `--user 0:0`, and it receives only the generated
temporary artifacts through a read-only bind mount; the repository checkout is
not mounted into the container.

Useful environment overrides:

| Variable                       | Default                                             | Purpose                                                                                            |
| ------------------------------ | --------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `API_ENDPOINT`                 | `http://localhost:8000`                             | Live API endpoint under test.                                                                      |
| `API_NAME_VERSION`             | `Status List Server:0.1.0`                          | Microcks service reference, matching OpenAPI title and version.                                    |
| `STATUS_LIST_AUTH_TOKEN`       | generated                                           | Existing management JWT to use instead of generating one.                                          |
| `MICROCKS_OPERATIONS_HEADERS`  | generated Authorization header                      | Full Microcks operations headers JSON override.                                                    |
| `NEWMAN_API_READY_TIMEOUT`     | `180`                                               | Maximum seconds to wait for the live API before running Newman.                                    |
| `MICROCKS_READY_TIMEOUT`       | `180s`                                              | Maximum time to wait for the ephemeral Microcks container to start.                                |
| `MICROCKS_WAIT_FOR`            | `30sec`                                             | Maximum wait time for each Microcks test.                                                          |
| `RUN_POSTMAN_CONFORMANCE`      | `false`                                             | Set to `true` to additionally try Microcks' Postman runner. The collection is imported either way. |
| `MICROCKS_VERBOSE`             | `true`                                              | Set to `false` to suppress Microcks CLI request/response dumps.                                    |
| `MICROCKS_IMAGE`               | `quay.io/microcks/microcks-cli@sha256:b420...f4c2e` | Pinned CLI container image used when no local CLI is installed.                                    |
| `MICROCKS_UBER_IMAGE`          | `quay.io/microcks/microcks-uber@sha256:c0da...3d91` | Pinned Microcks server image used by the Docker fallback.                                          |
| `MICROCKS_MANAGED_PORT`        | `8585`                                              | Host port for the disposable Microcks server.                                                      |

Example against a deployed server with an existing issuer token:

```bash
API_ENDPOINT=https://statuslist.example.com \
STATUS_LIST_AUTH_TOKEN="$TOKEN" \
./scripts/test-microcks-conformance.sh
```

Microcks exits non-zero when it detects path, query-parameter, header, status
code, or schema drift between the OpenAPI contract and the live implementation.
