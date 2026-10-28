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
| `issuer_id`       | `my-issuer`                            | Issuer identifier generated for the temporary Newman test key.         |
| `token`           | empty                                  | Signed issuer JWT for protected `PUT` and `PATCH` requests.           |
| `historical_time` | `1686925000`                           | Unix timestamp used by historical resolution.                         |

The collection is organized into Health & Metrics, Issuer Management, Status
Lists, and Aggregation folders. Requests include Postman test scripts that check
status codes, content types, token response headers, and JSON response shapes.

Protected management routes require a Bearer JWT signed by the private key that
matches the issuer public JWK provisioned in the operator-managed issuer
registry. The Newman script generates a temporary issuer key and token, writes
the public key to the registry file named by `POSTMAN_ISSUER_REGISTRY_FILE`,
and waits until the running server reloads that file.

## Local Prerequisites

The Postman/Newman runner expects these host tools:

- Rust/Cargo to start the local server with `cargo run`.
- Node.js for generating ephemeral issuer keys and JWTs.
- `curl` for readiness checks.
- Newman or Docker when running the Postman collection from the command line.
  The CI path uses the pinned Newman container by default.

## Newman Collection Check

Create an empty valid registry file, then start the API with that same path and
the audience used by the Newman script. The script replaces the empty registry
with its temporary issuer entry; the server's registry watcher reloads it.

```bash
registry_file="$PWD/target/postman-test-issuers.json"
mkdir -p "$(dirname "$registry_file")"
printf '{"version":1,"issuers":[],"admins":[]}\n' > "$registry_file"

APP_SERVER__HOST=0.0.0.0 \
APP_SERVER__CERT__PROVISIONING_STRATEGY=store \
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=test_data/ed25519_cert.pem \
APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=test_data/ed25519_key.pem \
APP_MANAGEMENT_AUTH__ISSUERS_FILE="$registry_file" \
APP_MANAGEMENT_AUTH__AUDIENCES=status-list-server-management \
cargo run
```

In another terminal, run the same collection check used by CI and point it at
the same registry file:

```bash
POSTMAN_ISSUER_REGISTRY_FILE="$PWD/target/postman-test-issuers.json" \
MANAGEMENT_AUDIENCE=status-list-server-management \
./scripts/test-postman-collection.sh
```

The script writes the issuer's public JWK to the registry file, then runs Newman
with a temporary collection and environment containing `baseUrl`, `list_id`,
`issuer_id`, `token`, and `historical_time`. It fails early if
`POSTMAN_ISSUER_REGISTRY_FILE` is unset. No generated collection or environment
is written into the repository. Set `NEWMAN_RUNNER=docker` to use the pinned
Newman container instead of a locally installed Newman binary.

Useful environment overrides:

| Variable                   | Default                             | Purpose                                                           |
| -------------------------- | ----------------------------------- | ----------------------------------------------------------------- |
| `API_ENDPOINT`             | `http://localhost:8000`             | Live API endpoint under test.                                     |
| `NEWMAN_API_READY_TIMEOUT` | `180`                               | Maximum seconds to wait for the live API before running Newman.   |
| `NEWMAN_RUNNER`            | `auto`                              | Newman runner selection: `auto`, `local`, or `docker`.            |
| `NEWMAN_DOCKER_IMAGE`      | `postman/newman@sha256:02dc...e04f` | Pinned Newman container used by CI and `NEWMAN_RUNNER=docker`.    |
| `POSTMAN_ISSUER_REGISTRY_FILE` | required                          | Dedicated registry file loaded by the server through `APP_MANAGEMENT_AUTH__ISSUERS_FILE`. |

The script replaces the registry file with its temporary test issuer. Run it
only against a local or isolated test server with a dedicated registry file;
never point it at a production registry or a registry shared with other
issuers. For a remote test server, the Newman runner and server must both have
access to the same dedicated registry file.
