# API Testing

This project ships a Postman collection, a local environment, and a Newman
runner for checking the live HTTP API:

- [`postman/status-list-server.postman_collection.json`](../postman/status-list-server.postman_collection.json)
- [`postman/status-list-server.postman_environment.json`](../postman/status-list-server.postman_environment.json)

## Postman Quickstart

Import both files and select the included environment. Set the public,
management, and admin listener URLs for your server. The defaults are
`http://localhost:8000`, `http://localhost:8001`, and
`http://localhost:8002`. Set `issuer_id` to an issuer already provisioned by
the operator, and set the secret `token` variable to a signed management JWT
for that issuer. The token must use a registered key and the audience required
by the server. See [issuer onboarding](issuer-onboarding.md) for local setup.

Send **Start new test run** to generate a fresh `list_id`, then **Verify issuer
credentials**. The latter calls the authenticated
`GET {{managementUrl}}/api/v1/credentials` endpoint. The management writes
inherit the collection's bearer token. Public reads and negative authentication
tests do not use it. The collection cannot register an issuer: the server's
management API no longer has a registration route.

The environment also contains `adminToken` for admin reads and optional hosted
issuer lifecycle requests. The **Issuer Lifecycle (destructive, hosted
profile)** folder requires a hosted server, a portal issuer, its key ID, and
an admin JWT with `issuers:write`. Set `issuer_id`, `kid`, and `adminToken`
before running that folder; suspend and revoke change live issuer state.
The Newman check omits this folder because it runs against the private profile.

Keep bearer tokens private. The checked-in environment contains empty secret
values; do not export populated local values to the repository or a public
workspace.

## Newman Collection Check

The runner requires Rust/Cargo to start the server, Node.js to generate
temporary test keys and JWTs, `curl` for readiness checks, and Newman or Docker.
It replaces a dedicated registry file with temporary issuer and admin entries,
then waits until both identities authenticate. Run it only against a local or
isolated server with a dedicated registry file.

Create an empty registry and start the server with that file:

```bash
registry_file="$PWD/target/postman-test-issuers.json"
mkdir -p "$(dirname "$registry_file")"
printf '{"version":1,"issuers":[],"admins":[]}\n' > "$registry_file"

APP_SERVER__HOST=0.0.0.0 \
APP_SERVER__MANAGEMENT__HOST=0.0.0.0 \
APP_SERVER__ADMIN__HOST=0.0.0.0 \
APP_SERVER__CERT__PROVISIONING_STRATEGY=store \
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=test_data/ed25519_cert.pem \
APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=test_data/ed25519_key.pem \
APP_MANAGEMENT_AUTH__ISSUERS_FILE="$registry_file" \
APP_MANAGEMENT_AUTH__AUDIENCES=status-list-server-management \
APP_ADMIN_AUTH__AUDIENCES=status-list-server-admin \
cargo run
```

In another terminal, run the collection check against that server:

```bash
POSTMAN_ISSUER_REGISTRY_FILE="$PWD/target/postman-test-issuers.json" \
MANAGEMENT_AUDIENCE=status-list-server-management \
ADMIN_AUDIENCE=status-list-server-admin \
./scripts/test-postman-collection.sh
```

The runner writes only temporary collection and environment copies. It
filters the hosted lifecycle folder and runs the remaining requests with the
generated tokens. `POSTMAN_ISSUER_REGISTRY_FILE` is required. `API_ENDPOINT`
defaults to `http://localhost:8000`; `MANAGEMENT_URL` and `ADMIN_URL`
default to the same host on ports 8001 and 8002. The runner selects a local
Newman binary when available, otherwise Docker; set `NEWMAN_RUNNER=local` or
`NEWMAN_RUNNER=docker` to choose explicitly. `NEWMAN_API_READY_TIMEOUT`
defaults to 180 seconds.
