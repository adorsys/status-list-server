# Performance / load-validation tests

Performance and load-validation tests for the Status List Server, currently
implemented with [Artillery](https://www.artillery.io/) and run through the
`npm` scripts below. They measure latency and error rates under load against a
local server. They do not replace the correctness tests (`cargo test`), and
their results describe the machine they ran on, not production capacity.

This suite contains four tests exercising the StatusList Server:

1. Load test
2. Stress test
3. Spike test
4. Authentication test

Each test targets `http://localhost:8000` by default. Public reads (health,
welcome, status-list retrieval) hit that target. Authenticated status-list
publishes and updates go to the management listener at `http://localhost:8001`
by default. Override the write destination with
`MANAGEMENT_TARGET` (e.g. `MANAGEMENT_TARGET=https://mgmt.example.com npm run
test:load`) for a deployment with a separate management hostname.

## Prerequisites

- Node.js (>= 22.18.0), as required by `package.json`
- A running StatusList Server instance reachable at the test `target`
- The server's default rate limits must be raised for meaningful results (see
  [Rate limits](#rate-limits) below)

## Setup

```bash
# go to the test workspace
cd perf

# install dependencies
npm install

# generate test tokens (JWK + signed JWTs written to ./scripts)
npm run generate-tokens
```

Set `MANAGEMENT_AUDIENCE` to an audience accepted by the target deployment
before generating tokens (local default: `status-list-server-management`).
Management tokens expire after 300 seconds; workers refresh them during longer
runs. The ignored `scripts/test-tokens.json` contains the ephemeral private key
and is written with owner-only permissions. Regenerate it for each run.

`generate-tokens` writes a single, git-ignored `scripts/test-tokens.json`
containing the issuer ID, the public JWK and a set of signed JWTs. The run and
setup scripts read everything they need from this file, so the key always
matches the signed JWTs it was generated with. It also writes the matching
operator-managed issuer registry to `scripts/issuer-registry.json`.

### Start the server with the generated registry

Generate the token and registry files before starting the server. From the
repository root, configure the server to load that registry and accept the same
audience used to sign the management tokens:

```bash
APP_MANAGEMENT_AUTH__ISSUERS_FILE="$PWD/perf/scripts/issuer-registry.json" \
APP_MANAGEMENT_AUTH__AUDIENCES=status-list-server-management \
cargo run
```

Set `MANAGEMENT_AUDIENCE` to the same value before `npm run generate-tokens` if
you use a different audience. Before each test, `scripts/setup.js` runs
automatically and publishes seed status lists with the registry-provisioned
issuer. It writes their IDs to `scripts/seed-lists.json` (git-ignored); the
seed lists give the read scenarios real list IDs to query. The issuer identity
lookup scenario also uses this issuer and its token. Regenerate the tokens and
registry, then restart the server, before running a test with a new key.

Setup runs as a separate Node script rather than an Artillery `before:` hook,
which does not execute processor `function:` steps.

## Rate limits

The server rate-limits by source IP (strict: 10 rejected management
authentications per 60s, permissive: 100 req/60s reads by default) and
management requests per issuer (burst 100, one token per second for the
`standard` tier). The
`auth` suite sends unauthenticated requests on purpose, which spend the strict
limit, and every suite writes as one issuer. A single IP and issuer running
this suite will be throttled with `429 Too Many Requests`, which masks the
behaviour the tests assert on. Raise the limits before running the suite.

### Limits per suite

Each suite runs from one source IP, so both limits must comfortably exceed the
suite's peak arrival rate multiplied by the requests each scenario fires (the
authenticated update flows fire a `PATCH` right after a `PUT`, i.e. two writes
per virtual user):

| Suite   | Peak arrival rate | Write-heavy? | Recommended limits                             |
| ------- | ----------------- | ------------ | ---------------------------------------------- |
| `auth`  | 50 users/sec      | yes          | `STRICT_BURST_SIZE=10000` / `PERMISSIVE=10000` |
| `load`  | 50 users/sec      | mixed        | `STRICT_BURST_SIZE=6000` / `PERMISSIVE=6000`   |
| `spike` | 600 users/sec     | mixed        | `STRICT_BURST_SIZE=60000` / `PERMISSIVE=60000` |
| `stress`| 250 users/sec     | mixed        | `STRICT_BURST_SIZE=30000` / `PERMISSIVE=30000` |

The values below (the highest of the four) are safe for every suite. Raising
the issuer request limit especially matters, since the authenticated update
flows send two writes back to back and every suite writes as one issuer, so
`APP_TIERS__STANDARD__WRITE_BURST_SIZE` needs the same headroom as
`STRICT_BURST_SIZE`. Use the per-suite values above when running
a single suite so the limits stay high enough to avoid `429`s yet still let the
server shed truly excessive load. `APP_SERVER__AGGREGATION_URI` makes every
served token carry `aggregation_uri`, so the read scenarios also measure the
aggregation ID lookup that comes with it:

```bash
APP_SERVER__ENABLE_METRICS=true \
APP_SERVER__AGGREGATION_URI=http://localhost:8000/api/v1/aggregation \
APP_TELEMETRY__ENABLED=true \
APP_TELEMETRY__ENVIRONMENT=development \
APP_RATE_LIMIT__STRICT_BURST_SIZE=60000 \
APP_RATE_LIMIT__STRICT_PERIOD_SECS=60 \
APP_RATE_LIMIT__PERMISSIVE_BURST_SIZE=60000 \
APP_RATE_LIMIT__PERMISSIVE_PERIOD_SECS=60 \
APP_TIERS__STANDARD__WRITE_BURST_SIZE=60000 \
RUST_LOG=info \
./target/debug/status-list-server
```

## Run a single test

```bash
npm run test:load     # tests/load-test.yml
npm run test:stress   # tests/stress-test.yml
npm run test:spike    # tests/spike-test.yml
npm run test:auth     # tests/auth-test.yml

# or all four in sequence
npm run test:all
```

Each test config declares `ensure` thresholds (max error rate, latency
percentiles). With the `ensure` plugin enabled, Artillery fails the run if a
threshold is breached.

## Run a test and capture a JSON report

Every test has a `:report` variant that writes the raw Artillery report (JSON)
into `results/` (git-ignored):

```bash
npm run test:load:report   # -> results/load-test.json
npm run test:stress:report # -> results/stress-test.json
npm run test:spike:report  # -> results/spike-test.json
npm run test:auth:report   # -> results/auth-test.json
```

Artillery's `artillery report` command is deprecated and no longer
generates an HTML report, so the scripts stop after writing the JSON report to
`results/`. Inspect the JSON files directly or pipe them into other reporting
tooling.

## Memory and CPU usage

Go to `localhost:9090` to access the Prometheus dashboard. Then search for the
memory or CPU usage.

**Memory usage**:

```text
process_resident_memory_bytes{job="status_list_server"} / 1024 / 1024
```

**CPU usage**:

```text
rate(process_cpu_seconds_total[30s]) * 100
```

Click on the graph to see the graph of each.
