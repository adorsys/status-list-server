# How to run the performance test

This suite contains four tests exercising the StatusList Server:

1. Load test
2. Stress test
3. Spike test
4. Authentication test

Each test targets `http://localhost:8000` by default.

## Prerequisites

- Node.js (>= 22.18.0) — `artillery@2.0.34` declares `engines.node: ">=22.18.0"`
- A running StatusList Server instance reachable at the test `target`
- The server's default rate limits must be raised for meaningful results (see
  [Rate limits](#rate-limits) below)

## Setup

```bash
# go to the test directory
cd artillery-tests

# install dependencies
npm install

# generate test tokens (JWK + signed JWTs written to ./scripts)
npm run generate-tokens
```

`generate-tokens` writes a single, git-ignored `scripts/test-tokens.json`
containing the issuer ID, the public JWK and a set of signed JWTs. The run and
setup scripts read everything they need from this file, so the key always
matches the signed JWTs it was generated with.

### One-time setup against the running server

Before each test, `scripts/setup.js` runs automatically (via the `npm run
test:*` scripts). It registers the test issuer from `test-tokens.json` and
publishes a set of seed status lists, writing their IDs to
`scripts/seed-lists.json` (git-ignored). This is what makes the authenticated
flows work on a fresh server — without registration the token's `iss` is
unknown and every authenticated request returns `401 issuer_not_found` — and it
gives the read scenarios real list IDs to query.

Registering the issuer used to be attempted from an Artillery `before:` hook,
but that hook does not execute processor `function:` steps in this Artillery
version, so the registration silently never ran. Running it as a Node script
before the load is deterministic and applies to every suite.

## Rate limits

The server rate-limits by source IP (strict 10 req/60s writes, permissive
100 req/60s reads by default). A single IP running this suite will be throttled
with `429 Too Many Requests`, which masks the behaviour the tests assert on.
Raise the limits before running the suite.

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

The values below (the highest of the four) are safe for every suite -- raising
the write (strict) limit especially matters, since the authenticated update
flows send two writes back to back. Use the per-suite values above when running
a single suite so the limits stay high enough to avoid `429`s yet still let the
server shed truly excessive load:

```bash
APP_SERVER__ENABLE_METRICS=true \
APP_TELEMETRY__ENABLED=true \
APP_TELEMETRY__ENVIRONMENT=development \
APP_RATE_LIMIT__STRICT_BURST_SIZE=60000 \
APP_RATE_LIMIT__STRICT_PERIOD_SECS=60 \
APP_RATE_LIMIT__PERMISSIVE_BURST_SIZE=60000 \
APP_RATE_LIMIT__PERMISSIVE_PERIOD_SECS=60 \
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

`artillery report` is deprecated and no longer generates an HTML report, so the
scripts stop after writing the JSON report to `results/`. Inspect the JSON files
directly or pipe them into other reporting tooling.

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
