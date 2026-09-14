# How to run the performance test

This suite contains four tests exercising the StatusList Server:

1. Load test
2. Stress test
3. Spike test
4. Authentication test

Each test targets `http://localhost:8000` by default.

## Prerequisites

- Node.js (>= 20)
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

`generate-tokens` writes `scripts/ec-private-key.pem`,
`scripts/ec-public-key.jwk` and `scripts/test-tokens.json`. All three are
git-ignored. The run scripts read the public key from `test-tokens.json`, so the
key always matches the signed JWTs it was generated with.

## Rate limits

The server rate-limits by source IP (strict 10 req/60s writes, permissive
100 req/60s reads by default). A single IP running this suite will be throttled
with `429 Too Many Requests`, which masks the behaviour the tests assert on.
Raise the limits before running the suite, e.g.:

```bash
APP_SERVER__ENABLE_METRICS=true \
APP_TELEMETRY__ENABLED=true \
APP_TELEMETRY__ENVIRONMENT=development \
APP_RATE_LIMIT__STRICT_BURST_SIZE=5000 \
APP_RATE_LIMIT__STRICT_PERIOD_SECS=60 \
APP_RATE_LIMIT__PERMISSIVE_BURST_SIZE=10000 \
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
