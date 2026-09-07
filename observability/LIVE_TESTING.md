# SLO Observability — Live Demo Guide

This guide walks a reviewer or operator through validating the SLO stack end to
end: dashboard panels populate with real data, and Prometheus alerts fire
against a running `status-list-server`.

It is the **hands-on companion** to:

- `docs/observability.md` — telemetry/metrics architecture and env contract.
- `observability/slo/README.md` — SLI/SLO definitions and targets.
- `observability/README.md` — layout and validation commands.
- `observability/runbooks/*.md` — per-alert runbooks with diagnostics/mitigation.

> What "correct" means here: the app **serves** metrics on `/metrics`, Prometheus
> **scrapes** them and evaluates the `sli:*` recording rules + alert rules, and
> Grafana **renders** those `sli:*` series on the committed dashboard. The whole
> pipeline is [app] -> [Prometheus] -> [Grafana].

---

## 1. What you are validating

| SLI                   | Recording rule                     | Dashboard panel      | Alert(s)                               |
| --------------------- | ---------------------------------- | -------------------- | -------------------------------------- |
| Request latency (p95) | `sli:request_latency:p95:5m`       | Request latency      | `RequestLatencyFastBurn` / `SlowBurn`  |
| Error rate            | `sli:error_rate:5m`                | Error rate           | `ErrorRateFastBurn` / `SlowBurn`       |
| Cache hit ratio       | `sli:cache_hit_ratio:5m`           | Cache hit ratio      | `CacheHitRatioLow`                     |
| DB latency (p95)      | `sli:db_query_latency:p95:5m`      | DB p95               | `DbLatencyFastBurn` / `SlowBurn`       |
| Token-gen failure     | `sli:token_gen_failure_rate:5m`    | Token-gen failure    | `TokenGenerationFastBurn` / `SlowBurn` |
| Cert renewal failure  | `sli:cert_renewal_failure_rate:5m` | Cert renewal failure | `CertRenewalFailures`                  |
| Error budget          | `sli:error_budget:success:30d`     | Error budget         | `ErrorBudgetCritical`                  |

The dashboard and alerts both query the `sli:*` recording rules, never raw
metrics, so a single number drives both.

---

## 2. Preflight: validate the rules (offline)

Run before/without a full stack to prove the PromQL is well-formed and the
tests pass:

```bash
promtool check rules observability/prometheus/rules/recording.rules.yml
promtool check rules observability/prometheus/rules/alerting.rules.yml
promtool test rules observability/prometheus/tests/recording.test.yml
promtool test rules observability/prometheus/tests/alerting.test.yml
```

If `promtool` is not on the host, run it inside the Prometheus image:

```bash
docker compose exec prometheus promtool check rules /etc/prometheus/rules/recording.rules.yml
```

---

## 3. Bring up the observability stack

```bash
docker compose up -d
```

Service name / host port (from the resolved `docker compose config`):

| Service                        | In-Docker name        | Host port |
| ------------------------------ | --------------------- | --------- |
| Prometheus                     | `prometheus:9090`     | `9092`    |
| Grafana                        | `grafana:3000`        | `3000`    |
| OTel collector (Prom exporter) | `otel-collector:8889` | `8889`    |

> **Port-conflict gotcha.** Host ports are shared across all running Compose
> projects on the machine. If another project's `prometheus`/`grafana` already
> grabbed `9090`/`3000`, this repo's containers start "up" but their ports are
> **not published** and you will get connection failures. Confirm with
> `docker port prometheus` / `docker port grafana`. Stop the competing
> containers (or remap ports) so this stack publishes.
> In this environment the repo Prometheus resolves to host **9092** and Grafana
> to **3000**; adjust the URLs below to match your `docker port` output.

---

## 4. Start the app with metrics + telemetry enabled

The app **does not serve `/metrics` by default** (`server.enable_metrics`
defaults to `false` in `src/config.rs`). You must start it with:

```bash
# from the repo root
APP_SERVER__ENABLE_METRICS=true \
APP_TELEMETRY__ENABLED=true \
APP_TELEMETRY__ENVIRONMENT=development \
RUST_LOG=info \
./target/debug/status-list-server
```

> Why `ENVIRONMENT=development`? Metrics are always exported to the in-process
> Prometheus registry (`/metrics`) regardless of environment. OTLP push to a
> Collector is only wired when the environment is `production` (see
> `src/utils/metrics.rs`), so for a scrape-based local demo we stay in
> `development` to avoid depending on a reachable Collector.

**Smoke check:**

```bash
curl -s -o /dev/null -w "health -> %{http_code}\n" http://localhost:8000/health/live   # 200
curl -s -o /dev/null -w "metrics -> %{http_code}\n" http://localhost:8000/metrics      # 200, NOT 404
curl -s http://localhost:8000/metrics | grep -E "http_server_duration_seconds|status_list_cache"
```

A `404` on `/metrics` means the flag was not set (or the process was started
before this change) — restart with `APP_SERVER__ENABLE_METRICS=true`.

---

## 5. Point Prometheus at the app

Prometheus's default scrape target is `app:8000` (the Compose DNS name for the
in-Docker app). If you run the app **on the host** (as in this demo), that DNS
name does not resolve, so change the target to the Docker bridge gateway
(host from the container's perspective) and reload:

```bash
# edit observability/prometheus/prometheus.yml
#   targets: ['app:8000']  ->  targets: ['192.168.0.1:8000']
# gateway IP:
docker network inspect status-list-server_status-list-network \
  --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}'

# reload (Prometheus is started with --web.enable-lifecycle)
curl -s -X POST -o /dev/null -w "reload -> %{http_code}\n" http://localhost:9092/-/reload
```

Verify the scrape target is up and the rules are loaded:

```bash
curl -s http://localhost:9092/api/v1/targets | python3 -c 'import sys,json;d=json.load(sys.stdin);[print(t["labels"].get("job"),"->",t["health"]) for t in d["data"]["activeTargets"]]'
# -> status_list_server -> up

curl -s http://localhost:9092/api/v1/rules | python3 -c 'import sys,json;d=json.load(sys.stdin);print("groups:",len(d["data"]["groups"]))'
# -> groups: 2 (sli recording + slo alerts)
```

> **Revert when the app runs in Docker again**: set the target back to
> `app:8000`.

---

## 6. Fix the Grafana "Data source prometheus was not found" error

The committed dashboard (`observability/dashboards/generated/status-list-slo.json`)
references the datasource UID `prometheus` in every panel. The provisioning file
must pin that UID, otherwise Grafana auto-generates a random UID and the panels
cannot resolve the datasource.

`observability/dashboards/provisioning/datasources.yml`:

```yaml
datasources:
  - name: Prometheus
    uid: prometheus # <-- must match the dashboard panels
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
```

Apply by recreating Grafana (provisioning is read at startup):

```bash
docker compose up -d --force-recreate grafana
```

Verify:

```bash
curl -s -u "admin:${GRAFANA_ADMIN_PASSWORD}" http://localhost:3000/api/datasources | python3 -c 'import sys,json;[print(x["name"],x["uid"]) for x in json.load(sys.stdin)]'
# -> Prometheus prometheus
```

---

## 7. Generate data so every SLI panel has a value

The raw metrics only exist **once the underlying code paths run**. A cold
server exposes HTTP latency + cache counters, but DB/token-gen/cert families
appear lazily when those operations occur. Run the simulation below to exercise
them.

Before running, be aware of two real API contract details (verified against the
running server):

1. **Credential registration takes a JWK** public key, not a PEM string —
   sending PEM yields `422 invalid type for public_key`.
2. **Statuses are integers** in the request body: `0`=VALID, `1`=INVALID,
   `2`=SUSPENDED (`src/server/handlers/status_list/utils/request.rs`). Sending
   `"VALID"` yields `422`.
3. The server **rate-limits by source IP** (strict 10 req/60s writes,
   permissive 100 req/60s reads by default). Single-IP load is throttled with
   `429 Too Many Requests`. For a demo, raise the limits (Section 8) or keep
   traffic just under them.

The repo already ships a ready-made issuer key + signed JWTs (generated by
`artillery-tests/scripts/token-generator.js`), used below.

### 7a. Optional: restart the app with raised rate limits (recommended for the demo)

```bash
# stop the current instance, then:
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

### 7b. Generate tokens (once)

```bash
cd artillery-tests
npm install
# run from the REPO ROOT (the script uses repo-root-relative paths; running
# `npm run generate-tokens` from inside artillery-tests/ fails with ENOENT):
cd ..
node artillery-tests/scripts/token-generator.js
```

This writes `artillery-tests/scripts/{test-tokens.json,ec-public-key.jwk,ec-private-key.pem}`.

### 7c. Run the simulation

```bash
cat > /tmp/simulate_slo.py << 'PY'
import requests, uuid, time, json

BASE = "http://localhost:8000"
s = requests.Session()
data = json.load(open("artillery-tests/scripts/test-tokens.json"))
jwk, issuer, tokens = data["publicKeyJwk"], data["issuerId"], data["tokens"]

# 1) Register issuer with a JWK (202 = new, 409 = already exists)
r = s.post(f"{BASE}/api/v1/credentials",
           json={"issuer": issuer, "public_key": jwk, "alg": "ES256"})
print(f"[register] -> {r.status_code} {r.text[:40]}")
time.sleep(3)  # pace to stay under default rate limits

lists = []
# 2) Publish + update status lists (token-gen + DB write path) using signed JWTs
for i in range(3):
    lid = str(uuid.uuid4()); lists.append(lid)
    h = {"Authorization": f"Bearer {tokens[i % len(tokens)]}"}
    r = s.put(f"{BASE}/api/v1/status-lists/{lid}/statuses", headers=h,
              json={"statuses": [{"index": 1, "status": 0}, {"index": 2, "status": 1}]})
    print(f"[publish] {lid[:8]} -> {r.status_code}")
    time.sleep(2)
    r = s.patch(f"{BASE}/api/v1/status-lists/{lid}/statuses", headers=h,
                json={"statuses": [{"index": 3, "status": 1}]})
    print(f"[update ] {lid[:8]} -> {r.status_code}")
    time.sleep(2)

# 3) Read lists repeatedly (cache + DB + request-latency metrics).
#    Reads require an explicit Accept header.
ok = 0
for rnd in range(8):
    for lid in lists:
        r = s.get(f"{BASE}/api/v1/status-lists/{lid}",
                  headers={"Accept": "application/statuslist+jwt"})
        if r.status_code == 200: ok += 1
        if rnd == 0: print(f"[read] {lid[:8]} -> {r.status_code}")
    time.sleep(0.5)
print(f"[reads] {ok} successful statuslist+jwt reads")

# 4) Force a couple of 4xx/5xx-class requests for the error-rate path
s.get(f"{BASE}/api/v1/status-lists/", headers={"Accept": "application/statuslist+jwt"})
print("[error-path] malformed GET ->", s.get(f"{BASE}/api/v1/status-lists/").status_code)
PY
python3 /tmp/simulate_slo.py
```

Even if some writes/reads are rate-limited to `429`, the **metric families** for
DB (`db_query_duration_seconds`), token generation
(`token_generation_attempts_total`/`_failures_total`), cache
(`status_list_cache_*`) and HTTP are created once the requests are attempted.
Raising the limits (7a) lets a full run complete with successful publishes and
reads.

### 7d. Confirm the SLI series have values in Prometheus

Wait a minute or two for `rate()[5m]` recording rules to accumulate, then:

```bash
for q in sli:request_latency:p95:5m sli:error_rate:5m sli:cache_hit_ratio:5m \
         sli:db_query_latency:p95:5m sli:token_gen_failure_rate:5m \
         sli:request_latency:p95:1h sli:error_budget:success:30d; do
  v=$(curl -s "http://localhost:9092/api/v1/query" --data-urlencode "query=$q" \
      | python3 -c 'import sys,json;r=json.load(sys.stdin)["data"]["result"];print(r[0]["value"][1] if r else "NO DATA")')
  printf "%-34s %s\n" "$q" "$v"
done
```

A healthy baseline looks like (exact numbers vary with traffic):

```text
sli:request_latency:p95:5m           0.00475     # 4.75 ms
sli:error_rate:5m                    0           # no 5xx
sli:cache_hit_ratio:5m               0.0         # depends on successful reads
sli:db_query_latency:p95:5m          0.00095     # 0.95 ms
sli:error_budget:success:30d         1           # full budget
```

> **"NO DATA" / `NaN` is normal for SLIs with no activity yet**, and it means the
> underlying path has not run (e.g. zero 5xx -> `sli:error_rate` has no series
> because `rate()` of an empty counter drops it; zero failures -> token-gen rate
> is `0/0`). Keep traffic flowing and those panels populate.

---

## 8. View the Grafana dashboard

Open `http://localhost:3000` (login using `GRAFANA_ADMIN_PASSWORD` configured in `docker-compose.yml`) -> **Status List SLO**
(direct: `http://localhost:3000/d/status-list-slo/status-list-slo`).

Panels (all query `sli:*` recording rules):

- Row 1 (golden signals): Request latency p95, Error rate, Error budget, DB p95.
- Row 2 (drill-down/health): Cache hit ratio, Cert renewal failure, Token-gen failure.

Give Grafana a **time range** that overlaps when you generated traffic (e.g. the
last 5–15 minutes), or data will look flat/empty.

---

## 9. Fire each alert end-to-end (optional but recommended for reviewers)

Prometheus evaluates with `scrape_interval: 2s`, `evaluation_interval: 15s`.
Fast-burn (page) alerts require **both** the long and short window (1h+5m for
fast erating, or 6h+30m for slow burn) to breach, so sustain a fault for several
minutes. The sections above walk each alert end to
end. A compact cheat-sheet:

| Alert                          | How to trigger                                                                  | Verify                                        |
| ------------------------------ | ------------------------------------------------------------------------------- | --------------------------------------------- |
| `ErrorRateFastBurn`/`SlowBurn` | Stop the DB and run read load so reads return 5xx                               | `curl -s http://localhost:9092/api/v1/alerts` |
| `RequestLatencyFastBurn`       | Add latency (e.g. `tc qdisc` delay, or saturate the DB) so p95 > 0.3s for 5m+1h | alert state                                   |
| `DbLatencyFastBurn`            | Hold a row lock / `pg_sleep` while hammering reads                              | alert state                                   |
| `TokenGenerationFastBurn`      | Break the signing-key backend while running token flows                         | alert state                                   |
| `CacheHitRatioLow` (warn)      | Burst many distinct list IDs (cold cache) so hit ratio < 0.85 for 15m           | alert state                                   |
| `CertRenewalFailures` (warn)   | Stop `pebble` around the renewal cadence                                        | alert state                                   |

Check fire:

```bash
curl -s http://localhost:9092/api/v1/alerts | python3 -c 'import sys,json;[print(a["labels"].get("alertname"),a["state"]) for a in json.load(sys.stdin)["data"]["alerts"]]'
```

Alert delivery to an external notification channel (e.g. via Alertmanager
webhooks) is handled outside of this repository.

---

## 10. Cleanup / revert dev-only changes

- **Restore the scrape target** in `observability/prometheus/prometheus.yml` to
  `app:8000` when running the app in Docker.
- **Rate-limit overrides** are runtime env only — don't ship the high values to
  production.
- **Datasource `uid: prometheus`** in `datasources.yml` is a permanent, correct
  fix (matches the committed dashboard) — keep it.
- Stop the stack: `docker compose stop` (or `down -v` to also drop Grafana /
  Prometheus state).
- Stop the locally-run server process when done.

---

## Troubleshooting

| Symptom                                      | Fix                                                                                             |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `GET /metrics` -> 404                        | App started without `APP_SERVER__ENABLE_METRICS=true` — restart with it.                        |
| `app:8000` target down                       | App runs on the host, not in Docker; point the scrape target at the bridge gateway (Section 5). |
| Ports 9090/3000 unreachable                  | Competing project owns them; check `docker port prometheus/grafana` and free the port.          |
| "Data source prometheus was not found"       | Datasource UID mismatch — pin `uid: prometheus` (Section 6) and recreate Grafana.               |
| Prompt `429 Too Many Requests`               | Rate limiter keys by source IP; raise limits (Section 7a) for single-IP load.                   |
| Panels show `No data` / `NaN`                | That SLI's code path hasn't run yet; generate the matching traffic (Section 7).                 |
| `422 public_key invalid type`                | Send a JWK, not a PEM (Section 7).                                                              |
| `422` on status publish                      | Use integer statuses `0/1/2`, not strings (Section 7).                                          |
| Recording rules show `NaN` right after start | `rate()[5m]` needs a couple of minutes of scrape history; it resolves.                          |

See the per-alert runbooks in `observability/runbooks/` for diagnostics and
mitigation when an alert fires for real.
