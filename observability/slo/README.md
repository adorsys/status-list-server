# SLIs & SLOs for status-list-server

This document defines the Service Level Indicators (SLIs) and Service Level
Objectives (SLOs) that drive the dashboards and alerts in `observability/`.
Everything here is **versioned as code and reviewed via PR** — a change to an
objective must land in this doc together with the alert rule and, where they
differ, its runbook.

The targets below are **starting values** intended for calibration after the
first ~30 days of production data. They are deliberately stated with their
rationale so they are defensible in review and tuneable without re-litigating
the methodology.

## Metric naming note

The app exports through the OTel `opentelemetry-prometheus` exporter, which
appends suffixes and the `otel_scope_name="status-list-server"` label. The names
below are the **exported** Prometheus series, not the raw instrument names:

| Instrument (source) | Exported series |
|---|---|
| `http_server_duration` histogram (`s`) | `http_server_duration_seconds{...}` |
| `http_server_requests` counter | `http_server_requests_total{...}` |
| `db_query_duration` histogram (`s`) | `db_query_duration_seconds{...}` |
| `db_query_errors` counter | `db_query_errors_total{...}` |
| `status_list_cache_hits` / `_misses` | `status_list_cache_hits_total` / `_misses_total` |
| `token_generation_attempts` / `_failures` | `token_generation_attempts_total` / `_failures_total` |
| `cert_renewal_attempts` / `_successes` / `_failures` | `cert_renewal_*_total` |
| `certificate_chain_cache_hits` / `_misses` | `certificate_chain_cache_*_total` |

Every query in this repo scopes with `{otel_scope_name="status-list-server"}` to
avoid double counting if multiple instrumentation scopes ever appear, and
`sum(...) by (...)`. `sum` is used (not `max`/`avg`) because every SLI here is an
aggregate rate or percentile across the server; aggregating by the bounded label
set keeps cardinality in check.

## Per-SLI table

| SLI | Metric source | Example target | Window | Alert windows / burn thresholds |
|---|---|---|---|---|
| Request latency | `http_server_duration_seconds` histogram | p95 < **300 ms** | 30d | fast page: 1h > 300ms **and** 6h > 300ms; slow warn: 6h > 300ms |
| Error rate | `sum(rate(http_server_requests_total{status_class="5xx"}[...])) / sum(rate(http_server_requests_total[...]))` | ≥ **99.5%** success (≤ 0.5% 5xx) | 30d | fast page: ≥14.4x (0.072) over 1h **and** 6h; slow warn: ≥6x (0.030) over 6h |
| Cache hit ratio | `status_list_cache_hits_total / (hits_total + misses_total)` | ≥ **85%** | 7d | warn-only (degradation, not outage) |
| DB latency | `db_query_duration_seconds` histogram | p95 < **50 ms** | 30d | fast page: 1h > 50ms **and** 6h > 50ms; slow warn: 6h > 50ms |
| Cert renewal failure | `cert_renewal_failures_total / cert_renewal_attempts_total` | < **1%** | 7d | warn-only (op risk) |
| Token-gen failure | `token_generation_failures_total / token_generation_attempts_total` | < **0.5%** | 30d | fast page: ≥14.4x (0.072) over 1h **and** 6h; slow warn: ≥6x (0.030) over 6h |

### Why these windows
- **30d** for latency/error/DB/token: matches the standard Google SRE "monthly
  rolling" objective. The **30d window feeds only the remaining-budget gauge**
  (`sli:error_budget:success:30d`); alerts use the `1h`+`6h` window pair so a
  single incident's error budget isn't exhausted by background noise.
- **7d** for cache hit ratio and cert renewal: these are *health* indicators
  that can turn over fast (a config change flips hit ratio within hours) and are
  alertable as degradation rather than burned revenue. A shorter window makes the
  alert responsive to regressions.

### Why these targets
- **p95 < 300 ms latency**: the SLO from the artillery `load-test.yml` commits to
  p95 < 800 ms under load; production target is set tighter (300 ms) to leave
  headroom so the loaded test does not itself breach the objective.
- **99.5% success**: err budget of 0.5%, chosen so a single cloud-provider
  routing hiccup or DB blip does not consume the whole month at once while still
  holding the service to a high bar. Matches the artillery `err < 5%` load test
  with margin.
- **≥ 85% cache hit**: token reads are the traffic path; a hit avoids a DB round
  trip. 85% is conservative — a well-warmed status list should sit near 100%,
  and dropping below 85% signals eviction pressure or a burst of distinct lists.
- **p95 < 50 ms DB latency**: the in-process cache makes DB reads rare, so the
  DB path tolerates a much tighter latency SLO than the HTTP surface. If cache
  misses spike, this is the canary.
- **< 1% cert renewal failure** (7d): renewal happens on a cron, so rate is low;
  1% catches repeated ACME/backend failures without paging on a single transient
  failure.
- **< 0.5% token-gen failure**: token generation failing means clients cannot
  read a status list. 0.5% err budget over 30d keeps this available without
  paging on an isolated signing-key cache miss.

## Burn-rate / multi-window multi-burn-rate

We follow Google SRE's multi-window multi-burn-rate model (`severity=page`
slow + fast pairs) per SLI that represents an outage (request latency, error
rate, DB latency, token-gen). See `observability/prometheus/rules/alerting.rules.yml`.

- **Fast burn (page)**: the burn rate exceeds **14.4x** the 0.5% budget
  (error/token ratio ≥ 0.072) — or the latency P95 breaches its threshold — on
  **both a short (1h) and a long (6h) window** with `for: 5m`. Requiring two
  aligned windows means a single spiky 5m burst cannot page on its own.
- **Slow burn (warn)**: the burn rate exceeds **6x** the 0.5% budget
  (error/token ratio ≥ 0.030), or the latency P95 breaches its threshold, on a
  **long (6h) window** with `for: 30m` — sustained degradation, not a blip.
- **Cache hit ratio & cert renewal** are **warn-only**: they degrade availability
  or security but do not immediately fail requests, so they page via a human
  review instead of an on-call page.

Two windows are required because a single short window makes the SLO a function
of noise (spiky traffic trips a short window that a longer window clears), and a
single long window is too slow to catch a fast outage.

## How to tune

1. Collect 30d of production data.
2. Compare the `sli:*` recording rule output against these targets in Grafana.
3. If an SLO is at 99.999% with zero near-misses, consider tightening; if it is
   breached monthly, loosen the *target* (not the window) and add a runbook step
   before widening the alert severity.
4. Tune targets, then update this table, `alerting.rules.yml`, and re-run
   `promtool test rules`.
