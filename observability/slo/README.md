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

| Instrument (source)                                  | Exported series                                       |
| ---------------------------------------------------- | ----------------------------------------------------- |
| `http_server_duration` histogram (`s`)               | `http_server_duration_seconds{...}`                   |
| `http_server_requests` counter                       | `http_server_requests_total{...}`                     |
| `db_query_duration` histogram (`s`)                  | `db_query_duration_seconds{...}`                      |
| `status_list_cache_hits` / `_misses`                 | `status_list_cache_hits_total` / `_misses_total`      |
| `token_generation_attempts` / `_failures`            | `token_generation_attempts_total` / `_failures_total` |
| `cert_renewal_attempts` / `_successes` / `_failures` | `cert_renewal_*_total`                                |
| `certificate_chain_cache_hits` / `_misses`           | `certificate_chain_cache_*_total`                     |

Every query in this repo scopes with `{otel_scope_name="status-list-server"}` to
avoid double counting if multiple instrumentation scopes ever appear, and
`sum(...) by (...)`. `sum` is used (not `max`/`avg`) because every SLI here is an
aggregate rate or percentile across the server; aggregating by the bounded label
set keeps cardinality in check.

## Per-SLI table

| SLI                  | Metric source                                                                                                 | Example target                   | Window | Alert windows / burn thresholds                                                      |
| -------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------- | ------ | ----------------------------------------------------------------------------         |
| Request latency      | `http_server_duration_seconds` histogram                                                                      | p95 < **300 ms**                 | 30d    | fast page: 1h > 300ms **and** 5m > 300ms; slow warn: 6h > 300ms **and** 30m > 300ms  |
| Error rate           | `sum(rate(http_server_requests_total{status_class="5xx"}[...])) / sum(rate(http_server_requests_total[...]))` | ≥ **99.5%** success (≤ 0.5% 5xx) | 30d    | fast page: ≥14.4x (0.072) on 1h **and** 5m; slow warn: ≥6x (0.030) on 6h **and** 30m |
| Cache hit ratio      | `status_list_cache_hits_total / (hits_total + misses_total)`                                                  | ≥ **85%**                        | 5m     | warn-only (degradation, not outage)                                                  |
| DB latency           | `db_query_duration_seconds` histogram                                                                         | p95 < **50 ms**                  | 30d    | fast page: 1h > 50ms **and** 5m > 50ms; slow warn: 6h > 50ms **and** 30m > 50ms      |
| Cert expiry          | `cert_time_to_expiry_seconds` gauge                                                                           | renew before expiry              | –      | warn: ≤14d to expiry (op risk); page: ≤7d to expiry (imminent)                       |
| Token-gen failure    | `token_generation_failures_total / token_generation_attempts_total`                                           | < **0.5%**                       | 30d    | fast page: ≥14.4x (0.072) on 1h **and** 5m; slow warn: ≥6x (0.030) on 6h **and** 30m |

### Why these windows
- **30d** for latency/error/DB/token/cert: matches the standard Google SRE "monthly
  rolling" objective. The **30d window feeds the long-term health metrics and budget gauges**
  (`sli:error_budget:success:30d`, `sli:token_gen_error_budget:30d`, `sli:cert_renewal_failure_rate:30d`); alerts use fast/slow burn or specific alert windows so a single incident does not consume the whole month at once.
- **5m** for cache hit ratio: hit ratio is a *health* indicator that can turn over fast (a config change flips hit ratio within hours) and is alertable as degradation rather than burned revenue. A shorter 5m window makes the alert responsive to instant regressions.

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
- **< 1% cert renewal failure** (30d): **no longer used for alerting.** Renewal
  happens on a sparse clock (every few days to weeks), so a `rate()` over a fixed
  window is `0/0 = NaN` whenever no renewal occurs and cannot fire. The firing
  cert alerts are instead **expiry-driven** on the continuous
  `cert_time_to_expiry_seconds` gauge (warn ≤14d, page ≤7d), which drops
  monotonically while renewal fails to keep the certificate fresh.
- **< 0.5% token-gen failure**: token generation failing means clients cannot
  read a status list. 0.5% err budget over 30d keeps this available without
  paging on an isolated signing-key cache miss.

## Burn-rate / multi-window multi-burn-rate

We follow Google SRE's multi-window multi-burn-rate model (`severity=page`
slow + fast pairs) per SLI that represents an outage (request latency, error
rate, DB latency, token-gen). See `observability/prometheus/rules/alerting.rules.yml`.

- **Fast burn (page)**: the burn rate exceeds **14.4x** the 0.5% budget
  (error/token ratio ≥ 0.072) — or the latency P95 breaches its threshold — on
  **both a short (5m) and a long (1h) window** with `for: 5m`. The short window
  is 1/12 of the long window, per the SRE workbook, so a severe incident pages
  off the fast 1h window (confirmed by 5m) without waiting for a slow trailing
  average.
- **Slow burn (warn)**: the burn rate exceeds **6x** the 0.5% budget
  (error/token ratio ≥ 0.030), or the latency P95 breaches its threshold, on
  **both a short (30m) and a long (6h) window** with `for: 30m` — sustained
  degradation, not a blip. The short window is again 1/12 of the long window.
- Each pair is an `and` of the long-window burn signal with its short-window
  confirmation. The long window guarantees the burn is significant; the short
  window guarantees it is *still happening* (good reset time) and, because a
  severe incident drives the 1h/5m windows immediately, the **page fires before
  the warn** instead of arriving hours later.
- **Cache hit ratio** is **warn-only**: it degrades availability but does not
  immediately fail requests, so it warns instead of paging.
- **Certificate expiry** is **warn + page**, but not burn-rate based: it alerts
  on the continuous `cert_time_to_expiry_seconds` gauge (warn ≤14d, page ≤7d),
  because renewal is a discrete, low-frequency event where `rate()` over a fixed
  window is `0/0 = NaN` and cannot fire.

Two windows are required because a single short window makes the SLO a function
of noise (spiky traffic trips a short window that a longer window clears), and a
single long window is too slow to catch a fast outage.

### Latency alerts are threshold-based, not burn-rate

Latency alerts are threshold-based on trailing-window quantiles, not burn-rate:
they compare `histogram_quantile(0.95, rate(...))` sampled over the 1h/6h windows
against a fixed threshold, rather than a ratio-to-budget burn rate. Because those
windows are long trailing averages, they respond slowly to brief spikes — a
30-second p95=800ms spike moves a 1h trailing average by only ~0.8%, far below
the 300ms threshold. A sustained breach of 10+ minutes is the minimum that will
meaningfully move the 1h window.

Expect, therefore, that a short latency spike visible in traces may not fire a
latency alert. This is accepted divergence (documented below): the latency alerts
`RequestLatencyFastBurn`/`SlowBurn` and `DbLatencyFastBurn`/`SlowBurn` fire only
on sustained degradation, on purpose, to avoid paging on a blip.

## Quarterly SLO Review Process

1. Query 30d of `sli:*` recording rule data from Prometheus/Grafana.
2. Calculate actual performance vs documented targets.
3. If an SLO performance is >99.9% with zero near-misses, consider tightening targets; if performance is <90% or continuously breached, investigate root causes and consider loosening targets or adjusting architecture.
4. If breached monthly, document root cause and remediation actions taken.
5. Update `thresholds.json` and regenerate dashboards using `npm run generate-dashboards`.
6. Update runbooks with new diagnostic queries, thresholds, and escalation paths.

## How to tune

1. Collect 30d of production data.
2. Compare the `sli:*` recording rule output against these targets in Grafana.
3. If an SLO is at 99.999% with zero near-misses, consider tightening; if it is
   breached monthly, loosen the *target* (not the window) and add a runbook step
   before widening the alert severity.
4. Tune targets, then update this table, `alerting.rules.yml`, and re-run
   `promtool test rules`.

## Thresholds are hard-coded: keep them in lockstep

Every SLO target in this doc is duplicated as a **literal constant** in more than
one file. A change to a target must be applied to **all** of them together, or
dashboards and alerts drift from the documented objective:

| Target               | Files that hard-code it                                                                                                                                      |
| -----------------    | --------------------------------------------------------------------------------------------------------------------------------                             |
| 300 ms latency       | `alerting.rules.yml` (0.3), `dashboards/src/generate.mjs` (0.3), this doc                                                                                    |
| 0.5% error budget    | `recording.rules.yml` (`0.005` denominator), `alerting.rules.yml` (0.072/0.030), `dashboards/src/generate.mjs` (0.005), this doc                             |
| 85% cache hit        | `alerting.rules.yml` (0.85), `dashboards/src/generate.mjs` (0.85), this doc                                                                                  |
| 50 ms DB latency     | `alerting.rules.yml` (0.05), `dashboards/src/generate.mjs` (0.05), this doc                                                                                  |
| 1% cert renewal      | `dashboards/src/generate.mjs` (0.01, diagnostic reference only); alerting uses expiry thresholds below                                                       |
| 14d / 7d cert expiry | `alerting.rules.yml` (1209600 / 604800 s), `helm/chart/values.yaml` (`slo.certExpiryWarnSeconds` / `certExpiryCriticalSeconds`), `thresholds.json`, this doc |
| 0.5% token-gen       | `recording.rules.yml` (0.005), `alerting.rules.yml` (0.072/0.030), this doc                                                                                  |

Because the dashboard JSON is generated, change `dashboards/src/generate.mjs`
and commit the regenerated `generated/status-list-slo.json` (`npm run
generate-dashboards`) together.

## Error budget exhaustion alert

Beyond the fast/slow burn pairs, `ErrorBudgetCritical` (`alerting.rules.yml`)
pages when the 30d remaining budget (`sli:error_budget:success:30d`) falls below
10%, i.e. when `sli:error_rate:30d` approaches 90% of the 0.5% target. Similarly, `TokenGenErrorBudgetCritical` pages when `sli:token_gen_error_budget:30d` falls below 10%. Certificate alerts are expiry-driven instead: `CertRenewalFailures` warns at ≤14 days to expiry and `CertRenewalErrorBudgetCritical` pages at ≤7 days. See `runbooks/error-budget.md`, `runbooks/token-generation.md`, and `runbooks/cert-renewal.md`.
