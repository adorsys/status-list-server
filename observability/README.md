# Observability (SLO dashboards & alerts)

SLO dashboards, Prometheus recording/alerting rules, and runbooks for
`status-list-server`, versioned as code and PR-reviewed.

```text
observability/
  slo/README.md                  # SLI/SLO definitions + methodology (Phase 2)
  prometheus/
    prometheus.yml               # full scrape + rule_files config
    rules/recording.rules.yml    # pre-aggregated sli:* series (Phase 3)
    rules/    alerting.rules.yml     # multi-window multi-burn-rate alerts (Phase 4)
    generate-alertmanager-config.sh  # renders Alertmanager receivers from env (Phase 4)
    tests/*.test.yml             # promtool rule tests (Phase 7)
  dashboards/
    src/                         # deterministic generator (Phase 5)
    generated/*.json             # committed dashboard Grafana loads
    provisioning/                # Grafana datasource + file provider
  runbooks/*.md                  # one per alert/SLI (Phase 6)
```

## Metric sources

The SLIs are emitted by the app and exported via the OTel `opentelemetry-prometheus`
exporter (which appends `_total`/`_seconds` and the `otel_scope_name` label).
Phase 1 added: `http_server_duration_seconds`, `http_server_requests_total`,
`db_query_duration_seconds`, `status_list_cache_hits_total`
/`_misses_total`, and `token_generation_attempts_total`/`_failures_total`.
Cert-renewal and cert-chain-cache series already existed.

## Validation

```bash
# Rules + tests (offline, via Prometheus image)
promtool check rules observability/prometheus/rules/*.rules.yml
promtool test rules observability/prometheus/tests/recording.test.yml
promtool test rules observability/prometheus/tests/alerting.test.yml

# Full stack
docker compose up -d   # brings up app + otel-collector + prometheus + grafana
```

Dashboard generation is documented in `dashboards/README.md`.

## Retention requirement

The error-budget gauge and the 30d window recording rules (`sli:error_rate:30d`,
`sli:error_budget:success:30d`) evaluate `rate(...[30d])`. PromQL silently uses
only the samples actually retained, so the 30d window is **unreliable unless the
Prometheus TSDB retains at least 31 days**. The Prometheus default is 15 days
(`--storage.tsdb.retention.time=15d`), which would halve the window and make the
error-budget gauge read artificially optimistic.

Production Prometheus **must** be configured with:

```text
--storage.tsdb.retention.time=31d
```

(or the equivalent in a managed Prometheus config). Without this, the error
budget gauge is not trustworthy. The dev `docker-compose.yml` stack is a local
demo and does not need this set.

## Deployment note

The repo ships standalone Prometheus + Grafana + a local Alertmanager for a dev
stack. Production wiring to a managed stack is an operator step (no credentials
or CRDs in this repo). Notifications are **platform-agnostic**: the Alertmanager
config is rendered at container start by
`observability/prometheus/generate-alertmanager-config.sh`, which emits the
native receiver for the platform selected via `ALERTMANAGER_PLATFORM`
(`slack|discord|teams|mattermost|email|webhook`) using the matching credential
env var. The same stack therefore works with whichever channel the customer
uses, with no per-platform repo code. Real tokens stay out of version control —
they're supplied via `.env` / a secrets manager.
