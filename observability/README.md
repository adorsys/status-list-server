# Observability (SLO dashboards & alerts)

SLO dashboards, Prometheus recording/alerting rules, and runbooks for
`status-list-server`, versioned as code and PR-reviewed.

```text
observability/
  slo/README.md                  # SLI/SLO definitions + methodology (Phase 2)
  prometheus/
    prometheus.yml               # full scrape + rule_files config
    rules/recording.rules.yml    # pre-aggregated sli:* series (Phase 3)
    rules/alerting.rules.yml     # multi-window multi-burn-rate alerts (Phase 4)
    alertmanager.yml             # page/warn routing (no secrets, Phase 4)
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

## Deployment note

The repo ships standalone Prometheus + Grafana + a local Alertmanager for a dev
stack. Production wiring to a managed stack is an operator step (no credentials
or CRDs in this repo); `alertmanager.yml` receivers are placeholders.
