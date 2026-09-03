# Observability (SLO dashboards & alerts)

SLO dashboards, Prometheus recording/alerting rules, and runbooks for
`status-list-server`, versioned as code and PR-reviewed.

```text
observability/
  slo/thresholds.json            # single source of truth for SLO targets
  slo/lint-thresholds.mjs        # CI linter verifying target lockstep
  slo/README.md                  # SLI/SLO definitions + methodology
  prometheus/
    prometheus.yml               # dev scrape config (2s scrape interval)
    prometheus.production.yml    # production scrape config (15s scrape interval)
    rules/recording.rules.yml    # pre-aggregated sli:* series
    rules/alerting.rules.yml     # multi-window multi-burn-rate alerts
    tests/*.test.yml             # promtool rule tests
  alertmanager/
    alertmanager.example.yml     # example routing config (severity page -> PagerDuty, warn -> Slack)
  dashboards/
    src/                         # deterministic generator
    generated/*.json             # committed dashboard Grafana loads
    provisioning/                # Grafana datasource + file provider
  runbooks/*.md                  # one per alert/SLI
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
promtool check config observability/prometheus/prometheus.yml
promtool check config observability/prometheus/prometheus.production.yml
promtool test rules observability/prometheus/tests/recording.test.yml
promtool test rules observability/prometheus/tests/alerting.test.yml

# SLO threshold consistency lint
node observability/slo/lint-thresholds.mjs

# The DEPLOYED rule copy (the Helm `PrometheusRule`, `prometheusRule.enabled: true`)
# is rendered and run through the same `promtool test rules` suite in CI, and a
# drift guard asserts it defines exactly the same rule names as these tested
# standalone files. See `.github/workflows/CI.yml` -> `prometheus-rules-validation`.

# Full stack
docker compose up -d   # brings up app + otel-collector + prometheus + grafana
```

Dashboard generation is documented in `dashboards/README.md`.

## Datasource UID requirement

Every panel in the committed dashboard (`generated/status-list-slo.json`) pins
its Prometheus datasource by UID `prometheus` (see
`dashboards/provisioning/datasources.yml`). Any environment that loads this
dashboard — including a production/managed Grafana — **must** register its
Prometheus datasource with exactly that UID, or the panels will not resolve.
Do not rely on the datasource _name_; Grafana matches the committed UID.

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
budget gauge is not trustworthy. The dev `docker-compose.yml` stack includes
this flag to model production behavior.

## Deployment note

The repo ships standalone Prometheus + Grafana for a dev stack. For Kubernetes
environments running `kube-prometheus-stack`, the Helm chart includes optional
`templates/servicemonitor.yaml` (`serviceMonitor.enabled: true`) and
`templates/prometheusrule.yaml` (`prometheusRule.enabled: true`). Alert delivery
routing is documented in `observability/alertmanager/alertmanager.example.yml`.

## Webhook alert notifications (ticket #446)

Alerts are forwarded to external systems over webhooks through **Alertmanager**
(Prometheus → Alertmanager → webhook → Discord/Slack/Teams/Mattermost/email).
No application code is involved.

- **How it works** — `observability/prometheus/prometheus*.yml` declares an
  `alerting.alertmanagers` target; the docker-compose `alertmanager` service runs
  `observability/prometheus/generate-alertmanager-config.sh`, which renders a
  native receiver config from environment variables (`ALERTMANAGER_PLATFORM` +
  the matching credential) so **no webhook URL is committed**.
- **Routing** — page and warn alerts share ONE human channel (the platform
  credential); the `severity` label stays in the payload for in-channel
  filtering. The always-firing **Watchdog** (`severity=none`) never hits a
  human channel: it pings a dead-man's-switch (`ALERTMANAGER_DMS_WEBHOOK_URL`)
  so a collapsed pipeline is detected by its absence, and is otherwise absorbed
  silently by a noop sink. Correlated page/warn pairs for the same SLI are
  inhibited (no duplicate warn while the page fires).
- **Supported platforms** — `discord`, `slack`, `teams`, `mattermost`, `email`,
  `webhook` (generic). Native receivers are used for Discord/Slack/email; Teams
  and Mattermost use Alertmanager's generic webhook JSON.
- **Alert Payload & Links** — Every notification payload includes contextual labels, summary/description, Git runbook links (`runbook_url`), and Grafana dashboard links (`dashboard_url`: defaults to `http://localhost:3000/d/status-list-slo`, configurable in Helm via `alerting.dashboardUrl`).
- **Resilience & Monitoring** — Alertmanager retries transient delivery failures with exponential back-off and emits `alertmanager_notifications_failed_total` metrics to monitor delivery health.
- **Test with a real channel** — see the step-by-step Discord guide and full JSON payload schema:
  `runbooks/webhook-notifications.md`.
- **Automated test** — `alertmanager/tests/test-alertmanager-config.sh`
  validates every platform's generated config and proves a real Alertmanager
  delivers both `firing` and `resolved` notifications to a mock webhook (run in
  CI).
