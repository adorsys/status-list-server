# Webhook / Discord Alert Testing Guide (ticket #446)

This guide walks you through firing a real alert through the full pipeline and
confirming it shows up in **three** places:

```text
Prometheus (alert fires)
   │  forwards fired/resolved alerts
   ▼
Alertmanager (page/warn -> single human channel; Watchdog/severity=none -> dead-man's-switch, not Discord)
   │  POSTs webhook
   ▼
Discord channel
```

and confirms you can also see the alert/metrics in **Prometheus** and **Grafana**.

The same setup also works for `slack`, `teams`, `mattermost`, `email`, or a
generic `webhook` — the only thing that changes is the credential you set.

---

## Prerequisites

- Docker + Docker Compose (the repo's dev stack).
- A real **Discord webhook URL**. Create one in a server you own:
  1. Open the Discord server → Server Settings → **Integrations** → **Webhooks**.
  2. Click **New Webhook**, name it (e.g. `status-list-alerts`), pick a channel.
  3. **Copy Webhook URL**. It looks like:
     `https://discord.com/api/webhooks/<ID>/<TOKEN>`
  - Treat this URL as a secret — never commit it.

---

## 1. Configure the Discord webhook (secrets only)

Alertmanager reads the platform and credentials from environment variables. It
**never** reads a webhook URL from a committed file.

Create a local `.env` (already git-ignored) next to `docker-compose.yml`, or
export the variables in your shell before `docker compose up`:

```bash
# .env  (do NOT commit this)
ALERTMANAGER_PLATFORM=discord
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/<ID>/<TOKEN>
```

> The Compose `alertmanager` service passes both variables through. When
> `ALERTMANAGER_PLATFORM=discord`, it invokes
> `generate-alertmanager-config.sh`, which writes a native
> `discord_configs` receiver with `send_resolved: true`.

If you prefer not to use a `.env`, export them instead:

```bash
export ALERTMANAGER_PLATFORM=discord
export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/<ID>/<TOKEN>
```

## 2. Start the observability stack

```bash
# from the repository root
docker compose up -d --build
```

The stack brings up (among others):

| Service          | Port   | Purpose                                     |
| ---------------- | ------ | ------------------------------------------- |
| `app`            | 8000   | status-list-server (exposes `/metrics`)     |
| `prometheus`     | 9092   | scrapes `app:8000`, evaluates alert rules   |
| `alertmanager`   | 9093   | receives alerts, sends Discord webhooks     |
| `grafana`        | 3000   | dashboards (login `admin` + password)       |
| `otel-collector` | 4317   | metrics pipeline                            |

Wait for everything to be healthy, then confirm Alertmanager accepts the
generated config:

```bash
docker compose ps
docker compose exec alertmanager amtool check-config /etc/alertmanager/alertmanager.yml
```

You should see `Checking ...  SUCCESS`.

> If Discord is misconfigured, `generate-alertmanager-config.sh` exits with an
> error because `DISCORD_WEBHOOK_URL` is required: the container will not start.

## 3. Confirm Prometheus is talking to Alertmanager

Open the Prometheus UI at **<http://localhost:9092>** and:

1. Go to **Status → Targets** → the `alertmanager` service must be **UP**.
2. Go to **Alerts** — you should already see some alert rules, most hand
   `inactive`, plus the always-firing **Watchdog**.

## 4. Fire a real alert

The **Watchdog** (`vector(1)`, always firing) is deliberately **not** routed to
a human channel: it goes to the dead-man's-switch (`ALERTMANAGER_DMS_WEBHOOK_URL`)
so a collapsed pipeline is detected by the Watchdog's **absence**, and is
otherwise absorbed silently. To see a real notification, fire a **page** or
**warn** alert (e.g. **CertRenewalFailures** below) — those do reach the
configured human channel.

To trigger a **meaningful, page-like alert** (e.g. **CertRenewalFailures,
severity=warn** or **RequestLatencyFastBurn, severity=page**), push a fabricated
metric the recording/alerting rules consume. From the repo root:

```bash
# Push a cert-expiry condition that trips the CertRenewalFailures alert
# (cert_time_to_expiry_seconds <= 1209600 is the warn gate).
curl -X POST http://localhost:9091/metrics/job/status-list/instance/app \
  --data-binary 'cert_time_to_expiry_seconds{otel_scope_name="status-list-server"} 100000'
```

or, to trip a **page** alert, push an error-rate burst:

```bash
curl -X POST http://localhost:9091/metrics/job/status-list/instance/app \
  --data-binary 'http_server_requests_total{otel_scope_name="status-list-server",status_class="5xx"} 100'
```

> `pushgateway` (port 9091) scrapes directly into the Prometheus TSDB. Adjust
> the metric name/values to trip the alert you want. To clear it later, delete
> the pushed series:
> `curl -X DELETE http://localhost:9091/metrics/job/status-list/instance/app`

Because the dev stack evaluates rules frequently, within ~1–2 windows (seconds
to a few minutes) Prometheus flips the alert to **firing** and forwards it to
Alertmanager.

## 5. See the alert in Prometheus, Grafana, and Discord

### Prometheus (<http://localhost:9092>)
- **Alerts** tab: the alert turns **red / "firing"** with its labels, severity,
  summary, and a runbook link.
- **Graph** tab: query the pushed metric (e.g.
  `cert_time_to_expiry_seconds`) or a recording rule
  (`sli:cert_renewal_failure_rate:5m`) to see the data.

### Grafana (<http://localhost:3000>)
- Log in (`admin` / your `GRAFANA_ADMIN_PASSWORD`).
- Open the **Status List SLO** dashboard (provisioned automatically).
- The affected panels (e.g. certificate renewal, request latency, error rate)
  will show the fired condition; on the alert evaluation you will see the
  burn-rate / threshold breach.

### Discord
- Within a few seconds of the alert firing you should receive a message in the
  configured channel — a native **Discord embed** with:
  - alert name, **severity**, **status (firing)**
  - the summary/description, the affected **service**
  - **timestamp**, and the **runbook / dashboard URL** when present.

## 6. See the resolution notification

Alertmanager sends the **resolved** webhook too (`send_resolved: true`).

- Delete the fabricated metric so the alert no longer breaches:

  ```bash
  curl -X DELETE http://localhost:9091/metrics/job/status-list/instance/app
  ```

- Within a few minutes Prometheus marks the alert **resolved**, Alertmanager
  sends a second Discord embed with **status: resolved**.

You should now see the full lifecycle in Discord: `firing` → `resolved`.

## 7. Automate test (optional)

To prove delivery without a real endpoint, run the in-repo integration test,
which validates all platforms and asserts firing + resolved notifications reach
a mock webhook:

```bash
observability/alertmanager/tests/test-alertmanager-config.sh
```

> [!NOTE]
> **Portability Requirement**: Step 2 of `test-alertmanager-config.sh` uses Docker `--network host` to connect Alertmanager to the mock Python receivers on `127.0.0.1`. Host networking requires a **Linux execution environment** (standard for Linux dev setups and CI runner environments). On macOS or Windows (Docker Desktop / Lima), host networking behaves differently; to run step 2 cross-platform, execute the test suite in a Linux container or CI pipeline.

---

## Using Slack / Teams / Mattermost / Email / generic webhook instead

The mechanism is identical — change only `ALERTMANAGER_PLATFORM` and the
matching credential in `.env`:

| System          | `ALERTMANAGER_PLATFORM` | Credential variable                                                                    |
| --------------- | ----------------------- | -------------------------------------------------------------------------------------- |
| Discord         | `discord`               | `DISCORD_WEBHOOK_URL`                                                                  |
| Slack           | `slack`                 | `SLACK_WEBHOOK_URL`                                                                    |
| Microsoft Teams | `teams`                 | `MS_TEAMS_WEBHOOK_URL`                                                                 |
| Mattermost      | `mattermost`            | `MATTERMOST_WEBHOOK_URL`                                                               |
| Email           | `email`                 | `ALERTMANAGER_SMTP_HOST`, `ALERTMANAGER_EMAIL_TO`, `ALERTMANAGER_SMTP_FROM` (required) |
| Generic         | `webhook`               | `ALERTMANAGER_WEBHOOK_URL`                                                             |

Each is rendered to a native receiver with `send_resolved: true`. Discord and
Slack use Alertmanager's native embed/message formats; Teams and Mattermost use
Alertmanager's generic webhook JSON (they expose inbound webhooks that accept
it).

---

## Alert Payload Format (JSON)

When delivering notifications via `webhook`, `teams`, `mattermost`, or generic HTTP webhooks, Alertmanager POSTs a structured JSON payload with Content-Type `application/json`. Native receivers (Discord, Slack, Email) format these identical fields into embeds, chat blocks, or HTML emails.

### Payload Schema & Example

```json
{
  "version": "4",
  "groupKey": "{}:{alertname=\"RequestLatencyFastBurn\"}",
  "truncatedAlerts": 0,
  "status": "firing",
  "receiver": "human",
  "groupLabels": {
    "alertname": "RequestLatencyFastBurn"
  },
  "commonLabels": {
    "alertname": "RequestLatencyFastBurn",
    "service": "status-list-server",
    "severity": "page",
    "sli": "request_latency"
  },
  "commonAnnotations": {
    "summary": "Request latency P95 sustainably above 300ms (>300ms on the 1h window)",
    "runbook_url": "https://github.com/adorsys/status-list-server/blob/develop/observability/runbooks/request-latency.md",
    "dashboard_url": "http://localhost:3000/d/status-list-slo"
  },
  "externalURL": "http://localhost:9093",
  "alerts": [
    {
      "status": "firing",
      "labels": {
        "alertname": "RequestLatencyFastBurn",
        "service": "status-list-server",
        "severity": "page",
        "sli": "request_latency"
      },
      "annotations": {
        "summary": "Request latency P95 sustainably above 300ms (>300ms on the 1h window)",
        "runbook_url": "https://github.com/adorsys/status-list-server/blob/develop/observability/runbooks/request-latency.md",
        "dashboard_url": "http://localhost:3000/d/status-list-slo"
      },
      "startsAt": "2026-09-02T10:00:00.000Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "http://localhost:9092/graph?g0.expr=...",
      "fingerprint": "a1b2c3d4e5f67890"
    }
  ]
}
```

### Payload Field Definitions

| Field Name                           | Type              | Description                                                                                                                                              |
| ------------------------------------ | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `status`                             | string            | Overall notification status: `firing` or `resolved`.                                                                                                     |
| `receiver`                           | string            | Name of the Alertmanager receiver target (e.g. `human` or `deadmansswitch`).                                                                             |
| `groupLabels`                        | object            | Labels used to group multiple alerts into this notification payload.                                                                                     |
| `commonLabels`                       | object            | Labels shared across all alerts in this notification batch.                                                                                              |
| `commonAnnotations`                  | object            | Annotations shared across all alerts in this notification batch.                                                                                         |
| `alerts[].status`                    | string            | Individual alert state (`firing` or `resolved`).                                                                                                         |
| `alerts[].labels.alertname`          | string            | Name of the alert rule (e.g., `RequestLatencyFastBurn`, `ErrorRateFastBurn`).                                                                            |
| `alerts[].labels.severity`           | string            | Alert urgency level: `page` (urgent action required), `warn` (degradation/monitoring), or `none` (Watchdog).                                             |
| `alerts[].labels.service`            | string            | Name of the affected service (`status-list-server`).                                                                                                     |
| `alerts[].labels.sli`                | string            | (Optional) Specific Service Level Indicator area (`request_latency`, `error_rate`, `db_latency`, `token_generation`, `cache_hit_ratio`, `cert_renewal`). |
| `alerts[].annotations.summary`       | string            | Human-readable summary of the alert condition.                                                                                                           |
| `alerts[].annotations.description`   | string            | (Optional) Detailed contextual values (e.g., exact metric percentage or time to expiry).                                                                 |
| `alerts[].annotations.runbook_url`   | string            | Direct link to the Git-hosted markdown runbook for step-by-step remediation.                                                                             |
| `alerts[].annotations.dashboard_url` | string            | Direct link to the Grafana dashboard (`http://localhost:3000/d/status-list-slo`) for real-time telemetry.                                                |
| `alerts[].startsAt`                  | string (ISO-8601) | Timestamp when the alert rule first breached its threshold.                                                                                              |
| `alerts[].endsAt`                    | string (ISO-8601) | Timestamp when the alert resolved (`0001-01-01T00:00:00Z` while firing).                                                                                 |
| `alerts[].generatorURL`              | string            | Permalink back to the Prometheus graph interface for rule evaluation details.                                                                            |
| `alerts[].fingerprint`               | string            | Unique cryptographic hash identifying the specific alert instance.                                                                                       |

---

## Failure / Retry Behavior

### Retry Mechanism & Parameters

Alertmanager features built-in delivery resilience. When a webhook endpoint or SMTP server returns an HTTP server error (5xx), network timeout, or connection refusal, Alertmanager retries delivery automatically using exponential back-off:

| Parameter        | Default Value                     | Description                                                                                   |
| ---------------- | --------------------------------- | --------------------------------------------------------------------------------------------- |
| `min_backoff`    | `10s`                             | Initial delay before the first retry attempt.                                                 |
| `max_backoff`    | `5m`                              | Maximum delay ceiling between consecutive retries.                                            |
| `backoff_factor` | `2`                               | Multiplier applied to back-off interval on each failure.                                      |
| `max_attempts`   | unlimited (within group interval) | Attempts continue until successful or until the next `group_interval` re-evaluates the group. |

### Customizing Retry Configuration

Global or receiver-level HTTP client parameters can be configured in `/etc/alertmanager/alertmanager.yml` under `global.http_config` or inside individual receiver configurations:

```yaml
global:
  http_config:
    follow_redirects: true
    enable_http2: true
    # Timeout for individual HTTP requests to webhooks
    # timeout: 10s

receivers:
  - name: 'human'
    webhook_configs:
      - url: 'http://localhost:8080/webhook'
        send_resolved: true
        # Override default retry backoff per receiver if needed:
        # http_config:
        #   timeout: 5s
```

### Retry Exhaustion & Outage Behavior

- **Transient Outages**: Temporary network glitches or endpoint restarts (lasting seconds to a few minutes) are automatically recovered by retry back-off without dropping alerts.
- **Persistent Failures**: If an endpoint remains unreachable for the duration of the notification attempt, Alertmanager abandons the delivery attempt for that evaluation cycle and logs a warning. On the subsequent `repeat_interval` (4h for `page`, 24h for `warn`), Alertmanager will attempt delivery again if the alert is still firing.
- **Client Errors (4xx)**: Non-retryable HTTP responses (e.g. 400 Bad Request, 401 Unauthorized, 404 Not Found) fail immediately without retrying to avoid spamming broken endpoints.
- **Startup Validation**: `generate-alertmanager-config.sh` validates mandatory credential environment variables (e.g. `DISCORD_WEBHOOK_URL`, `ALERTMANAGER_SMTP_FROM`) before Alertmanager starts. Missing variables cause container startup to fail loudly rather than silently ignoring alerts.

### Monitoring Delivery Failures

Alertmanager exposes self-monitoring Prometheus metrics that track webhook and notification delivery health:

1. **`alertmanager_notifications_failed_total`**: Counter metric tracking failed notification attempts, partitioned by `integration` (e.g. `discord`, `slack`, `webhook`, `email`).
   - Query in Prometheus: `rate(alertmanager_notifications_failed_total[5m]) > 0` indicates active notification delivery issues.
2. **`alertmanager_notifications_total`**: Counter metric tracking total notification attempts.
3. **Container Logs**: Alertmanager logs all notification failures to stdout with level `warn` or `error`:

   ```text
   level=warn ts=2026-09-02T10:00:00.000Z caller=notify.go:732 component=dispatcher msg="Notify attempt failed" attempt=1 integration=discord err="POST https://discord.com/api/webhooks/...: 503 Service Unavailable"
   ```
