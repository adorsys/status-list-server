# Webhook / Discord Alert Testing Guide (ticket #446)

This guide walks you through firing a real alert through the full pipeline and
confirming it shows up in **three** places:

```
Prometheus (alert fires)
   │  forwards fired/resolved alerts
   ▼
Alertmanager (routes by severity -> Discord)
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

| Service        | Port | Purpose                                          |
|----------------|------|--------------------------------------------------|
| `app`          | 8000 | status-list-server (exposes `/metrics`)          |
| `prometheus`   | 9092 | scrapes `app:8000`, evaluates alert rules        |
| `alertmanager` | 9093 | receives alerts, sends Discord webhooks          |
| `grafana`      | 3000 | dashboards (log in `admin` / your `GRAFANA_ADMIN_PASSWORD`) |
| `otel-collector`| 4317| metrics pipeline                                 |

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

Open the Prometheus UI at **http://localhost:9092** and:

1. Go to **Status → Targets** → the `alertmanager` service must be **UP**.
2. Go to **Alerts** — you should already see some alert rules, most hand
   `inactive`, plus the always-firing **Watchdog**.

## 4. Fire a real alert

The easiest alert to trigger on purpose is the **Watchdog** (`vector(1)`,
always firing) — but since the default Alertmanager routing sends
`severity=none` to the `default` receiver (which is also the Discord webhook),
the Watchdog will already appear in Discord.

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

### Prometheus (http://localhost:9092)
- **Alerts** tab: the alert turns **red / "firing"** with its labels, severity,
  summary, and a runbook link.
- **Graph** tab: query the pushed metric (e.g.
  `cert_time_to_expiry_seconds`) or a recording rule
  (`sli:cert_renewal_failure_rate:5m`) to see the data.

### Grafana (http://localhost:3000)
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

---

## Using Slack / Teams / Mattermost / Email / generic webhook instead

The mechanism is identical — change only `ALERTMANAGER_PLATFORM` and the
matching credential in `.env`:

| System      | `ALERTMANAGER_PLATFORM` | Credential variable     |
|-------------|--------------------------|-------------------------|
| Discord     | `discord`                | `DISCORD_WEBHOOK_URL`   |
| Slack       | `slack`                  | `SLACK_WEBHOOK_URL`     |
| Microsoft Teams | `teams`               | `MS_TEAMS_WEBHOOK_URL`  |
| Mattermost  | `mattermost`             | `MATTERMOST_WEBHOOK_URL`|
| Email       | `email`                  | `ALERTMANAGER_SMTP_HOST`, `ALERTMANAGER_EMAIL_TO` |
| Generic     | `webhook`                | `ALERTMANAGER_WEBHOOK_URL` |

Each is rendered to a native receiver with `send_resolved: true`. Discord and
Slack use Alertmanager's native embed/message formats; Teams and Mattermost use
Alertmanager's generic webhook JSON (they expose inbound webhooks that accept
it).

## Failure / retry behavior

- **Webhook unreachable** — Alertmanager retries with exponential back-off
  (default: 10 retries, back-off up to ~5 minutes per attempt) before dropping,
  and logs a warning. Discord/Slack are delivered by Alertmanager's own
  notification pipeline, so a transient outage is retried automatically.
- **URL unreachable at container start** — `generate-alertmanager-config.sh`
  exits non-zero only if the mandatory credential is missing, so the container
  fails loudly rather than silently sending nothing.
- **Keep credentials out of git** — put them in `.env` (git-ignored) or a
  secret store; the repo ships only placeholders.
