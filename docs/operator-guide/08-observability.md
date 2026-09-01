# 08 — Observability

This guide covers monitoring the Status List Server: Prometheus metrics, rotation
telemetry, OpenTelemetry trace export, and the health check endpoints.

## 1. Health check endpoints

The server exposes two standard endpoints (see `src/server/health.rs`):

| Endpoint            | Used by         | Semantics                                                                  |
| ------------------- | --------------- | -------------------------------------------------------------------------- |
| `GET /health/live`  | liveness probe  | Process is alive.                                                          |
| `GET /health/ready` | readiness probe | All registered dependency checks pass (e.g. DB reachable, backends ready). |

The chart wires these automatically:

```yaml
statuslist:
  livenessProbe:
    httpGet: { path: /health/live, port: http }
    initialDelaySeconds: 10
    periodSeconds: 15
    timeoutSeconds: 5
    failureThreshold: 3
  readinessProbe:
    httpGet: { path: /health/ready, port: http }
    initialDelaySeconds: 5
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 3
```

Probe directly:

```bash
curl -s https://<your-host>/health/live
curl -s https://<your-host>/health/ready
```

`/health/ready` returns non-200 until dependencies are ready, which also gates rolling
updates (a new pod only receives traffic once ready).

## 2. Prometheus metrics

Metrics are enabled with `APP_SERVER__ENABLE_METRICS=true` (default `false`) and exposed
on `GET /metrics`. The chart adds scrape annotations automatically:

```yaml
# pod annotations set by the chart
prometheus.io/scrape: "true"
prometheus.io/port: "8081" # statuslist.service.targetPort
prometheus.io/path: "/metrics"
```

The server emits **OpenTelemetry** metrics additionally exported via the in-process
Prometheus exporter, tagged with the scope label
`otel_scope_name="status-list-server"`. Relevant metric families include:

| Metric                                                         | Meaning                                                      |
| -------------------------------------------------------------- | ------------------------------------------------------------ |
| `cert_renewal_attempts`                                        | Certificate renewal attempts.                                |
| `cert_renewal_successes` / `cert_renewal_failures`             | Renewal outcomes.                                            |
| `cert_last_successful_renewal_timestamp`                       | Gauge of the last successful renewal.                        |
| `cert_chain_cache_replacements_total`                          | Certificate chain cache replacements after (re)provisioning. |
| `vault_auth_renewals_total`                                    | Vault token renewals.                                        |
| Vault re-authentication / failure counters                     | Login/renewal failure telemetry.                             |
| HTTP request metrics (`axum_http_requests_duration_seconds_*`) | Request latency/status.                                      |

> [!NOTE]
> When querying by HTTP metrics, include the scope label to avoid double counting across
> instrumentation scopes. See [docs/observability.md](../observability.md) for migration
> guidance for dashboards/alerts.

## 3. OpenTelemetry trace export

Traces and metrics are exported over OTLP gRPC. Configuration:

```yaml
statuslist:
  env:
    APP_TELEMETRY__ENABLED: "true"
    APP_TELEMETRY__ENVIRONMENT: "production" # "production" enables OTLP export
    APP_TELEMETRY__OTLP_ENDPOINT: "http://<collector>.svc.cluster.local:4317"
    APP_TELEMETRY__SAMPLER_RATIO: "1.0"
```

When the chart's `opentelemetry-collector` subchart is **enabled** (default), the chart
**overrides** `APP_TELEMETRY__ENABLED=true` and sets `APP_TELEMETRY__OTLP_ENDPOINT` to the
in-cluster collector service (`http://<release>-opentelemetry-collector.<ns>.svc.cluster.local:4317`).
When the collector is **disabled**, `APP_TELEMETRY__ENABLED` defaults to `false`.

The bundled collector runs as a Deployment configured (by default) with a **`debug`
exporter** — spans/metrics show in the collector's stdout. To ship to a real backend
(Jaeger, Tempo, Datadog, ...), override `opentelemetry-collector.config` in your values:

```yaml
opentelemetry-collector:
  config:
    exporters:
      otlp/backend:
        endpoint: "jaeger.example.com:4317"
        tls: { insecure: true }
    service:
      pipelines:
        traces:
          exporters: [otlp/backend, debug]
        metrics:
          exporters: [otlp/backend, debug]
```

You can also disable the bundled collector and point `APP_TELEMETRY__OTLP_ENDPOINT` at an
external OTLP endpoint. See [docs/observability.md](../observability.md) for the full
OpenTelemetry wiring and Prometheus/OTel label migration.

## 4. What to alert on

- `up` / pod readiness: `/health/ready` coverage.
- `cert_renewal_failures` rising, or `cert_last_successful_renewal_timestamp` older than
  the renewal cadence → **rotation/renewal is broken**; tokens may expire.
- `vault_auth_renewals_total` / failure counters → Vault/OpenBao auth degraded.
- HTTP 5xx rate and request latency → capacity/backend issues (see
  [07-scaling-and-availability.md](07-scaling-and-availability.md)).
- DB pool saturation (acquire timeouts or connection errors in logs) → recheck pool sizing.

## 5. Local observability stack

For local development, `docker compose up -d` provisions a collector, Prometheus, and
Jaeger alongside the server:

- Server: `http://localhost:8000`, metrics `http://localhost:8000/metrics`
- Prometheus UI: `http://localhost:9090`
- Jaeger UI: `http://localhost:16686`
- Collector: `localhost:4317` (grpc) / `4318` (http) / `8889` (prometheus exporter)

## Related

- [04-configuration-reference.md](04-configuration-reference.md) — all `APP_TELEMETRY__*` and `APP_SERVER__*METRICS` variables.
- [06-secret-rotation.md](06-secret-rotation.md) — the rotation metrics you are observing.
- [docs/observability.md](../observability.md) — deep dive on OTel wiring and label migration.
