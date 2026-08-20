# Observability & OpenTelemetry Guide

This document describes the telemetry, tracing, and metrics architecture in `status-list-server`, including configuration contracts, local development workflows, Kubernetes/Helm deployment wiring and Prometheus label migration.

## 1. Environment & Configuration Contract

Telemetry behavior is determined primarily by the deployment environment (`APP_ENV`), with explicit overrides available via environment variables:

| Environment Variable           | Allowed Values                     | Default                 | Description                                                                                                                        |
| ------------------------------ | ---------------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `APP_ENV`                      | `development`, `production`        | `development`           | Core environment selector. `development` outputs human-readable logs to stdout. `production` emits structured JSON logs to stdout. |
| `APP_TELEMETRY__ENABLED`       | `true`, `false`                    | `true`                  | Explicit toggle to enable or disable OpenTelemetry OTLP trace, metric, and log exporting.                                          |
| `APP_TELEMETRY__ENVIRONMENT`   | `development`, `production`        | (inherits `APP_ENV`)    | Explicit override for telemetry environment log formatting selection.                                                              |
| `APP_TELEMETRY__OTLP_ENDPOINT` | URL (e.g. `http://localhost:4317`) | `http://localhost:4317` | Target OTLP gRPC collector endpoint.                                                                                               |
| `APP_TELEMETRY__SAMPLER_RATIO` | Float `0.0` – `1.0`                | `1.0`                   | Trace sampling ratio (`1.0` = 100% sampling).                                                                                      |

> [!NOTE]
> Reusing `APP_ENV` guarantees that applications inheriting standard environment settings automatically use pretty stdout logging in development while exporting structured JSON OTLP data in production.

## 2. Helm Deployment Architecture & Wiring

When deploying via Helm (`helm/chart`), OpenTelemetry Collector integration is provided by the official
[`open-telemetry/opentelemetry-collector`](https://github.com/open-telemetry/opentelemetry-helm-charts/tree/main/charts/opentelemetry-collector)
subchart. Configuration is under the `opentelemetry-collector` key in `values.yaml`.

### `opentelemetry-collector.enabled` ↔ `APP_TELEMETRY__ENABLED` Relationship

Setting `.Values.opentelemetry-collector.enabled=true` automatically sets `APP_TELEMETRY__ENABLED="true"`
and wires `APP_TELEMETRY__OTLP_ENDPOINT` on the status-list-server application pod to the in-cluster
collector service:

```text
http://<release>-opentelemetry-collector.<namespace>.svc.cluster.local:<otlp-grpc-port>
```

The OTLP gRPC port is read from `opentelemetry-collector.ports.otlp.servicePort` (default `4317`).

### Deployment Mode

The collector runs as a `Deployment` (one replica, `mode: deployment` in `values.yaml`). This matches
the previous custom standalone deployment topology. Sidecar mode is not used.

### Configuring Exporters

The default `values.yaml` configures a `debug` exporter only (telemetry appears in collector stdout logs).
For production, override the `opentelemetry-collector.config` block in your environment-specific values
to add backend exporters, for example:

```yaml
opentelemetry-collector:
  # Expose the Prometheus exporter port on the Service so Prometheus can scrape it.
  # Without this ports entry, port 8889 exists only on the container but not on the Service.
  ports:
    prometheus:
      enabled: true
      containerPort: 8889
      servicePort: 8889
      protocol: TCP
  config:
    exporters:
      debug:
        verbosity: basic
      otlp/backend:
        endpoint: "jaeger.example.com:4317"
        tls:
          insecure: true
      prometheus:
        endpoint: "0.0.0.0:8889"
    service:
      pipelines:
        traces:
          exporters: [otlp/backend, debug]
        metrics:
          exporters: [prometheus, debug]
```

> [!NOTE]
> Exposing the Prometheus port via `ports.prometheus` makes it reachable inside the cluster, but Prometheus still needs to discover it. Either add `prometheus.io/scrape: "true"` pod annotations (if using annotation-based discovery) or create a `ServiceMonitor` / `PodMonitor` (if using the Prometheus Operator).

Default values reference: <https://github.com/open-telemetry/opentelemetry-helm-charts/blob/main/charts/opentelemetry-collector/values.yaml>

### Network Policy Considerations

When `statuslist.networkPolicy.enabled=true` is set:

- **Egress** from the status-list-server pod to the collector on OTLP ports `4317` (gRPC) and `4318` (HTTP) is explicitly allowed.
- The status-list-server pod does **not** receive inbound traffic on collector ports.

## 3. Local Development Workflow

### Running the Observability Stack

In local development, Docker Compose provisions an OpenTelemetry Collector, Prometheus, and Jaeger instance alongside the server. The application runs in `development` mode (human-readable stdout logs) with `APP_TELEMETRY__ENABLED=true` exporting OTLP traces to Jaeger:

```bash
docker compose up -d
```

Services provisioned for observability:

- **Status List Server**: `http://localhost:8000`
- **Prometheus Metrics**: `http://localhost:8000/metrics`
- **Prometheus UI**: `http://localhost:9090`
- **Jaeger UI**: `http://localhost:16686`
- **OTLP Collector**: `localhost:4317` (gRPC) / `localhost:4318` (HTTP) / `localhost:8889` (Prometheus metrics exporter)

### Inspecting Traces in Jaeger

1. Open `http://localhost:16686` in your browser.
2. Select Service: `status-list-server`.
3. Click **Find Traces** to view distributed trace timelines, spans, and attributes.

## 4. Prometheus Metric Label Migration

Metrics are exported via the in-process Prometheus exporter (`opentelemetry-prometheus`).

### Scope Label (`otel_scope_name`)

Metrics recorded through OpenTelemetry include the instrumentation scope label:

```prometheus
otel_scope_name="status-list-server"
```

#### Migration Guidance for Existing Dashboards & Alerts

If you have existing Grafana dashboards or Prometheus alerting rules:

- **Aggregations**: Ensure queries grouping by labels either aggregate over `otel_scope_name` or specify `{otel_scope_name="status-list-server"}` to avoid double-counting if multiple instrumentation scopes exist.
- **Example Query Update**:

  ```promql
  # Before
  sum(rate(axum_http_requests_duration_seconds_count[5m])) by (status)

  # After
  sum(rate(axum_http_requests_duration_seconds_count{otel_scope_name="status-list-server"}[5m])) by (status)
  ```

## 5. Trace Retention & Privacy Posture

In accordance with [IETF OAuth Status List (draft-21 §12.7 - Privacy Considerations)](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-12.7):

- **Attribute Scoping**: Spans record operational metadata such as `list_id` and `issuer` to facilitate debugging and error tracking. Personally identifiable information (PII) or subject identity details must not be captured in trace attributes.
- **Trace Retention**: In alignment with the historical snapshot retention guidelines, production trace storage (e.g. in Jaeger or Tempo) should apply retention policies matching data minimization principles (e.g. purging trace data past the configured operational window).
