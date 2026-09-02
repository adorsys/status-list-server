# Status List Server — Helm Chart

This directory contains the Helm chart for the **Status List Server**. It bundles the
application Deployment plus PostgreSQL and an OpenTelemetry collector as dependencies.

## Deploy the server

Follow the [Operator Deployment Guide](DEPLOYMENT.md) — a single-page, step-by-step guide
(prerequisites → image choice → secrets → `helm` install → verification) that requires no
understanding of the server's internals. The detailed operator documentation and deep-dive
references are linked from that page.

## Chart essentials

- [`chart/values.yaml`](chart/values.yaml) — the single source of truth for every Helm value.
- [`chart/values-local.yaml`](chart/values-local.yaml) — working local-cluster configuration
  (see the [Operator Deployment Guide](DEPLOYMENT.md) for how to use it).
- [`chart/values-external-secrets.yaml`](chart/values-external-secrets.yaml) and
  [`chart/values-production.yaml`](chart/values-production.yaml) — additional reference values.
- The chart's image, service, ingress, secrets, autoscaling, and observability settings are
  documented in [`chart/values.yaml`](chart/values.yaml) and described in the
  [Operator Deployment Guide](DEPLOYMENT.md).

For the technical architecture behind the chart, see
[`../docs/deployment-architecture.md`](../docs/deployment-architecture.md).
