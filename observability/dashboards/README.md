# Dashboards (as code)

The SLO dashboard is defined in code and committed under `generated/` so Grafana
always loads the reviewed artifact (no manual import).

## Layout

- `src/` — the deterministic generator (`generate.mjs`) + `package.json`.
- `generated/status-list-slo.json` — the committed dashboard Grafana loads.
- `provisioning/` — file-provider and datasource configs consumed by Grafana on
  startup (mounted by `docker-compose.yml`).

## Regenerate 

```bash
cd observability/dashboards/src
npm install        # first time only (no third-party deps)
npm run generate-dashboards   # rewrites ../generated/status-list-slo.json
```

The output is byte-for-byte stable, so a reviewable diff appears in the committed
JSON whenever a panel's intent changes. **Commit both** the generator change and
the regenerated JSON together.

## Panels

All panels query the Phase 3 recording rules (`sli:*`), never raw /metrics, so
dashboards and alerts share identical numbers:

- Four golden-signal row: request latency p95, error rate, error budget, DB p95.
- Drill-down row: cache hit ratio, cert renewal failure, token-gen failure.

## Grafana provisioning

- `provisioning/datasources.yml` — Prometheus datasource pointing at
  `http://prometheus:9090`.
- `provisioning/dashboards.yml` — file provider watching
  `/var/lib/grafana/dashboards` (which mounts the `generated/` dir in compose).
