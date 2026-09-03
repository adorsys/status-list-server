# Runbook: Error Budget Exhaustion

Alerts:

- `ErrorBudgetCritical` (severity=page)

## What fired

The 30d error budget (`sli:error_budget:success:30d`) dropped below 10% remaining.
This means the trailing 30-day 5xx rate is close to consuming the full 0.5%
budget. Unlike the fast/slow burn alerts (which fire on a _current_ burn rate),
this fires on the _cumulative_ window: the budget has largely been spent, so any
further degradation risks breaching the SLO for the month.

## Ranked likely causes

1. **Sustained or repeated incidents** — recurring 5xx across the window have
   accumulated; check the error-rate alert history.
2. **Elevated baseline error rate** — a persistent error source (e.g. a slow DB
   path or a misconfigured route) that never triggered a fast-burn page.
3. **Monitoring / budget calibration** — the 30d window is only trustworthy if
   Prometheus retains at least 31 days (`--storage.tsdb.retention.time=31d`);
   confirm retentention before acting on the value.

## Diagnostics

```promql
# Current trailing error rate and remaining budget
sli:error_rate:30d
sli:error_budget:success:30d
# 5xx contribution by route over the wiring window
sum(rate(http_server_requests_total{otel_scope_name="status-list-server",status_class="5xx"}[30d])) by (route)
```

```bash
# Recent server errors and the alert history
docker compose logs app | grep -i -E "internal error|server error"
```

## Mitigation

1. Identify the dominant error source (DB / token backend / route) and remediate
   it; see `error-rate.md`, `db-latency.md`, and `token-generation.md`.
2. Stop the bleed first — restore availability even before tuning the SLO.
3. Only after the regression is confirmed fixed and the leading 30d window is
   recovering should a target change be considered. SLO targets are defined in
   `observability/slo/README.md` (and mirrored in `recording.rules.yml` and the
   dashboard generator); change **all three in lockstep** under review.

## Escalation

- Page: on-call. The month's error budget is nearly exhausted — escalate if the
  dominant error source is not identified within 30m.
