# Runbook: Error Rate

Alerts:

- `ErrorRateFastBurn` (severity=page)
- `ErrorRateSlowBurn` (severity=warn)

## What fired

The fraction of requests returning 5xx exceeded the 0.5% SLO (fast burn >=
14.4x over a 1h+6h window / slow burn >= 6x over a 6h window). A page means
clients are consistently getting server errors.

## Ranked likely causes

1. **DB unavailable / failing** — `get_status_list` returns 5xx on DB failure.
   A DB outage surfaces here before the DB-latency alert necessarily does.
2. **Backend failure for token material** — signing key/cert backend (Vault,
   cloud KMS) failures make `build_status_list_token` fail → 500s.
3. **Out-of-disk / panic reopening** — `CatchPanicLayer` + internal errors.
4. **Misconfigured route exposed** — a broken historical query path failing.

## Diagnostics

```promql
# 5xx by route
sum(rate(http_server_requests_total{otel_scope_name="status-list-server",status_class="5xx"}[5m])) by (route)
# Is the total request volume stable (traffic spike vs genuine errors)?
sum(rate(http_server_requests_total{otel_scope_name="status-list-server"}[5m]))
# Token-gen + DB backends
sli:token_gen_failure_rate:5m
sli:db_query_latency:p95:5m
```

```bash
# Recent server errors in logs
docker compose logs app | grep -i -E "internal error|server error"
```

## Mitigation

1. If it is a DB outage: restore DB connectivity (see `db-latency.md` for
   recovery steps).
2. If signing-key backend is the cause, restore that backend; token generation
   recovers automatically once it returns.
3. Confirm the errors are genuinely server-side (500/502/503 story driving the
   5xx class) and not a monitoring label gap.
4. If a bad release introduced errors, roll back; if a config change did, revert
   it.

## Escalation

- Page: on-call. Escalate on unresolved client-facing 5xx after 30m.
- Warn: review during business hours.
