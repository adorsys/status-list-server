# Runbook: DB Latency

Alerts:

- `DbLatencyFastBurn` (severity=page)
- `DbLatencySlowBurn` (severity=warn)

## What fired

The p95 DB query latency over the 1h and 6h windows exceeded the 50 ms SLO.
Because reads are cached, every cache miss pays this directly — a slow DB also
lowers the cache hit ratio and raises HTTP latency.

## Ranked likely causes

1. **DB saturation / pool exhaustion** — connection pool at `max_connections`;
   acquire timeouts.
2. **Missing index / slow query** — especially the historical snapshot lookup
   (`find_valid_at` scans `idx_status_list_history_exp`); the retention sweep
   (`delete_older_than`) can contend on the same index.
3. **Lock contention** — a busy write path (publish/update) blocking reads;
   write rollbacks show in `db_write_contention`.
4. **DB host degradation** — CPU/disk/network on the Postgres/MySQL host.

## Diagnostics

```promql
# Which operation is slow?
histogram_quantile(0.95, sum(rate(db_query_duration_seconds_bucket{otel_scope_name="status-list-server"}[5m])) by (operation, le))
# Error rate redistribution
sum(rate(db_query_errors_total{otel_scope_name="status-list-server"}[5m])) by (operation)
# Contention
sum(rate(db_write_contention_total[5m]))
```

```sql
-- (Postgres) top wait / slow queries
SELECT pid, state, wait_event_type, wait_event, query
FROM pg_stat_activity WHERE state <> 'idle';
```

## Mitigation

1. If pool-exhausted: raise `database.pool.max_connections` at the server and
   confirm the DB allows it; otherwise check for a connection leak (idle
   connections not released).
2. If the retention sweep contends: verify `history_retention_secs` is sane and
   the sweep is not overlapping writes; consider a maintenance window.
3. If a query is slow: add/extend the targeted index, then re-run the panel.
4. If DB host saturated: scale the DB instance (vertical) or offload the
   historical sweep.

## Escalation

- Page: on-call. Escalate to the database/platform on-call if pool or host
  saturation is not resolved in 30m.
- Warn: review during business hours.
