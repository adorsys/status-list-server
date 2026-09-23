# Runbook: Cache Hit Ratio

Alert:

- `CacheHitRatioLow` (severity=warn)
- `RedisCacheStartupError` (severity=warn)

## What fired

The status-list read cache hit ratio fell below 85% over 15m. This is a
**degradation**, not an outage: reads still succeed, but each miss costs a DB
round trip. It pages only through review (warn).

## Ranked likely causes

1. **Cache TTL too short** — `cache.ttl` expires entries before they are
   re-read; a low TTL guarantees a low hit ratio under a sparse-read workload.
2. **Cardinality spike** — a burst of distinct `list_id`s exceeds
   `cache.max_capacity`, thrashing the selected cache backend (evictions).
3. **Cache disabled** — `cache.ttl == 0` disables the cache entirely (hit ratio
   drops to ~0).
4. **Process restarts** — every restart warms the in-process cache from empty.
5. **Redis startup/connectivity errors** — Redis-backed pods continue serving
   with cache misses while the lazy Redis connection manager reconnects; Redis
   invalidation resumes once Redis is reachable.

## Diagnostics

```promql
# Constant-time hit/miss rates
sum(rate(status_list_cache_hits_total{otel_scope_name="status-list-server"}[15m]))
sum(rate(status_list_cache_misses_total{otel_scope_name="status-list-server"}[15m]))
# Current ratio
sli:cache_hit_ratio:5m
# Redis startup/connectivity errors
sum(status_list_cache_errors_total{otel_scope_name="status-list-server",operation="startup"})
# Confirms whether slow reads are cache-induced
sli:db_query_latency:p95:5m
```

```bash
# Does the config disable the cache?
grep -i cache .env 2>/dev/null
```

## Mitigation

1. If TTL is the cause and the data allows it, raise `cache.ttl` / raise
   `cache.max_capacity`; redeploy.
2. If eviction-driven, right-size `max_capacity` to the concurrent distinct-list
   working set.
3. Re-check after a restart warm-up (the ratio recovers over ~one TTL period).
4. If Redis errors are present, verify Redis DNS, credentials, TLS mode, and
   NetworkPolicy `cacheEgress`; the Redis cache backend reconnects lazily once
   Redis is reachable.

## Escalation

- Warn: no page. Track in the SLO review; escalate to the service owner if the
  cache was deliberately disabled and the resulting DB load is a risk.
