# Runbook: Request Latency

Alerts:

- `RequestLatencyFastBurn` (severity=page)
- `RequestLatencySlowBurn` (severity=warn)

## What fired

The p95 request latency over both the 1h and 6h windows exceeded the 300 ms SLO
(fast burn), or the 6h p95 exceeded 300 ms sustained (slow burn). A page means
the service's latency target is being breached for a sustained period — either
a single slow path or a broad degradation.

## Ranked likely causes

1. **DB latency** — every cache miss does a DB round trip; a slow DB drags the
   read path. Check the DB latency panel/alert first.
2. **CPU/saturation** — token generation is CPU-bound (JWT/CWT signing + gzip).
   Sustained request volume or a noisy neighbour (CPU throttling) raises p95.
3. **Network / upstream** — ACME/signing-key backend (Vault, cloud KMS) latency
   is on the token path; a slow secrets backend stalls reads.
4. **Rate-limiter misconfiguration** — a too-aggressive governor adds
   queueing/delays rather than clean 429s.

## First diagnostics

```promql
# Which routes are slow?
histogram_quantile(0.95, sum(rate(http_server_duration_seconds_bucket{otel_scope_name="status-list-server"}[5m])) by (route, le))
# DB parallel?
sli:db_query_latency:p95:5m
# Process saturation
rate(process_cpu_seconds_total[1m])
```

```bash
# Local stack: inspect live latency distribution
curl -s http://localhost:8000/metrics | grep http_server_duration_seconds_bucket
```

## Mitigation

1. Resolve the underlying cause (DB / CPU / upstream) before scaling.
2. If DB latency is the trigger, follow `db-latency.md`; if CPU-bound, check for
   request spikes and re-balance the token signing path.
3. If a single route is implicated, confirm the route pattern is bounded
   (no unaggregated path-parameter labels inflating p95).
4. Only widen the SLO after confirming the regression is truly retuned and the
   30d budget has headroom — change `observability/slo/README.md` (with its
   rationale for the 300 ms target and its consistency requirements) with the rule.

## Escalation

- Page: on-call for status-list-server. If unknown or uncontained after 30m,
  escalate to the platform/DB on-call.
- Warn: review during business hours.
