# Runbook: Token Generation

Alerts:

- `TokenGenerationFastBurn` (severity=page)
- `TokenGenerationSlowBurn` (severity=warn)

## What fired

The fraction of status-list token-generation attempts that failed exceeded the
0.5% SLO (fast burn >= 14.4x / slow burn >= 1x). Token generation failing means
clients cannot read a status list — it is an outage SLI and pages.

## Ranked likely causes

1. **Signing material backend down** — `signing_key_pem()` / `certificate_chain()`
   fail (Vault, cloud KMS), so `build_status_list_token` errors on the first await.
2. **Cert chain unavailable** — no cert chain (`StatusListError::Unavailable`)
   makes every token generation fail.
3. **Serialization / crypto regression** — a bad release that breaks JWT/CWT
   signing or gzip encoding.
4. **Resource exhaustion** — `spawn_blocking` pool starvation under load, or an
   out-of-memory signing path.

## Diagnostics

```promql
# Failure rate + volume
sli:token_gen_failure_rate:5m
sum(rate(token_generation_failures_total{otel_scope_name="status-list-server"}[5m])) by (format)
sum(rate(token_generation_attempts_total{otel_scope_name="status-list-server"}[5m])) by (format)
# Backends on the path
sum(rate(db_query_errors_total{otel_scope_name="status-list-server"}[5m]))
```

```bash
docker compose logs app | grep -i -E "token|signing|certificate"
```

## Mitigation

1. Restore the signing-material backend; token generation recovers on the next
   successful attempt.
2. If the cert chain is missing, trigger `renew_cert_if_needed` / check the cert
   provider (see `cert-renewal.md`).
3. If it is a code regression, roll back to the previous release.
4. Confirm the failures are not a monitoring gap — e.g. a single issuer with a
   dead certificate driving the rate.

## Escalation

- Page: on-call. Reads are failing — escalate immediately if the backend is not
  restored in 30m.
- Warn: sustained degradation; review during business hours.
