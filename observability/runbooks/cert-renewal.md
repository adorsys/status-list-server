# Runbook: Certificate Renewal

Alerts:

- `CertRenewalFailures` (severity=warn) — fires when the renewal failure rate is
  at/above 1% over the last 7 days.
- `CertRenewalErrorBudgetCritical` (severity=page) — fires when the renewal
  failure rate is at/above 50% over the 30-day window (the renewal loop is
  broken and the certificate will expire).

## What fired

Wallet renewals run on a low-frequency cycle (every few days, governed by the
renewal strategy), not a continuous stream, so short `rate` windows are
meaningless. `CertRenewalFailures` therefore uses a 7-day window that is
guaranteed to observe a full renewal cycle. `CertRenewalErrorBudgetCritical`
pages only when >=50% of renewals over 30 days have failed — a single transient
failure (e.g. 1 of ~30 renewals) raises the warn alert but does not page on-call.

## Ranked likely causes

1. **ACME / DNS challenge failure** — the DNS-01 or HTTP-01 challenge handler
   (Route53, Cloudflare, GCloud, Azure, acme-dns, Pebble) could not satisfy the
   CA. Bad DNS credentials, rate limits, or provider outage.
2. **Secrets/material backend outage** — the signing-key storage (Vault, cloud
   KMS) is unavailable, so the new key cannot be persisted.
3. **Rate limiting from the CA** — too many orders against the ACME directory.
4. **Clock skew / validity parse** — certificate parse failures on
   `cert_renewal_*` counters.

## Diagnostics

```promql
sum(rate(cert_renewal_failures_total{otel_scope_name="status-list-server"}[7d]))
sum(rate(cert_renewal_attempts_total{otel_scope_name="status-list-server"}[7d]))
```

```bash
# Rename via logs
docker compose logs app | grep -i -E "renew|acme|challenge"
# Manual renewal attempt triggers the scheduler
curl -f http://localhost:8000/health/ready
```

## Mitigation

1. Confirm the ACME account / DNS credentials are valid and un-expired.
2. Test the DNS challenge path the handler uses; fix the provider config.
3. Ensure the material backend is reachable so the new key persists; otherwise
   the renewal will not stick.
4. After fixing, trigger a renewal (`renew_cert_if_needed`) or wait for the cron;
   `cert_last_successful_renewal_timestamp` should advance.

## Escalation

- Warn: no page. Escalate before the certificate actually expires — check
  `cert_time_to_expiry_seconds`; if expiry is imminent, treat as page-worthy and
  follow the ACME recovery path immediately.
