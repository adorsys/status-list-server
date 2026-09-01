# Runbook: Certificate Renewal

Alerts:

- `CertRenewalFailures` (severity=warn) — fires when the certificate expires
  within 14 days (`cert_time_to_expiry_seconds <= 14d`): the renewal loop is not
  refreshing the certificate and there is runway to intervene.
- `CertRenewalErrorBudgetCritical` (severity=page) — fires when the certificate
  expires within 7 days (`cert_time_to_expiry_seconds <= 7d`): imminent expiry,
  the certificate will be invalid for TLS handshakes unless action is taken
  immediately.

## What fired

Wallet renewals run on a low-frequency cycle (every few days to weeks, governed
by the renewal strategy), not a continuous stream, so a `rate()` of the
`cert_renewal_failures_total` / `cert_renewal_attempts_total` counters over a
fixed window is `0/0 = NaN` whenever no renewal happened in the window and can
never fire reliably.

The firing alerts therefore watch the **continuous** `cert_time_to_expiry_seconds`
gauge, which is emitted on every renewal/refresh and drops monotonically toward 0
while renewals fail to keep the certificate fresh. This is the deterministic,
actionable signal: when it crosses the interval thresholds, the certificate is
not being re-signed.

## Ranked likely causes

1. **ACME / DNS challenge failure** — the DNS-01 or HTTP-01 challenge handler
   (Route53, Cloudflare, GCloud, Azure, acme-dns, Pebble) could not satisfy the
   CA. Bad DNS credentials, rate limits, or provider outage.
2. **Secrets/material backend outage** — the signing-key storage (Vault, cloud
   KMS) is unavailable, so the new key cannot be persisted.
3. **Rate limiting from the CA** — too many orders against the ACME directory.
4. **Renewal scheduler stopped** — the scheduler task crashed or was disabled, so
   renewal simply stopped firing.

## Diagnostics

```promql
# Remaining time before the certificate is invalid (seconds).
cert_time_to_expiry_seconds{otel_scope_name="status-list-server"}
# When the last successful renewal happened.
cert_last_successful_renewal_timestamp{otel_scope_name="status-list-server"}
# Renewal activity over the past month (informational).
sum(increase(cert_renewal_attempts_total{otel_scope_name="status-list-server"}[30d]))
sum(increase(cert_renewal_failures_total{otel_scope_name="status-list-server"}[30d]))
```

```bash
# Renewal activity via logs
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
   confirm `cert_time_to_expiry_seconds` rises back above the alert threshold,
   which also advances `cert_last_successful_renewal_timestamp`.

## Escalation

- Warn (≤14d): no page. Root-cause and fix before the certificate expires.
- Page (≤7d): treat as imminent-expiry incident. The certificate will stop being
  valid for TLS handshakes; follow the ACME recovery path immediately and, if the
  renewal cannot be restored in time, plan a manual re-issue of the certificate.
