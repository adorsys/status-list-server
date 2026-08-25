# Runbook: Certificate Renewal

Alert:

- `CertRenewalFailures` (severity=warn)

## What fired

The certificate-renewal failure rate reached 1% over 15m. Renewal runs on a
cron; this is operational risk (a certificate about to expire), not an outage —
so it is warn-only.

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
sum(rate(cert_renewal_failures_total{otel_scope_name="status-list-server"}[15m]))
sum(rate(cert_renewal_attempts_total{otel_scope_name="status-list-server"}[15m]))
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
