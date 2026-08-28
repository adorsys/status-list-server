# Startup Validation and Fail-Fast Production Configuration

This document catalogs mandatory production configuration validations and their failure behaviors. The server uses a **fail-fast** philosophy: misconfigurations that would prevent safe operation are detected at startup, causing immediate termination with a descriptive error rather than deferred runtime failures.

## Validation Summary by Component

### Legend

- **Fatal**: Server exits immediately during startup; process terminates with non-zero exit code
- **Readiness**: Server starts but reports `NOT_READY` (503) on `/health/ready` endpoint
- **Warning**: Logged but does not block startup or readiness
- **Secret**: Value is wrapped in `SecretString` and never exposed in error messages

---

## 1. Database Validations

<!-- markdownlint-disable MD060 -->

| Config Key | Required Condition | Failure Behavior | Readiness Behavior | Remediation |
|------------|-------------------|------------------|-------------------|-------------|
| `database.backend` | Must be one of: `memory`, `postgres`, `mysql`, `sqlite` | **Fatal**: Config parsing fails with unknown variant error | N/A | Set to valid backend enum matching your deployment |
| `database.url` | Non-empty string with valid URL format | **Fatal**: Config parsing fails | N/A | Configure connection string (e.g., `postgres://user:pass@host:5432/db`) |
| `database.url` | URL scheme must match `database.backend` | **Fatal**: `eyre!` error: "URL scheme does not match configured backend" | N/A | Ensure URL prefix matches backend (e.g., `postgres://` for Postgres backend) |
| `database.url` | Credential secrets must be valid | **Fatal**: Connection failure | N/A | Verify database credentials; check secret injection via Helm/external-secrets |
| `database.pool.max_connections` | Positive integer | **Fatal**: Config parsing fails | N/A | Set to `floor(pg_max_connections / replicas) - headroom` |
| `database.pool.min_connections` | Positive integer ≤ `max_connections` | **Fatal**: Config parsing fails | N/A | Set to `1` for typical workloads |
| Database (MySQL) | All tables must use InnoDB engine | **Fatal**: `eyre!` error with ALTER TABLE fix command | N/A | Run `ALTER TABLE ... ENGINE=InnoDB` on non-InnoDB tables |
| Database (MySQL) | `binlog_format` must be `ROW` or `MIXED` | **Fatal**: `eyre!` error: "binary logging is incompatible" | N/A | Execute `SET GLOBAL binlog_format = 'ROW'` and restart MySQL |
| Database (all SQL) | Connection must succeed | **Fatal**: `eyre!` error: "Failed to connect to database" | N/A | Check network connectivity, credentials, TLS settings |
| Database (all SQL) | Migrations must succeed | **Fatal**: `eyre!` error: "Failed to run database migrations" | N/A | Check migration logs; verify database user has DDL permissions |
| Database connectivity | Ping must succeed post-startup | N/A | **NOT_READY**: "database unreachable: {error}" | Check database health, network policies, credential expiry |

<!-- markdownlint-enable MD060 -->

**Secret Redaction**: The database URL (containing credentials) is stored as `SecretString`. Connection failure errors redact the password portion; only the scheme and host are visible in logs

---

## 2. Secrets Backend Validations

The cryptographic material backend (signing keys, certificates) is selected by compile-time feature flags. One backend is active based on feature precedence.

<!-- markdownlint-disable MD060 -->

| Config Key | Required Condition | Failure Behavior | Readiness Behavior | Remediation |
|------------|-------------------|------------------|-------------------|-------------|
| `vault.addr` (Vault/OpenBao) | Non-empty valid URL when `vault` feature enabled | **Fatal**: Config parsing or connection failure | N/A | Set to Vault/OpenBao API endpoint (e.g., `http://vault:8200`) |
| `vault.auth_method` | Must be `approle` or `kubernetes` | **Fatal**: Config parsing fails with unknown variant | N/A | Use `approle` for machine auth, `kubernetes` for pod auth |
| `vault.role_id` (AppRole) | Non-empty string when `auth_method=approle` | **Fatal**: `eyre!` error: "requires 'role_id' to be configured" | N/A | Configure via Helm `values.yaml` or ExternalSecrets |
| `vault.secret_id` XOR `vault.secret_id_path` (AppRole) | At least one must be non-empty | **Fatal**: `eyre!` error: "missing secret_id: provide 'secret_id' or 'secret_id_path'" | N/A | Mount secret via Kubernetes volume or inject via ExternalSecrets |
| `vault.secret_id_path` (AppRole) | File must exist and contain non-empty content | **Fatal**: `eyre!` error with file path | N/A | Verify volume mount and secret injection |
| `vault.k8s_role` (Kubernetes) | Non-empty string when `auth_method=kubernetes` | **Runtime Fatal**: `eyre!` error: "Vault auth_method=kubernetes requires 'k8s_role' to be configured" | N/A | Configure Vault Kubernetes auth role |
| `vault.k8s_token_path` (Kubernetes) | File must exist at path | **Runtime Fatal**: Token read failure during login | N/A | Verify projected ServiceAccount token volume mount |
| `vault.mount` | Non-empty mount path (default: `secret`) | **Fatal**: Config parsing or Vault API error | N/A | Configure KV v2 engine mount path |
| Vault connectivity | Login must succeed | **Fatal**: Vault client build failure | **NOT_READY**: "cryptographic-material backend unreachable" | Check Vault TLS, namespace, auth credentials |
| `gcp_secret_manager.project_id` | Non-empty when `gcp-secrets` feature enabled (no `vault`) | **Runtime Fatal**: Client initialization error | N/A | Set GCP project ID; ensure Workload Identity or ADC configured |
| `gcp_secret_manager.service_account_key` OR `service_account_key_path` | At least one valid credential when not using ADC | **Runtime Fatal**: Authentication failure | N/A | Configure service account key or ensure GKE Workload Identity |
| `gcp_secret_manager.allow_anonymous_credentials` | Must be `true` for emulator/testing; not for production | **Warning**: Logs anonymous credential use | N/A | Enable only for local testing with GCP emulator |
| `azure_keyvault.vault_url` | Non-empty valid URL when `azure-kv` feature enabled (no `vault`, `gcp-secrets`). *Note: Optional in config, validated at runtime* | **Fatal**: `eyre!` error: "Azure Key Vault configuration error: azure_keyvault.vault_url is required when azure-kv is enabled" | N/A | Set Azure Key Vault URL |
| `azure_keyvault.tenant_id` | Non-empty for Service Principal auth. *Note: Optional in config, validated at runtime* | **Runtime Fatal**: Authentication failure | N/A | Configure Azure AD tenant ID |
| `azure_keyvault.client_id` | Non-empty for Service Principal auth. *Note: Optional in config, validated at runtime* | **Runtime Fatal**: Authentication failure | N/A | Configure Azure AD application/client ID |
| `azure_keyvault.client_secret` | Non-empty for Service Principal auth. *Note: Optional in config, validated at runtime* | **Runtime Fatal**: Authentication failure | N/A | Configure via ExternalSecrets; never commit to Git |
| AWS Secrets Manager | `aws.region` must be valid | **Runtime Fatal**: AWS SDK configuration error | N/A | Set valid AWS region (e.g., `us-east-1`, `eu-central-1`) |
| AWS Secrets Manager | IAM credentials or IRSA must be valid | **Runtime Fatal**: AWS auth failure | N/A | Verify IRSA annotation or IAM credentials |

<!-- markdownlint-enable MD060 -->

**Secret Redaction**: All secret fields (`vault.secret_id`, `vault.secret_id_path` file contents, `azure_keyvault.client_secret`, `gcp_secret_manager.service_account_key`, ACME-DNS passwords) are stored as `SecretString`. Error messages never expose these values; they reference the configuration key name only.

---

## 3. Certificate Provisioning Validations

<!-- markdownlint-disable MD060 -->

| Config Key | Required Condition | Failure Behavior | Readiness Behavior | Remediation |
|------------|-------------------|------------------|-------------------|-------------|
| `server.cert.provisioning_strategy` | Must be `acme` or `store` | **Fatal**: `eyre!` error: "unsupported certificate provisioning strategy" | N/A | Use `acme` for Let's Encrypt; `store` for pre-provisioned certs |
| `server.cert.email` | Non-empty valid email | **Warning**: Some ACME CAs may reject | N/A | Set to valid contact email for ACME registration |
| `server.cert.acme_directory_url` | Non-empty valid URL when `provisioning_strategy=acme` | **Fatal**: ACME client initialization failure | N/A | Use `https://acme-v02.api.letsencrypt.org/directory` for production |
| `server.cert.renewal_cron_schedule` | Valid 6-field cron expression | **Fatal**: Config parsing fails | N/A | Use format: `sec min hour day month day-of-week` (e.g., `0 0 0 * * *` for daily at midnight) |
| `server.cert.signing_key_cache_ttl` | Non-negative integer (0 disables cache) | **Fatal**: Config parsing fails | N/A | Set to `0` to force backend reads; `300` for 5-minute cache |
| Store strategy: `server.cert.store.certificate_path` | Valid filesystem path readable by container | **Fatal** (if configured): `eyre!` error | N/A | Mount certificate via Kubernetes secret or projected volume |
| Store strategy: `server.cert.store.signing_key_path` | Valid filesystem path readable by container | **Fatal** (if configured): `eyre!` error | N/A | Mount private key via Kubernetes secret; ensure restricted permissions |
| Store strategy: `server.cert.store.certificate_key` | Valid key in secrets backend | **Readiness Failure**: Backend lookup fails | **NOT_READY**: "cryptographic-material backend unreachable" | Ensure key exists in Vault/AWS/GCP/Azure |
| Store strategy: `server.cert.store.signing_key_key` | Valid key in secrets backend | **Readiness Failure**: Backend lookup fails | **NOT_READY**: "cryptographic-material backend unreachable" | Ensure key exists in secrets backend |
| Store strategy validation | Must configure filesystem XOR storage keys, not both | **Fatal**: `eyre!` error: "store provisioning must configure either filesystem paths or material backend keys, not both" | N/A | Remove one configuration method |
| Store strategy validation | Filesystem requires both cert AND key paths | **Fatal**: `eyre!` error: "filesystem store provisioning requires both server.cert.store.certificate_path and server.cert.store.signing_key_path" | N/A | Configure both paths |
| Store strategy validation | Storage-backed requires both cert AND key keys | **Fatal**: `eyre!` error: "storage-backed store provisioning requires both server.cert.store.certificate_key and server.cert.store.signing_key_key" | N/A | Configure both keys |
| Filesystem certs (non-ACME) | Files must exist and be readable | N/A | **NOT_READY**: "cert store file '{path}' unavailable" or "not readable" | Verify volume mounts, file permissions (should be 0600 for keys) |

<!-- markdownlint-enable MD060 -->

**Secret Redaction**: Paths to certificate files are logged; private key paths and secret backend keys are referenced by name only. File contents are never logged.

---

## 4. DNS Provider Validations (ACME Only)

<!-- markdownlint-disable MD060 -->

| Config Key | Required Condition | Failure Behavior | Readiness Behavior | Remediation |
|------------|-------------------|------------------|-------------------|-------------|
| `server.cert.dns.provider` | Must be one of: `route53`, `cloudflare`, `gcloud`, `azure`, `acmedns`, `pebble` (dev only) | **Fatal**: Config parsing fails with unknown variant | N/A | Set valid DNS provider matching your DNS infrastructure |
| `server.cert.dns.provider` | Valid provider selected for environment | **Warning**: "The 'pebble' DNS provider is a development-only fake DNS server but APP_ENV=production" | N/A | Use `route53` (default), `cloudflare`, `gcloud`, `azure`, or `acmedns` in production |
| **Cloudflare** `server.cert.dns.cloudflare.api_token` | Non-empty API token with Zone:Read and DNS:Edit | **Fatal**: `eyre!` error: "have an empty api_token" | N/A | Create token in Cloudflare dashboard; mount via ExternalSecrets |
| **Google Cloud** `server.cert.dns.gcloud.service_account_key` OR `service_account_key_path` | Valid service account JSON key | **Fatal**: `eyre!` error: "settings are missing" | N/A | Create DNS admin service account; mount key via Kubernetes secret |
| **Azure DNS** `server.cert.dns.azure.tenant_id` | Non-empty string | **Fatal**: `eyre!` error listing empty fields | N/A | Configure Azure AD tenant ID |
| **Azure DNS** `server.cert.dns.azure.client_id` | Non-empty string | **Fatal**: `eyre!` error listing empty fields | N/A | Configure Azure AD application/client ID |
| **Azure DNS** `server.cert.dns.azure.client_secret` | Non-empty secret string | **Fatal**: `eyre!` error listing empty fields | N/A | Configure via ExternalSecrets; never hardcode |
| **Azure DNS** `server.cert.dns.azure.subscription_id` | Non-empty string | **Fatal**: `eyre!` error listing empty fields | N/A | Configure Azure subscription ID |
| **Azure DNS** `server.cert.dns.azure.resource_group` | Non-empty string | **Fatal**: `eyre!` error listing empty fields | N/A | Configure resource group holding DNS zones |
| **ACME-DNS** `server.cert.dns.acmedns.server_url` | Non-empty valid HTTPS URL | **Fatal**: `eyre!` error: "have an empty server_url" | N/A | Deploy ACME-DNS server; configure URL |
| **ACME-DNS** `server.cert.dns.acmedns.username` | Non-empty (if using default account) | **Fatal**: `eyre!` error: "must be set together" | N/A | Configure username from ACME-DNS registration |
| **ACME-DNS** `server.cert.dns.acmedns.password` | Non-empty secret (if using default account) | **Fatal**: `eyre!` error: "must be set together" | N/A | Configure via ExternalSecrets |
| **ACME-DNS** `server.cert.dns.acmedns.subdomain` | Non-empty (if using default account) | **Fatal**: `eyre!` error: "must be set together" | N/A | Configure subdomain from ACME-DNS registration |
| **ACME-DNS** `server.cert.dns.acmedns.accounts` | Map of domain → account credentials | **Fatal**: `eyre!` error if entry has empty fields or invalid domain key | N/A | Configure per-domain accounts as JSON; ensure wildcard domains use base domain as key |
| **ACME-DNS** Domain coverage | All certificate domains must have matching account | **Fatal**: ACME-DNS order domain check failure | N/A | Ensure CNAME records point `_acme-challenge.<domain>` to ACME-DNS fulldomain |
| **Route53** IAM permissions | `route53:ListHostedZones`, `route53:ChangeResourceRecordSets`, `route53:GetChange` | **Runtime Fatal**: AWS API permission denied | N/A | Attach IAM policy with required permissions; use IRSA in EKS |

<!-- markdownlint-enable MD060 -->

**Secret Redaction**: DNS provider credentials (API tokens, service account keys, client secrets, ACME-DNS passwords) are stored as `SecretString`. Error messages reference the configuration key name; values are never exposed.

---

## 5. Telemetry Validations

<!-- markdownlint-disable MD060 -->

| Config Key | Required Condition | Failure Behavior | Readiness Behavior | Remediation |
|------------|-------------------|------------------|-------------------|-------------|
| `telemetry.environment` | Must be `development`, `dev`, `production`, or `prod` | **Fatal**: Config parsing fails with unknown variant | N/A | Set to `production` for OTLP export; `development` for stdout logs |
| `telemetry.enabled` | Boolean | **Fatal**: Config parsing fails | N/A | Set to `true` to enable OTLP export; `false` to disable |
| `telemetry.otlp_endpoint` | Valid gRPC URL when `enabled=true` and `environment=production` | **Runtime Fatal**: OTLP connection failure | N/A | Configure OpenTelemetry Collector endpoint (e.g., `http://otel-collector:4317`) |
| `telemetry.sampler_ratio` | Finite float in range 0.0–1.0 | **Fatal**: Config parsing fails with "must be a finite value in 0.0..=1.0" | N/A | Use `1.0` for 100% sampling, `0.1` for 10%, etc. |

<!-- markdownlint-enable MD060 -->

**Note**: Telemetry configuration does not affect readiness probes. OTLP connection failures are logged but do not block startup or readiness.

---

## 6. Helm-Provided Environment Variables

When deploying via Helm, additional validations apply to the Kubernetes/Helm integration:

<!-- markdownlint-disable MD060 -->

| Config Source | Required Condition | Failure Behavior | Readiness Behavior | Remediation |
|--------------|-------------------|------------------|-------------------|-------------|
| `image.digest` (Helm values) | Valid `sha256:<64-hex-chars>` when provided | **Helm Template Error**: Invalid digest format | N/A | Use CI-provided digest from container build |
| `externalSecret.enabled` | ExternalSecret must sync secrets successfully | **Runtime Fatal**: Secret not available to pod | N/A | Verify ExternalSecrets operator, SecretStore connectivity, AWS/GCP/Azure credentials |
| `externalSecret.spec.target.name` | Secret must exist before pod starts | **Fatal**: Container waiting for secret mount | N/A | Check ExternalSecret status: `kubectl describe externalsecret` |
| `postgres.enabled` (Helm) | PostgreSQL must be ready before app starts | **Fatal**: Init container waits indefinitely | N/A | Check PostgreSQL pod status, PVC binding, resource limits |
| `opentelemetry-collector.enabled` | When `true`, OTLP endpoint auto-configured | N/A | N/A | Ensure collector service name matches Helm release name |
| `networkPolicy.enabled` | Network policies must allow required egress | **Readiness/Runtime Failure**: Connection timeouts | **NOT_READY** or runtime errors | Verify NetworkPolicy allows: DNS (53), HTTPS (443), database, secrets backend, ACME |

<!-- markdownlint-enable MD060 -->

---

## Secret Values and Error Redaction

### Fields Marked as Secrets

The following configuration values are stored as `secrecy::SecretString` and are **never exposed in error messages or logs**:

<!-- markdownlint-disable MD060 -->

| Component | Secret Fields |
|-----------|--------------|
| **Database** | `database.url` (entire connection string with password), `database.password` (split credentials) |
| **Vault/AppRole** | `vault.secret_id`, `vault.secret_id_path` file contents |
| **Vault/K8s** | `vault.k8s_token_path` file contents (read at runtime) |
| **GCP** | `gcp_secret_manager.service_account_key`, key file contents |
| **Azure** | `azure_keyvault.client_secret` |
| **ACME-DNS** | `server.cert.dns.acmedns.password`, per-domain account passwords |
| **Cloudflare** | `server.cert.dns.cloudflare.api_token` |
| **Azure DNS** | `server.cert.dns.azure.client_secret` |
| **Google Cloud DNS** | `server.cert.dns.gcloud.service_account_key` |
| **Certificate Store** | `server.cert.store.signing_key_path` file contents, `signing_key_key` backend value |

<!-- markdownlint-enable MD060 -->

### Error Message Patterns

When a secret is invalid or missing, error messages follow this pattern:

- **Config validation**: Reference the configuration key name (e.g., `"Cloudflare DNS settings have an empty api_token"`)
- **File read errors**: Reference the file path (e.g., `"Failed to read Vault secret_id from file '/vault/secrets/secret-id'"`)
- **Backend errors**: Describe the operation without credential exposure (e.g., `"cryptographic-material backend unreachable: connection refused"`)

### Example Redacted Errors

```text
# GOOD: References config key, not value
Error: "Azure DNS settings have empty required fields: client_secret"

# GOOD: References file path, not contents
Error: "Failed to read Vault secret_id from file '/vault/secrets/secret-id': No such file"

# GOOD: Describes connection failure without credentials
Error: "cryptographic-material backend unreachable: error sending request for url"

# NEVER: Secret value exposed
Error: "Invalid password: supersecret123"  # This will NEVER happen
```

---

## Validation Gaps (Implementation Tickets Recommended)

The following validations are **NOT currently implemented** but would improve operator experience:

1. **Vault K8s Token File Existence** (`vault.k8s_token_path`)
    - **Current**: Validated only at login time
    - **Gap**: No startup validation that projected ServiceAccount token file exists
    - **Recommendation**: Add file existence check in `VaultConfig::validate()`

2. **GCP Service Account Key File Existence** (`gcp_secret_manager.service_account_key_path`)
    - **Current**: Validated only when building DNS challenge handler
    - **Gap**: No startup validation for file-based GCP auth
    - **Recommendation**: Add file existence check in startup wiring

3. **ACME Directory URL Reachability**
    - **Current**: Validated only on first ACME operation
    - **Gap**: No startup health check of ACME server
    - **Recommendation**: Add optional startup probe (may slow startup)

4. **Database Pool Sizing Sanity**
    - **Current**: No validation of `min_connections ≤ max_connections`
    - **Gap**: Invalid pool configuration causes runtime errors
    - **Recommendation**: Add validation in `DatabasePoolConfig`

5. **Helm `image.digest` Presence in Production**
    - **Current**: Falls back to tag-based deployment
    - **Gap**: Production deploys may not use digest-pinned images
    - **Recommendation**: Add Helm value validation requiring digest when `APP_ENV=production`

6. **ExternalSecret Sync Status**
    - **Current**: Pod fails at container start if secret missing
    - **Gap**: No pre-startup validation that ExternalSecret synced
    - **Recommendation**: Document init container pattern for ExternalSecret readiness check

---

## Quick Reference: Fatal vs. Readiness Failures

### Fatal Startup Errors (Process Exits)

The following errors cause immediate process termination:

- Configuration parsing errors (invalid enum, out-of-range values)
- Missing required configuration for selected features
- Database connection failures
- Database migration failures
- MySQL binlog_format/InnoDB engine mismatches
- Vault/AWS/GCP/Azure authentication failures
- Certificate provisioning strategy misconfiguration
- DNS provider configuration errors

### Readiness Failures (Process Runs, Reports 503)

The following conditions allow startup but block `/health/ready`:

- Database connectivity lost post-startup
- Cryptographic material backend unreachable
- Certificate/key files missing or unreadable (non-ACME store mode)

### Warnings (Logged, Non-Blocking)

The following conditions generate warnings but allow operation:

- Pebble DNS provider selected in production environment
- Invalid email format for ACME (CA may reject, not the server)

---

## Operator Checklist

Before deploying to production, verify:

- [ ] `APP_ENV=production` is set
- [ ] `database.backend` matches your infrastructure (typically `postgres`)
- [ ] `database.url` uses correct scheme and is injected via ExternalSecrets
- [ ] Database migrations will succeed (user has DDL permissions)
- [ ] For MySQL: `binlog_format=ROW` and all tables use InnoDB
- [ ] Secrets backend configured and reachable (Vault/GCP/Azure/AWS)
- [ ] Certificate provisioning strategy chosen (`acme` or `store`)
- [ ] If `acme`: DNS provider configured with valid credentials
- [ ] If `store`: Certificate material available in filesystem or secrets backend
- [ ] Telemetry configured with valid OTLP endpoint
- [ ] Helm `image.digest` set for digest-pinned deployment
- [ ] ExternalSecrets operator configured and secrets accessible
- [ ] NetworkPolicy allows egress to database, secrets backend, DNS, HTTPS
