# Startup Validation and Fail-Fast Production Configuration

<!-- markdownlint-disable line-length -->

This is the operator-facing inventory of configuration checks that happen while the server boots, plus dependency checks that affect `/health/ready` after the process is running.

The server fails fast for configuration that would make the application unsafe or unusable. Runtime dependency loss is reported through readiness: `/health/ready` returns `503 NOT_READY`, while liveness stays independent so Kubernetes does not restart a healthy process just because a downstream service is unavailable.

## Behavior Legend

- **Fatal startup error**: the process exits before serving traffic.
- **Readiness failure**: the process is running, but `/health/ready` returns `503 NOT_READY`.
- **Warning**: the server logs the condition and continues.
- **Template error**: Helm refuses to render the manifest.
- **Not implemented**: no validation exists today; create an implementation ticket if production needs the guardrail.

## Production Startup and Readiness Matrix

<!-- markdownlint-disable MD060 -->

| Component | Config key or source | Required condition | Failure behavior | Readiness behavior | Remediation |
| --- | --- | --- | --- | --- | --- |
| Database | `database.backend` | One of `memory`, `postgres`, `mysql`, or `sqlite`, and the corresponding feature must be compiled in. | **Fatal startup error** for an unknown enum or a configured backend whose feature is not compiled. | N/A | Set `APP_DATABASE__BACKEND` to the deployed backend and use an image built with that backend feature. |
| Database | `database.url` or split fields | SQL backends require either a full URL or split fields. Split fields require `database.host`, `database.username`, `database.password` or `database.password_file`, and `database.name`; they are supported only for `postgres` and `mysql`. | **Fatal startup error**: missing or ambiguous database configuration, unsupported split fields, unreadable `database.password_file`, or invalid split field value. | N/A | Use either `APP_DATABASE__URL` or the split `APP_DATABASE__HOST`, `APP_DATABASE__USERNAME`, `APP_DATABASE__PASSWORD(_FILE)`, `APP_DATABASE__NAME`, and optional `APP_DATABASE__PORT`. Do not configure both forms. |
| Database | `database.url` | URL scheme must match `database.backend`: `postgres://` or `postgresql://`, `mysql://`, `sqlite:`, or `memory:`/`memory`. | **Fatal startup error**: `URL scheme does not match configured backend`. | N/A | Align the URL prefix with the selected backend. |
| Database | `database.host` | Split-field host must be a hostname/IP only, without scheme, port, path, user info, query, fragment, or whitespace. | **Fatal startup error** during config load. | N/A | Provide only the database host, for example `postgres.statuslist.svc.cluster.local`. |
| Database | `database.query` | Optional query string may contain only non-secret driver/TLS options. Credential-like keys such as `password`, `secret`, `token`, `user`, and `username` are rejected. | **Fatal startup error** during config load. | N/A | Keep credentials in `database.password` or `database.password_file`; use `database.query` only for driver options such as TLS settings. |
| Database | `database.pool.*` | Values must deserialize to unsigned integers. There is no explicit startup validation that `min_connections <= max_connections` or that values are non-zero. | Deserialization errors are **fatal startup errors**; invalid pool semantics may fail when the SQL pool is constructed. | Existing pool connectivity loss becomes **readiness failure**. | Use conservative pool values, for example max sized against database capacity and min `1`. Add an implementation ticket for explicit pool sanity validation. |
| Database | SQL connection | SQL connection must succeed before repositories are wired. Errors are wrapped as `Failed to connect to database` with a redacted target. | **Fatal startup error**. | If the established pool later cannot `ping`, readiness logs `database unreachable: ...` and returns `NOT_READY`. | Check service DNS, network policy, TLS settings, credentials, database availability, and user permissions. |
| Database | Migrations | SeaORM migrations must run successfully. | **Fatal startup error**: `Failed to run database migrations`. | N/A | Ensure the configured database user has required DDL permissions and inspect migration logs. |
| Database, MySQL | Table engines | `credentials`, `status_lists`, and `status_list_history` must use InnoDB. No-op on PostgreSQL and SQLite. | **Fatal startup error** after migrations; logs identify table engines and include `ALTER TABLE ... ENGINE=InnoDB` remediation. | N/A | Convert affected tables to InnoDB during a maintenance window. |
| Database, MySQL | `@@GLOBAL.binlog_format` | Must not be `STATEMENT`; `ROW` and `MIXED` pass. No-op on PostgreSQL and SQLite. | **Fatal startup error** after migrations. | N/A | Set MySQL binary logging to `ROW` or `MIXED` and restart MySQL if required by your deployment. |
| Redis | N/A | Redis is not part of the current application startup path; the Redis HA chart was removed. | N/A | N/A | Use the Redis removal cleanup runbook in [`deployment-runbook.md`](deployment-runbook.md#redis-removal-cleanup-breaking-change) for old releases. |
| Secrets backend | Compile-time features | With `acme`, cryptographic material storage is selected by feature precedence: `vault`, then `gcp`, then `azure`, then `aws`, else in-memory. Without `acme`, static filesystem or inline PEM certificate material is used instead. | **Fatal startup error** if the selected backend cannot be built. | ACME storage backends are checked by `cert_store`; failures return `NOT_READY`. | Deploy an image with the intended feature set and configure the backend required by that feature. |
| Vault/OpenBao | `vault.addr` | Non-empty parseable URL when the `vault` feature is selected. | **Fatal startup error** while building the Vault client. | If Vault later cannot be reached, readiness logs `cryptographic-material backend unreachable: ...`. | Set the Vault/OpenBao API URL and verify DNS, TLS, namespace, and network policy. |
| Vault/OpenBao | `vault.auth_method` | One of `approle` or `kubernetes`. | **Fatal startup error** for an unknown enum. | N/A | Configure the selected auth method explicitly. |
| Vault/OpenBao AppRole | `vault.role_id` | Non-empty when `vault.auth_method=approle`. | **Fatal startup error**. | N/A | Configure `APP_VAULT__ROLE_ID`. |
| Vault/OpenBao AppRole | `vault.secret_id` or `vault.secret_id_path` | Non-empty AppRole secret ID, either inline or read from a file. File contents must be non-empty. | **Fatal startup error** if missing, empty, or unreadable. | N/A | Mount or inject the AppRole secret ID and point `APP_VAULT__SECRET_ID_PATH` to the mounted file when using file delivery. |
| Vault/OpenBao Kubernetes auth | `vault.k8s_role` and `vault.k8s_token_path` | Non-empty Kubernetes auth role; token file must be readable and non-empty during initial login. | **Fatal startup error** if the role is missing or token read/login fails. | Later auth/renewal failure can make storage operations and readiness fail. | Configure the Vault Kubernetes role and ensure the projected ServiceAccount token is mounted. |
| Vault/OpenBao | `vault.mount`, `vault.auth_mount`, `vault.k8s_auth_mount` | Selected mount values must not be empty. | **Fatal startup error** while building the Vault client. | N/A | Set the correct KV v2 mount and auth engine mount names. |
| GCP Secret Manager | `gcp_secret_manager.project_id` | Non-empty when the `gcp` feature is selected and `vault` is not selected. | **Fatal startup error**. | If GCP Secret Manager later cannot be reached, readiness logs `cryptographic-material backend unreachable: ...`. | Set the GCP project ID and grant access to the app identity. |
| GCP Secret Manager | `gcp_secret_manager.service_account_key`, `gcp_secret_manager.service_account_key_path`, ambient credentials, `allow_anonymous_credentials` | Uses inline service account JSON, a service account key file, ambient Google credentials, or anonymous credentials when explicitly allowed for emulator/testing. | **Fatal startup error** for unreadable or unparsable configured key files/JSON, or client construction failure. | Readiness probes the API with metadata for a non-existent health secret. | Prefer Workload Identity/ADC in production. Use anonymous credentials only with a local emulator. |
| Azure Key Vault | `azure_keyvault.vault_url` | Required when the `azure` feature is selected and neither `vault` nor `gcp` is selected. | **Fatal startup error** if missing or invalid. | If Azure Key Vault later cannot be reached, readiness logs `cryptographic-material backend unreachable: ...`. | Set a valid Key Vault URL and grant the app identity access. |
| Azure Key Vault | `azure_keyvault.tenant_id`, `azure_keyvault.client_id`, `azure_keyvault.client_secret`, or ambient Azure credentials | When all service-principal fields are present, the app uses `ClientSecretCredential`; otherwise it builds a default chain of Workload Identity, Managed Identity, and developer tools credentials. | **Fatal startup error** only if the credential client cannot be constructed; token acquisition may fail later on first Key Vault call/readiness. | Readiness probes Key Vault with a non-existent health secret. | In production, configure Workload Identity/Managed Identity or provide all service-principal fields through secrets. |
| AWS Secrets Manager | `aws.region` and ambient/static AWS credentials | Region is passed to the AWS SDK when the `aws` feature is selected and no earlier secrets backend feature is selected. Credentials may come from IRSA/Workload Identity or mounted AWS config files. | AWS client construction is local and normally succeeds; missing permissions/credentials surface on first backend call or readiness. | Readiness calls `DescribeSecret` for a non-existent health secret and fails if AWS auth, region, network, or permissions are wrong. | Set `APP_AWS__REGION`, configure IRSA/Workload Identity or mounted credentials, and grant `secretsmanager:DescribeSecret` plus required secret permissions. |
| Certificate provisioning, ACME feature | `server.domain`, `server.cert.acme_directory_url`, `server.cert.email`, `server.cert.eku`, `server.cert.signing_key_cache_ttl` | ACME mode is selected by compiling the `acme` feature; there is no runtime `server.cert.provisioning_strategy` key. At least one domain, a challenge handler, an ACME directory URL, and cryptographic storage are required. | **Fatal startup error** if the manager cannot be built. The initial certificate request is spawned after the HTTP server is created; renewal/request failures are logged as warnings and metrics rather than aborting startup. | `cert_store` readiness checks only storage reachability, not ACME CA reachability or certificate issuance success. | Configure the intended feature set, `APP_SERVER__DOMAIN`, an ACME directory URL, DNS provider settings, and a reachable cryptographic material backend. |
| Certificate provisioning, static mode | `server.cert.store.certificate_path` plus `server.cert.store.signing_key_path`, or `server.cert.store.certificate` plus `server.cert.store.signing_key` | When `acme` is not compiled, both certificate and signing key must come from the same source: filesystem paths or inline PEM values. Do not mix filesystem and inline values. | **Fatal startup error** if neither pair is fully configured, sources are mixed, files are unreadable, PEM is malformed, or the certificate public key does not match the signing key. | Filesystem mode also checks configured paths for existence/readability and returns `NOT_READY` if files disappear later. Inline mode has no external readiness dependency after startup validation. | Mount both files or inject both inline PEM values. Keep private key material in Kubernetes Secrets or an external secret injector. |
| Certificate renewal | `server.cert.renewal_cron_schedule` | In ACME builds, the cron schedule must be accepted by `tokio_cron_scheduler`. It is ignored when `acme` is not compiled. | **Fatal startup error** before binding the HTTP listener if the scheduler rejects the expression. | N/A | Use the six-field cron syntax expected by the scheduler, for example `0 0 0 * * *`. |
| DNS provider, ACME only | `server.cert.dns.provider` | One of `route53`, `cloudflare`, `gcloud`, `azure`, `acmedns`, or `pebble`. If unset, defaults to `route53` in production and `pebble` otherwise. | **Fatal startup error** for an unknown enum or for selecting Route53 when the `aws` feature is not compiled. | DNS API reachability is not part of readiness. | Set the provider that matches your DNS infrastructure and image features. |
| DNS provider, ACME only | `server.cert.dns.provider=pebble` with `APP_ENV=production` | Pebble is development-only. | **Warning** only: startup continues. | N/A | Use Route53, Cloudflare, Google Cloud DNS, Azure DNS, or ACME-DNS for production ACME issuance. |
| DNS provider, Route53 | AWS region, credentials, and Route53 permissions | AWS SDK must be able to change DNS records at renewal time. | Startup builds the handler locally; DNS permission errors surface during certificate issuance/renewal, not during startup. | N/A | Grant `route53:ListHostedZones`, `route53:ChangeResourceRecordSets`, and `route53:GetChange`, and configure region/credentials. |
| DNS provider, Cloudflare | `server.cert.dns.cloudflare.api_token` | Cloudflare settings must exist and API token must be non-empty. | **Fatal startup error**: provider settings missing or token empty. | N/A | Create a token with Zone:Read and DNS:Edit and inject it as a secret. |
| DNS provider, Google Cloud DNS | `server.cert.dns.gcloud.service_account_key` or `server.cert.dns.gcloud.service_account_key_path` | Google DNS provider settings must include non-empty inline service account JSON or a non-empty key path. If a path is configured, it is read during startup. | **Fatal startup error** if settings are missing, path is unreadable, or key JSON cannot build the DNS provider. | N/A | Provide DNS admin service account JSON or mount the key file. |
| DNS provider, Azure DNS | `server.cert.dns.azure.*` | `tenant_id`, `client_id`, `client_secret`, `subscription_id`, and `resource_group` must be non-empty. | **Fatal startup error** listing empty field names only. | N/A | Configure all Azure DNS service-principal fields via secret injection. |
| DNS provider, ACME-DNS | `server.cert.dns.acmedns.*` | `server_url` must be non-empty. Configure either a complete default account (`username`, `password`, `subdomain`) or a non-empty accounts map. Each account entry must name a domain and include non-empty fields. Certificate domains must be covered by configured accounts. | **Fatal startup error** for missing settings, partial account fields, invalid account keys, duplicate normalized accounts, or domain coverage failure. | N/A | Register ACME-DNS accounts, configure complete credentials, and create the required `_acme-challenge` CNAME records. |
| Helm env and image | `statuslist.image.digest` | If set, must match `sha256:<64 hex chars>`. Production values currently set a digest, but the chart does not require one solely because `APP_ENV=production`. | **Template error** for malformed digest. | N/A | Use the CI-produced image digest for production. Add a follow-up if production should hard-require digest pinning. |
| Helm env and secrets | `externalSecret.enabled`, `secretStore.*`, `externalSecret.spec.target.name` | When ESO is enabled, chart-rendered SecretStore and ExternalSecret references must be internally consistent; several provider-specific SecretStore values are template-validated. | **Template error** for invalid chart values. If the external secret never syncs, the pod may stay pending or the container may fail when mounted/env secrets are missing. | Missing mounted files or bad downstream credentials can become startup or readiness failures depending on the consumed key. | Check `kubectl describe externalsecret`, SecretStore auth, target Secret name, and provider credentials. |
| Helm env and secret files | `statuslist.secretMounts[*].fileEnv` | File env paths must be non-empty normalized relative paths, must reference mounted items, and must not duplicate rendered env vars. | **Template error**. | N/A | Fix the `fileEnv` path and duplicate env declarations. |
| Helm env and Workload Identity | `serviceAccount.annotations`, `serviceAccount.automountServiceAccountToken`, `statuslist.aws.mountCredentials`, Azure pod label | Workload Identity is provider-specific. AWS IRSA is opt-in by disabling mounted AWS credentials and annotating the ServiceAccount. Azure Workload Identity also requires `azure.workload.identity/use: "true"` on the pod. | Miswiring usually does not fail template rendering; it fails on backend auth or readiness. | AWS/GCP/Azure backend readiness fails when ambient credentials cannot authenticate. | Follow the Workload Identity section in [`../helm/README.md`](../helm/README.md#serviceaccount-and-workload-identity). |
| Helm env and networking | `networkPolicy.enabled` | Network policies must allow egress to DNS, database, secrets backends, ACME CA/DNS APIs, and telemetry collector when used. | Startup may fail on initial dependency connection; later blocks surface as readiness or runtime errors. | Database and cert-store readiness fail if probes cannot reach dependencies. | Permit required egress for TCP/UDP DNS, database, HTTPS, provider APIs, and OTLP where applicable. |
| HTTP server | `server.host`, `server.port` | Address must bind successfully. Port must deserialize as `u16`. | **Fatal startup error** if config parsing fails or the listener cannot bind. | N/A | Use a valid container bind address and avoid port conflicts. |
| Aggregation URI | `server.aggregation_uri` | Optional. When non-empty, it must parse as a URL and its path must be `/api/v1/aggregation`. | **Fatal startup error** in HTTP server setup. | N/A | Set the URI to the public aggregation endpoint path or leave it unset. |
| Rate limiting | `rate_limit.strict_burst_size`, `rate_limit.strict_period_secs`, `rate_limit.permissive_burst_size`, `rate_limit.permissive_period_secs` | Governor burst sizes and periods must be non-zero. | **Fatal startup error** while building HTTP middleware. | N/A | Set positive strict and permissive burst/period values. |
| Telemetry | `telemetry.environment` | One of `development`, `dev`, `production`, or `prod`. Defaults from `APP_ENV`. | **Fatal startup error** for an unknown enum. | N/A | Set `APP_ENV=production` or configure `APP_TELEMETRY__ENVIRONMENT` explicitly. |
| Telemetry | `telemetry.sampler_ratio` | Finite number in `0.0..=1.0`. | **Fatal startup error** during config load. | N/A | Use a value such as `1.0`, `0.1`, or `0.0`. |
| Telemetry | `telemetry.enabled`, `telemetry.otlp_endpoint` | If enabled, OTLP span/log exporters must be constructible with the configured endpoint. The app does not perform a startup reachability probe of the collector. | Exporter construction errors are **fatal startup errors**; collector/network outages after construction are logged by telemetry components and do not affect readiness. | N/A | Configure a valid OTLP gRPC endpoint. Monitor collector delivery separately. |

<!-- markdownlint-enable MD060 -->

## Secrets and Redaction

The following values are secret material and must be delivered through Kubernetes Secrets, External Secrets Operator, mounted files, or an equivalent secret manager:

<!-- markdownlint-disable MD060 -->

| Component | Secret values |
| --- | --- |
| Database | `database.url`, `database.password`, and `database.password_file` contents |
| Vault/OpenBao | `vault.secret_id`, `vault.secret_id_path` contents, and `vault.k8s_token_path` contents |
| GCP | `gcp_secret_manager.service_account_key`, `gcp_secret_manager.service_account_key_path` contents, `server.cert.dns.gcloud.service_account_key`, and DNS key-file contents |
| Azure | `azure_keyvault.client_secret` and `server.cert.dns.azure.client_secret` |
| AWS | Mounted AWS shared credentials file contents and any static AWS credential environment supplied outside the chart |
| DNS | `server.cert.dns.cloudflare.api_token`, `server.cert.dns.acmedns.password`, and per-domain ACME-DNS account passwords |
| Static certificate mode | `server.cert.store.signing_key` and `server.cert.store.signing_key_path` contents |

<!-- markdownlint-enable MD060 -->

Most credential fields are modeled as `secrecy::SecretString`, including database URLs/passwords, Vault AppRole secret IDs, GCP service account keys, Azure client secrets, Cloudflare tokens, Azure DNS client secrets, and ACME-DNS passwords. Static inline PEM values are currently plain `String` fields in config, so operators should avoid logging raw environment dumps and should prefer mounted files or secret injection.

Error messages are written to identify the broken key, source path, backend, or operation without printing credential values. For example:

```text
Cloudflare DNS settings have an empty api_token
Failed to read Vault secret_id from file "/vault/secrets/secret-id": ...
Failed to connect to database (kind=connection, backend=postgres, host=postgres, port=5432, database=statuslist)
cryptographic-material backend unreachable: ...
```

The unauthenticated readiness endpoint returns only `READY` or `NOT_READY`; detailed dependency reasons are logged internally.

## Follow-Up Implementation Issues

The documentation review found these validation gaps. They should be tracked as implementation tickets rather than documented as existing behavior:

1. Add explicit database pool sanity validation for `min_connections <= max_connections` and non-zero values before constructing the SQL pool.
2. Decide whether production Helm values should require `statuslist.image.digest` whenever `APP_ENV=production`.
3. Add an optional ACME CA and DNS provider startup probe if operators want certificate issuance failures to block startup instead of surfacing as renewal warnings.
4. Consider wrapping static inline certificate PEM config, especially `server.cert.store.signing_key`, in a secret type or recommending mounted files only for production.
5. Consider a pre-flight ExternalSecret sync/init-container pattern for environments where missing ESO data should fail before the app container starts.

## Operator Checklist

- Set `APP_ENV=production`.
- Choose the intended database backend and verify the image includes the matching feature.
- Use either the full database URL or split database fields, not both.
- Verify database migrations, MySQL InnoDB/binlog settings when applicable, and network policy.
- Configure the selected cryptographic material backend and confirm `/health/ready` can reach it.
- For ACME builds, configure the DNS provider and understand that initial issuance errors are logged warnings, not readiness failures.
- For static certificate builds, provide both certificate and signing key from the same source.
- Verify Helm-rendered secrets, Workload Identity/static credentials, and mounted secret-file paths.
