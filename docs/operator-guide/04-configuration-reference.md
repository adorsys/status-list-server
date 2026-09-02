# 04 — Configuration Reference

This is the exhaustive reference for every application environment variable
(`APP_*`) the server reads, its default, and the validation rules that apply. The
canonical source is [.env.template](../../.env.template); this page mirrors it in a
usable, searchable form and adds the Kubernetes/Helm-specific behaviors and validation
rules enforced by the chart.

## How configuration reaches the pod in Helm

- **Plain (non-secret) values** go in `statuslist.env.<VAR>` in your values file and are
  rendered as `env` entries on the Deployment.
- **Secrets** (passwords, API tokens, role/secret IDs) must **not** be set as plain env
  values. They arrive via the `statuslist-secret` Secret (ESO- or fallback-delivered) and
  are referenced by `secretKeyRef`:
  - `APP_DATABASE__PASSWORD` is always injected from the `postgres-password` key of
    `statuslist-secret`. Setting it as a plain env value is **rejected by the chart**.
  - The ESO/fallback provider also carries cloud/Vault credentials as needed.
- The chart sets some defaults automatically when a relevant variable is missing (e.g.
  `APP_DATABASE__BACKEND=postgres`, `APP_DATABASE__HOST`, `APP_DATABASE__USERNAME`,
  `APP_DATABASE__NAME`, `APP_SERVER__DOMAIN`, `APP_TELEMETRY__ENABLED`,
  `APP_TELEMETRY__OTLP_ENDPOINT`).

### Chart-enforced validation rules

These fail at `helm template`/`upgrade` time (fail-fast), not at runtime:

| Rule                                                             | Behavior                                                                                             |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `statuslist.env.APP_DATABASE__URL`                               | **Rejected.** Assembled credential-bearing URLs are not permitted in pod metadata. Use split fields. |
| `statuslist.env.APP_DATABASE__PASSWORD`                          | **Rejected.** Must come from `statuslist-secret` (key `postgres-password`).                          |
| `statuslist.env.APP_DATABASE__PORT`                              | **Required.** Must be set to the database service port.                                              |
| `externalSecret.enabled` + `statuslist.fallbackSecret.enabled`   | **Rejected** — contradictory secret-delivery modes.                                                  |
| `externalSecret.enabled` without `secretStore.enabled`           | **Rejected.**                                                                                        |
| `externalSecret.spec.target.name` ≠ `statuslist-secret`          | **Rejected.** Single supported app-secret name.                                                      |
| `secretStore.provider` outside `aws`/`vault`/`gcp`/`azure`/`raw` | **Rejected.**                                                                                        |
| `secretStore.provider=raw` with empty `secretStore.raw`          | **Rejected.**                                                                                        |
| `statuslist.image.digest` ≠ `sha256:<64 hex>`                    | **Rejected.**                                                                                        |
| `statuslist.image.digest` / flag combos                          | `digest` pins the exact scanned image; empty falls back to `tag` then `appVersion`. Never `latest`.  |

### File-based secret mounts & rotation (`secretMounts`, `watcher`, `*_FILE`)

Since chart #462, the chart mounts Kubernetes Secrets as **files** for rotation-friendly
credential delivery. The chart-injected env pattern is `<VAR>_FILE` (the env value is a
path on the pod, so Kubernetes never exposes the raw secret bytes in pod metadata):

| Value / env pattern                                                  | Meaning                                                                                                                                                                          |
| -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `statuslist.secretMounts[]`                                          | Mount a Kubernetes Secret as files at `mountPath` (optionally `items[]`).                                                                                                        |
| `statuslist.secretMounts[].fileEnv`                                  | Map a mounted file to an env var, e.g. `APP_DATABASE__PASSWORD_FILE: password`. Values are relative to `mountPath`.                                                              |
| `APP_WATCHER__POLL_INTERVAL_SECS`                                    | File-watcher poll interval (seconds) for credential rotation detection; injected when `statuslist.watcher.pollIntervalSecs` is set. Requires an issue #456 image to take effect. |
| `APP_DATABASE__PASSWORD_FILE`                                        | Path to the mounted DB password file. When set, the chart skips `APP_DATABASE__PASSWORD` injection.                                                                              |
| `APP_SERVER__CERT__STORE__CERTIFICATE_PATH` / `..._SIGNING_KEY_PATH` | Often supplied via `fileEnv` so the signing key/cert mount at a known path.                                                                                                      |

Additional render-time validation (from `deployment.yaml`):

- `fileEnv` paths must be **non-empty, relative to `mountPath`, normalized**, and resolve
  inside the mount; when `items` is present, each `fileEnv` path must match an
  `items[].path`.
- A `fileEnv` key must not duplicate `statuslist.env` or another chart-managed variable.
- `fileEnv` must not define `APP_DATABASE__URL` (assembled credentials) or
  `APP_DATABASE__PASSWORD` (use `APP_DATABASE__PASSWORD_FILE` instead).
- Chart-managed vars (`APP_AWS__REGION`, `AWS_SHARED_CREDENTIALS_FILE`/`AWS_CONFIG_FILE`,
  `APP_WATCHER__POLL_INTERVAL_SECS`, `APP_DATABASE__PASSWORD`) cannot be redefined by
  `fileEnv`.

When `externalSecret.spec.secretStoreRef.kind` is `ClusterSecretStore`, the chart skips
rendering the namespaced `SecretStore` (it must be created cluster-wide by an admin) and
the ESO CRs use apiVersion `external-secrets.io/v1`. Additional separately-mounted
Secrets can be synced via `externalSecret.extraExternalSecrets[]`.

## Group 1 — Server

| Variable                      | Default       | Allowed / Notes                                                                                              |
| ----------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------ |
| `RUST_LOG`                    | `info`        | Log level for the tracing/logging layer.                                                                     |
| `APP_ENV`                     | `development` | `development` (human-readable logs) or `production` (structured JSON logs).                                  |
| `APP_SERVER__HOST`            | `0.0.0.0`     | Bind address.                                                                                                |
| `APP_SERVER__DOMAIN`          | —             | Public domain of the server. Set via ingress `externalDnsHostname` or env; defaults to `localhost` if unset. |
| `APP_SERVER__PORT`            | `8000`        | HTTP listen port (chart `statuslist.service.targetPort`).                                                    |
| `APP_SERVER__ENABLE_METRICS`  | `false`       | Serve Prometheus metrics on `/metrics`. See [08-observability.md](08-observability.md).                      |
| `APP_SERVER__AGGREGATION_URI` | _unset_       | Optional URI of the Status List Aggregation endpoint (draft-21 §9). Unset omits it from tokens.              |

## Group 2 — Certificate provisioning (server identity)

`APP_SERVER__CERT__*` controls the identity certificate + signing key the server uses to
sign Status List Tokens and expose its API over TLS **when the server terminates TLS
itself**. This is distinct from ingress TLS — see
[05-token-signing-credentials.md](05-token-signing-credentials.md).

| Variable                                     | Default                           | Notes                                                                                                               |
| -------------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `APP_SERVER__CERT__PROVISIONING_STRATEGY`    | `acme`                            | `acme` (server requests/renews via ACME) or `store` (loads externally-managed material from filesystem or backend). |
| `APP_SERVER__CERT__EMAIL`                    | —                                 | ACME contact email (required when `acme`).                                                                          |
| `APP_SERVER__CERT__ORGANIZATION`             | —                                 | Organization for the ACME order (required when `acme`).                                                             |
| `APP_SERVER__CERT__ACME_DIRECTORY_URL`       | —                                 | ACME directory URL. `https://pebble:14000/dir` local; `https://acme-v02.api.letsencrypt.org/directory` production.  |
| `APP_SERVER__CERT__EKU`                      | `1,3,6,1,5,5,7,3,30`              | Extended Key Usage OID list (the Status List signing EKU).                                                          |
| `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL`    | `0`                               | Seconds to cache private signing-key reads from the selected backend. `0` forces every read to the backend.         |
| `APP_SERVER__CERT__RENEWAL_CRON_SCHEDULE`    | `0 0 0 * * *`                     | 6-field cron for certificate renewal checks (sec min hour day month dow).                                           |
| `APP_SERVER__CERT__DNS_CHALLENGE_SERVER_URL` | `http://challtestsrv:8055`        | DNS challenge server URL; development-only.                                                                         |
| `APP_SERVER__CERT__DNS__PROVIDER`            | `route53` (prod) / `pebble` (dev) | `route53 \| cloudflare \| gcloud \| azure \| acmedns \| pebble`.                                                    |

### Store provisioning (`PROVISIONING_STRATEGY=store`)

Configure **either** filesystem paths **or** storage keys, never both:

| Variable                                    | Notes                                                       |
| ------------------------------------------- | ----------------------------------------------------------- |
| `APP_SERVER__CERT__STORE__CERTIFICATE_PATH` | Filesystem path to PEM/DER certificate chain.               |
| `APP_SERVER__CERT__STORE__SIGNING_KEY_PATH` | Filesystem path to PKCS#8 PEM/DER private signing key.      |
| `APP_SERVER__CERT__STORE__CERTIFICATE_KEY`  | Storage-key reference for the certificate (backend-backed). |
| `APP_SERVER__CERT__STORE__SIGNING_KEY_KEY`  | Storage-key reference for the signing key (backend-backed). |

Validation (enforced at setup): store provisioning requires either both filesystem paths
or both storage keys — never one of each, and never all empty.

### DNS provider credentials

These are **secrets** and should come from `statuslist-secret`/ESO, not plain env:

| Variable                                                                                                                         | Provider   | Notes                                                                                     |
| -------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------- |
| `APP_SERVER__CERT__DNS__CLOUDFLARE__API_TOKEN`                                                                                   | cloudflare | Zone:Read + DNS:Edit.                                                                     |
| `APP_SERVER__CERT__DNS__GCLOUD__SERVICE_ACCOUNT_KEY` / `..._KEY_PATH`                                                            | gcloud     | Service account key JSON (inline or path).                                                |
| `APP_SERVER__CERT__DNS__AZURE__TENANT_ID` / `..._CLIENT_ID` / `..._CLIENT_SECRET` / `..._SUBSCRIPTION_ID` / `..._RESOURCE_GROUP` | azure      | Service principal with DNS Zone Contributor.                                              |
| `APP_SERVER__CERT__DNS__ACMEDNS__SERVER_URL` / `..._USERNAME` / `..._PASSWORD` / `..._SUBDOMAIN` / `..._ACCOUNTS`                | acmedns    | Self-hosted ACME-DNS registration. `ACCOUNTS` is a JSON object of per-domain credentials. |

## Group 3 — Database (split settings)

Prefer **split fields** in Kubernetes so pod metadata never exposes a fully assembled
credential-bearing URL.

| Variable                      | Default       | Notes                                                                                                                                                                   |
| ----------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `APP_DATABASE__BACKEND`       | `postgres`    | `postgres \| mysql \| sqlite`. `mysql` covers MariaDB-compatible servers.                                                                                               |
| `APP_DATABASE__HOST`          | `db`          | Database host. Chart defaults to the bundled Postgres service.                                                                                                          |
| `APP_DATABASE__PORT`          | `5432`        | Port; `3306` for MySQL. **Required by the chart.**                                                                                                                      |
| `APP_DATABASE__USERNAME`      | `postgres`    | Chart defaults to `postgres.auth.username`.                                                                                                                             |
| `APP_DATABASE__PASSWORD`      | —             | **Secret.** Injected from `statuslist-secret` key `postgres-password`. Never a plain env value.                                                                         |
| `APP_DATABASE__PASSWORD_FILE` | —             | **File-based password.** Path to a mounted password file (via `statuslist.secretMounts` + `fileEnv`). When set, the chart **does not** inject `APP_DATABASE__PASSWORD`. |
| `APP_DATABASE__NAME`          | `status-list` | Database name. Chart defaults to `postgres.auth.database`.                                                                                                              |
| `APP_DATABASE__QUERY`         | —             | Optional non-secret driver/TLS query params, e.g. `sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt`.                                                           |
| `APP_DATABASE__URL`           | —             | Supported for local/custom deployments **but not** by the chart (rejected); do not combine with split fields.                                                           |

### Connection pool (Postgres / MySQL)

| Variable                                   | Default | Notes                                                                                |
| ------------------------------------------ | ------- | ------------------------------------------------------------------------------------ |
| `APP_DATABASE__POOL__MAX_CONNECTIONS`      | `5`     | Size as `floor(server_max_connections / replica_count) - headroom`.                  |
| `APP_DATABASE__POOL__MIN_CONNECTIONS`      | `1`     |                                                                                      |
| `APP_DATABASE__POOL__ACQUIRE_TIMEOUT_SECS` | `5`     | Seconds to wait for a free connection before erroring (prevents indefinite queuing). |
| `APP_DATABASE__POOL__CONNECT_TIMEOUT_SECS` | `10`    |                                                                                      |
| `APP_DATABASE__POOL__IDLE_TIMEOUT_SECS`    | `600`   |                                                                                      |
| `APP_DATABASE__POOL__MAX_LIFETIME_SECS`    | `1800`  |                                                                                      |

Pool sizing is covered in [07-scaling-and-availability.md](07-scaling-and-availability.md).

## Group 4 — AWS SDK

| Variable                                          | Default                  | Notes                                                                                                                                      |
| ------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `APP_AWS__REGION`                                 | `us-east-1`              | Region. Chart injects it only when explicitly configured (pure-IRSA/WI installs leave it empty so the SDK discovers region from metadata). |
| `AWS_ENDPOINT_URL`                                | `http://localstack:4566` | Custom endpoint; remove in production.                                                                                                     |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`     | `test`                   | Development only.                                                                                                                          |
| `AWS_SHARED_CREDENTIALS_FILE` / `AWS_CONFIG_FILE` | —                        | Set by the chart to `/home/nobody/.aws/credentials` and `/home/nobody/.aws/config` when `statuslist.aws.mountCredentials=true`.            |

## Group 5 — Vault / OpenBao (`vault` feature)

| Variable                    | Default                                               | Notes                                                                    |
| --------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------ |
| `APP_VAULT__AUTH_METHOD`    | `approle`                                             | `approle` or `kubernetes`.                                               |
| `APP_VAULT__ADDR`           | `http://vault:8200`                                   | Vault/OpenBao API address.                                               |
| `APP_VAULT__AUTH_MOUNT`     | `approle`                                             | AppRole auth mount path.                                                 |
| `APP_VAULT__ROLE_ID`        | —                                                     | Secret. Required for AppRole.                                            |
| `APP_VAULT__SECRET_ID`      | —                                                     | Secret.                                                                  |
| `APP_VAULT__SECRET_ID_PATH` | —                                                     | File path to load the secret_id (volume mount; recommended over inline). |
| `APP_VAULT__K8S_ROLE`       | —                                                     | K8s auth role (when `kubernetes`).                                       |
| `APP_VAULT__K8S_TOKEN_PATH` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Projected SA token file.                                                 |
| `APP_VAULT__K8S_AUTH_MOUNT` | `kubernetes`                                          | K8s auth mount path.                                                     |
| `APP_VAULT__MOUNT`          | `secret`                                              | KV v2 engine mount.                                                      |
| `APP_VAULT__PATH_PREFIX`    | —                                                     | Prefix prepended to all secret keys.                                     |
| `APP_VAULT__NAMESPACE`      | —                                                     | Vault Enterprise/OpenBao namespace.                                      |
| `APP_VAULT__TIMEOUT_SECS`   | `30`                                                  | HTTP request timeout.                                                    |

## Group 6 — Cache

| Variable                  | Default | Notes                                                                         |
| ------------------------- | ------- | ----------------------------------------------------------------------------- |
| `APP_CACHE__TTL`          | `300`   | Status-list record cache TTL in seconds. `0` disables (always fetch from DB). |
| `APP_CACHE__MAX_CAPACITY` | `1000`  |                                                                               |

## Group 7 — Status list tokens

| Variable                                   | Default   | Notes                                                                                                                                              |
| ------------------------------------------ | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `APP_STATUS_LIST__TOKEN_EXP_SECS`          | `900`     | Token expiration in seconds (time from issuance to expiry).                                                                                        |
| `APP_STATUS_LIST__TOKEN_TTL_SECS`          | `300`     | Advertised lifetime of the status list token.                                                                                                      |
| `APP_STATUS_LIST__SNAPSHOT_RETENTION_SECS` | `7776000` | Historical snapshot retention (default 90 days). `0` disables snapshots (draft-21 §12.7). `APP_STATUS_LIST__HISTORY_RETENTION_SECS` is deprecated. |

## Group 8 — Rate limiting & limits

| Variable                                 | Default   | Notes                            |
| ---------------------------------------- | --------- | -------------------------------- |
| `APP_RATE_LIMIT__STRICT_BURST_SIZE`      | `10`      | Strict (write endpoints) burst.  |
| `APP_RATE_LIMIT__STRICT_PERIOD_SECS`     | `60`      |                                  |
| `APP_RATE_LIMIT__PERMISSIVE_BURST_SIZE`  | `100`     | Permissive (public reads) burst. |
| `APP_RATE_LIMIT__PERMISSIVE_PERIOD_SECS` | `60`      |                                  |
| `APP_LIMITS__MAX_BODY_SIZE_BYTES`        | `2097152` | 2 MiB body limit.                |
| `APP_LIMITS__MAX_STATUS_INDEX`           | `100000`  |                                  |
| `APP_LIMITS__MAX_STATUSES_PER_REQUEST`   | `5000`    |                                  |
| `APP_LIMITS__MAX_SERIALIZED_LIST_SIZE`   | `1048576` | 1 MiB serialized list size.      |

## Group 9 — Telemetry / OpenTelemetry

| Variable                       | Default                      | Notes                                                                                    |
| ------------------------------ | ---------------------------- | ---------------------------------------------------------------------------------------- |
| `APP_TELEMETRY__ENVIRONMENT`   | `development`                | `development` (stdout) or `production` (OTLP export).                                    |
| `APP_TELEMETRY__OTLP_ENDPOINT` | `http://otel-collector:4317` | OTLP gRPC endpoint (production mode). Chart wires the in-cluster collector when enabled. |
| `APP_TELEMETRY__SAMPLER_RATIO` | `1.0`                        | 0.0–1.0 trace sampling ratio.                                                            |
| `APP_TELEMETRY__ENABLED`       | `true`                       | Toggle for the OTLP pipeline. Chart sets it based on collector availability.             |

## Group 10 — Docker Compose only (not used by Helm)

`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` and the MySQL `MYSQL_*` variables
configure the local Docker Compose database containers only; they are ignored by the
Helm chart and the running application in Kubernetes.

## Environment → chart mapping cheat-sheet

| App variable                                  | Helm value                                                            |
| --------------------------------------------- | --------------------------------------------------------------------- |
| `APP_DATABASE__PASSWORD`                      | always from `statuslist-secret` / `postgres-password`                 |
| `APP_DATABASE__PASSWORD_FILE`                 | `statuslist.secretMounts[].fileEnv` (path to mounted file)            |
| `APP_DATABASE__HOST/PORT/USERNAME/NAME/QUERY` | `statuslist.env.*`                                                    |
| `APP_AWS__REGION`                             | `statuslist.aws.region` (or legacy `secretStore.aws.region`)          |
| `APP_SERVER__DOMAIN`                          | `statuslist.ingress.externalDnsHostname`                              |
| `APP_SERVER__CERT__STORE__*_PATH`             | `statuslist.secretMounts[].fileEnv` (filesystem signing key)          |
| `APP_WATCHER__POLL_INTERVAL_SECS`             | `statuslist.watcher.pollIntervalSecs`                                 |
| `APP_TELEMETRY__OTLP_ENDPOINT`                | set by chart when `opentelemetry-collector.enabled=true`              |
| AWS credential files                          | `statuslist.aws.mountCredentials`                                     |
| DNS/cloud secrets                             | ESO `externalSecret`/`secretStore` → `statuslist-secret`              |
| Separately-mounted Secrets                    | `externalSecret.extraExternalSecrets[]` + `statuslist.secretMounts[]` |
