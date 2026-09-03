# Operator Troubleshooting Reference

This guide is an error-indexed reference for the Status List Server. Each entry maps an
exact error message or symptom to its root cause, copy-paste diagnostics, and a fix. It is
organized around the four operational areas that account for most incidents:

1. [Startup & Connection Failures](#startup--connection-failures)
2. [Secret & Token Key Rotation Failures](#secret--token-key-rotation-failures)
3. [Kubernetes & External Secrets Operator Issues](#kubernetes--external-secrets-operator-issues)
4. [Helm & Upgrade Issues](#helm--upgrade-issues)

Object names below follow the production release (`statuslist` in namespace
`statuslist-production`). Substitute your release/namespace for other deployments.

| Standard object    | Kubernetes name                                |
| ------------------ | ---------------------------------------------- |
| Deployment         | `statuslist-status-list-server-deployment`     |
| Application Secret | `statuslist-secret`                            |
| ExternalSecret     | `statuslist-external-secret`                   |
| SecretStore        | `statuslist-secret-store`                      |
| NetworkPolicy      | `statuslist-status-list-server-network-policy` |

> **Naming caveat:** Object names above assume release `statuslist` with **no
> `fullnameOverride`** set. The Deployment (`<fullname>-deployment`) and dependent object names
> derive from the Helm `fullname` helper, which honors `fullnameOverride`; if you set it, substitute
> that value for `statuslist-status-list-server` in every command below. The application Secret name
> is fixed (`statuslist-secret`) and is not configurable.

Application errors are quoted verbatim from the source (see the `Source` line in each entry),
so they stay grep-able. Kubernetes and External Secrets Operator (ESO) symptoms are platform
behaviors and are labeled as such.

---

## Startup & Connection Failures

### `Failed to connect to database (kind=connection, backend=postgres, host=..., port=..., database=...)`

**When you see this:** At startup, immediately after config validation. The message carries a
redacted target (backend, host, port, database) — never the password or URL. `kind` is the
classifier of the underlying driver failure: `connection` (TCP/auth handshake to the server)
and `connection_acquire` (could not get a pool connection within `acquire_timeout`), among a
small closed set (`connection`, `connection_acquire`, `execution`, `query`, `conversion`,
`last_insert_id`, `missing_primary_key`, `record_not_found`, `attribute_not_set`, `custom`,
`type`, `json`, `migration`, `record_not_inserted`, `record_not_updated`).

_Source: `src/setup.rs:158` (message), `src/setup.rs:101` (classifier)_

**Root cause:** One of:

- The database is unreachable on `host:port` (network policy, wrong service name, or the
  database is down).
- Invalid credentials (wrong username/password, or the secret mounted into the pod is stale
  or different from what the database expects).
- The configured `connect_timeout_secs` / `acquire_timeout_secs` are too low for the network
  in front of the database.

**Diagnostics:**

```bash
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=200
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n statuslist-production
# What host/port is the pod actually talking to?
kubectl get pod -l app.kubernetes.io/name=status-list-server -n statuslist-production -o jsonpath='{.items[*].spec.containers[*].env}'
# The password is mounted as a file; confirm the mount and its key names (never the value):
kubectl get secret statuslist-secret -n statuslist-production \
  -o go-template='{{range $k,$v := .data}}{{println $k}}{{end}}'
```

**Fix:**

- Confirm reachability from inside the pod. The published image is scratch-based (no shell or
  `nc`), so attach a temporary debug container with a utility image instead of `exec`:

  ```bash
  kubectl debug -it deploy/statuslist-status-list-server-deployment -n statuslist-production \
    --image=alpine -- sh -c 'command -v nc || apk add --no-cache netcat-openbsd; nc -vz <db-host> <db-port>'
  ```

- Fix credentials: rotate `postgres-password` in the secret, or correct the database
  `username`/`name`. See the Kubernetes section below when a `CrashLoopBackOff` wraps this.
- If the error is `kind=connection_acquire`, raise `database.pool.max_connections` headroom or
  the `acquire_timeout_secs` in your values (`APP_DATABASE__POOL__*`).

**Prevention:** Keep the pool tuning consistent with the database's `max_connections`
("pool.max = floor(pg_max / replicas) - 5", see `src/config.rs` `DatabasePoolConfig`). Verify a
password rotation by restarting the rollout and watching this specific message disappear.

---

### `Failed to connect to database ... pool timed out while waiting for an open connection` while PostgreSQL is reachable and authenticates

**When you see this:** At startup, the pod crash-loops (`CrashLoopBackOff`) with the *pool*
timeout message rather than an immediate connect/auth error. Raising `APP_DATABASE__POOL__*`
timeouts (e.g. `ACQUIRE_TIMEOUT_SECS=60`, `CONNECT_TIMEOUT_SECS=60`) does **not** help: the pod
keeps exiting after roughly the same delay.

**Observed during local k3d testing (two-node cluster):** this is a **distinct** failure from the
`kind=connection` / `kind=connection_acquire` entry above. The PostgreSQL pod is `Running` and
ready, DNS resolves, raw TCP to the ClusterIP is open, and a standalone `psql` client
(`sslmode=disable`) connects and returns `SELECT 1` — yet the application's connection pool still
times out. Critically, **PostgreSQL logs (e.g. `kubectl logs <postgres-pod>`) show no connection
activity at all** and the app init container's `wait-for-postgres` `nc -z` probe succeeds. This
means the pool connectors are not completing a connection to the database.

**Diagnostics:**

```bash
kubectl get pods -n <namespace> -o wide
kubectl logs -l app.kubernetes.io/name=status-list-server -n <namespace> --tail=50
kubectl logs -n <namespace> <postgres-pod> --tail=100   # look for "connection authorized" / auth errors
# Confirm the target host actually resolves from the app's node:
kubectl get svc -n <namespace> <release>-postgres -o jsonpath='{.spec.clusterIP}{"/"} {.spec.ports[0].port}{"\n"}'
kubectl run pgcheck --image=postgres:16.3 --restart=Never --env="PGPASSWORD=<pw>" --command -- \
  sh -c 'timeout 15 psql "host=<release>-postgres.<ns>.svc.cluster.local port=5432 user=postgres dbname=<db> sslmode=disable connect_timeout=8" -c "SELECT 1;"'
kubectl delete pod pgcheck --ignore-not-found
```

`switching sslmode=disable via APP_DATABASE__QUERY and raising the pool timeouts` are both
confirmed **not** to resolve it here.

**Fix:** Not yet established — a maintainer must confirm whether the application's connection
pool is failing to initiate the TCP/driver handshake (e.g. driver TLS or a resolution path that
differs from `psql`) on multi-node clusters. Treat this as **upstream investigation**, not an
operator misconfiguration. If you only need a local smoke test, a single-node cluster (one server,
no agent) avoids the cross-node path.

**Prevention:** Keep PostgreSQL and the application on the same node for local/dev testing, and
verify the database truly received a connection attempt (postgres logs) before assuming an auth or
pool-tuning problem.

---

### `Database backend 'X' configured, but feature flag for it was not compiled in.`

**When you see this:** At startup, when the configured `database.backend` is `Memory` and the
`memory` feature is absent, or any backend whose compile-time feature was not enabled. There are
**two distinct messages** depending on which backend is missing; grep for either variant:

- `Database backend 'memory' configured, but 'memory' feature flag was not compiled in.`
  (the `Memory` backend when the `memory` feature is absent)
- `Database backend 'X' configured, but feature flag for it was not compiled in.`
  (a backend compiled out entirely, no SQL/memory feature present)

_Source: `src/setup.rs:431` (memory variant), `src/setup.rs:472` (generic variant)_

**Root cause:** Image **variant mismatch** — the container image you pulled was built with a
different feature set than the configuration expects (e.g. a build without `postgres`/`sqlite`/
`mysql`/`memory` being told to use that backend).

**Diagnostics:**

```bash
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=50
helm get values statuslist -n statuslist-production
kubectl get pod -l app.kubernetes.io/name=status-list-server -n statuslist-production -o jsonpath='{.items[0].spec.containers[0].image}'
```

**Fix:** Use the image variant compiled for your backend, or set `database.backend` to a backend
the image supports. Default backend by feature set is defined in `src/config.rs` `base_builder`
(`postgres` when `postgres` is compiled, else `sqlite`, else `mysql`, else `memory`).

**Prevention:** Document which image tag/variant each backend maps to, and pin `statuslist.image`
(digest preferred) so a drifting tag cannot silently change the compiled feature set.

---

### `URL scheme does not match configured backend 'X'. Expected URL starting with ...`

**When you see this:** At startup, when validating the database connection string against the
selected `database.backend`.

_Source: `src/setup.rs:133`, schemes in `src/config.rs`_

**Root cause:** Backend vs scheme mismatch, e.g. `APP_DATABASE__BACKEND=postgres` with a
`mysql://` URL, or a URL using `postgresql://` where the validator only accepts the exact
prefix set. Expected prefixes: `memory:`/`memory`, `postgres://`/`postgresql://`, `mysql://`,
`sqlite:`.

**Diagnostics:**

```bash
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=50
helm get values statuslist -n statuslist-production
```

**Fix:** Align `database.backend` with the URL scheme (prefer the split fields — see next entry,
which avoids assembling URLs in pod metadata entirely).

**Prevention:** Use split database fields (`APP_DATABASE__HOST/PORT/USERNAME/NAME/QUERY`) with
`APP_DATABASE__BACKEND` rather than a hand-assembled `database.url`.

---

### `Ambiguous database configuration: use either database.url or split database fields, not both`

**When you see this:** At startup, when both the full `database.url` _and_ any split field
(`host`, `username`, `password`, `name`) are set.

_Source: `src/config.rs:749`_

**Root cause:** Mixed configuration — the app refuses to guess which source wins.

**Diagnostics / Fix:** Inspect the effective env (`helm get values`, or the pod env as in the
first entry). Keep exactly one source of truth: either `APP_DATABASE__URL` alone, or the split
fields with the chart-managed `APP_DATABASE__PASSWORD_FILE` mount. Remove the other.

**Prevention:** The Helm chart already rejects `APP_DATABASE__URL` (it would expose assembled
credentials in pod metadata) — see the Helm section. Use the split fields on Kubernetes.

---

### `Missing required config field: database.password`

**When you see this:** At startup, when a split database field required to assemble the URL is
absent/empty. The same pattern applies to `database.host`, `database.username`, `database.name`,
and to the combined `database.url or split database fields`.

_Source: `src/config.rs:638-650` (`required_config_field` / `required_secret_field`), call sites `src/config.rs:769-775`, combined-message `src/config.rs:742`_

**Root cause:** A required config value is not present. In the Helm/deployment model this is
usually a **missing or empty secret mount / env**: the pod has no `APP_DATABASE__PASSWORD_FILE`
pointing at a mounted password, or `statuslist-secret` is missing the `postgres-password` key.

**Diagnostics:**

```bash
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=50
# List the secret's key names (never their values):
kubectl get secret statuslist-secret -n statuslist-production \
  -o go-template='{{range $k,$v := .data}}{{println $k}}{{end}}'
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n statuslist-production
```

**Fix:** Ensure the secret with the `postgres-password` key exists and is referenced. In ESO
mode, confirm the ExternalSecret synced it (see the Kubernetes section). In fallback mode,
confirm `statuslist.fallbackSecret.stringData` contains the key.

**Prevention:** Never deliver the password as a plain env value; the chart rejects
`APP_DATABASE__PASSWORD` as a literal and mounts the secret to a file via
`APP_DATABASE__PASSWORD_FILE` instead. The file mount is what lets the watcher pick up a
rotation without a pod restart (see the rotation section below).

---

### Invalid `database.host` or `database.query` validation errors

**When you see this:** At startup. Two distinct messages:

- `Invalid database.host: expected a hostname or IP address without scheme, port, path, userinfo, query, or fragment`
- `Invalid database.query: query parameter keys must be non-empty and contain only ASCII letters, digits, '.', '_' or '-'`
- `Invalid database.query: credential-like query parameter key '...' is not allowed`

_Source: `src/config.rs:687-707` (host validator, message at `706`), `src/config.rs:653-680` (query validator, messages at `666` and `679`)_

**Root cause:** `database.host` contained a scheme/port/userinfo/`@`/`?`/`#`/whitespace, or
trailing/leading `-`/`.`; or `database.query` used a forbidden credential-like key
(`password`, `passwd`, `secret`, `token`, `user`, `username`).

**Diagnostics / Fix:** Correct the offending value. Put port/user/name in their own split fields,
never inside `host`. Put TLS/driver settings such as
`sslmode=verify-full&sslrootcert=/certs/ca.crt` into `database.query` and keep credentials out of
it.

**Prevention:** Use the split fields and a strictly TLS/`sslmode`-only query string.

---

### Vault authentication errors (AppRole vs Kubernetes)

**When you see this:** At startup (the Vault client logs in during construction) or on renewal.
Several distinct strings:

- `Vault auth_method=approle requires 'role_id' to be configured`
- `Vault auth_method=kubernetes requires 'k8s_role' to be configured`
- `Vault configuration missing secret_id: provide 'secret_id' or 'secret_id_path'`
- `Failed to read Vault secret_id from file '...': ...`
- `vault AppRole login denied (HTTP 403)` / `vault Kubernetes login denied (HTTP 403)`
- `vault {AppRole|Kubernetes} login failed: HTTP <status>: <body>`
- `failed to read Kubernetes service account token from '...': ...`
- `Kubernetes service account token in '...' is empty`

_Source: `src/setup.rs:715, 725` (config gate), `src/config.rs:894-908` (secret_id resolve), `src/outbound/vault.rs:491, 498` (SA token), `src/outbound/vault.rs:563, 574` (login)_

**Root cause:**

- AppRole: `role_id` missing, or `secret_id`/`secret_id_path` unset/empty/unreadable, or the
  role/secret pair is rejected (403 usually means the role or secret-id revoked/wrong).
- Kubernetes: `k8s_role` missing, the SA token file at `vault.k8s_token_path` is unreadable or
  empty, or Vault denies the JWT for that role (403).
- Address typo / wrong `vault.auth_mount` / missing `X-Vault-Namespace`.

**Diagnostics:**

```bash
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=100
# List secret key names (never values):
kubectl get secret statuslist-secret -n statuslist-production \
  -o go-template='{{range $k,$v := .data}}{{println $k}}{{end}}'
# Confirm the service-account token volume is mounted and the expected env is present:
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n statuslist-production
kubectl get pod -l app.kubernetes.io/name=status-list-server -n statuslist-production \
  -o jsonpath='{.items[*].spec.containers[*].env}'
```

The published image is scratch-based (no shell), so to inspect the mounted SA token file at
`vault.k8s_token_path` attach a temporary debug container instead of `kubectl exec`:

```bash
kubectl debug -it deploy/statuslist-status-list-server-deployment -n statuslist-production \
  --image=busybox -- ls -l /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null || true
```

**Fix:** Set the missing config (`vault.role_id` / `vault.secret_id` / `vault.secret_id_path`;
`vault.k8s_role` + `vault.k8s_token_path`). For 403s, fix the Vault role binding — role/secret_id
must match, and the Kubernetes auth role must be bound to the service account the pod runs as.
Set `vault.namespace` when the mount is tenant-scoped.

**Prevention:** Prefer the Kubernetes auth method on EKS (the SA token is rotated by the
platform) and keep the K8s role bound to the minimal ServiceAccount.

---

## Secret & Token Key Rotation Failures

> **Accuracy note:** The application reloads the database password **in-process** when it is
> delivered as a file. `spawn_database_rotation` (`src/setup.rs:166`) watches the path named by
> `APP_DATABASE__PASSWORD_FILE` (the chart mounts it by default under
> `/var/run/status-list-server/database/password`) via `FileWatcher`. On change it builds and
> validates a **new** pool, atomically swaps it into the repositories, then drains the old pool.
> On validation failure the old pool is retained. This replaces the historical "restart required"
> model for images with the watcher and a file-mounted password; a restart is still required only
> when the running image predates the watcher or the password is delivered as an environment
> variable rather than a file.
>
> Vault tokens are renewed/re-authenticated in-process by `TokenManager` (see the Vault entry
> below). The filesystem token-signing material is also watched and reloaded in-process when the
> `-fscert`/store strategy is used.

### Database pool rotation after password-file change

**When you see this:** You rotate `postgres-password` and update the Secret the pod mounts. The
running pod picks the change up without a restart once the watcher notices the mounted file
changed.

**How it works (`spawn_database_rotation`, `src/setup.rs:166-222`):**

- The watcher uses the OS file watcher where it is available and falls back to polling every
  `watcher.poll_interval_secs` (default `30`). With a Kubernetes Secret volume, the kubelet
  updates the mounted file when the Secret changes; the watcher sees it.
- On a change it connects a brand-new pool from the current config and `ping()`s it. If the ping
  succeeds (`rotation_succeeded`), the new pool is swapped in atomically and the old pool is
  drained and closed in the background. If validation fails (`rotation_failed`), the **old pool
  is retained** and the app keeps serving on the previous credential.
- Log markers to watch for: `rotation_started`, `rotation_succeeded`, `rotation_failed` (the
  latter two also drive `rotation_failed`/`rotation_succeeded` metrics).

**Diagnostics:**

```bash
kubectl get events -n statuslist-production --sort-by=.lastTimestamp | tail -40
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=100
# Confirm the password is delivered as a file the watcher can see:
kubectl get pod -l app.kubernetes.io/name=status-list-server -n statuslist-production \
  -o jsonpath='{.items[*].spec.containers[*].env}'
# Confirm the Secret exists and the key is present (names only):
kubectl get secret statuslist-secret -n statuslist-production \
  -o go-template='{{range $k,$v := .data}}{{println $k}}{{end}}'
```

**If rotation did not happen / the app still uses the old password:**

- Rotation only runs when `database.password_file` is set (the chart sets it via
  `APP_DATABASE__PASSWORD_FILE`). If the password is delivered as a literal environment
  variable or the image predates the watcher, there is nothing to watch and a restart is still
  required:

  ```bash
  kubectl rollout restart deployment/statuslist-status-list-server-deployment -n statuslist-production
  kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist-production
  ```

- Check the pod actually mounts the Secret (a stale mount or a Secret that never changed means
  the file content is unchanged, so the watcher reports no change).
- When rotation is automated (ESO), the app Secret is rewritten by the controller; the watcher
  only fires after the kubelet propagates the new file into the pod volume.

**Prevention:** Deliver the password as a file (`APP_DATABASE__PASSWORD_FILE`, the chart
default), keep the watcher polling interval aligned with your rotation cadence, and watch for
`rotation_failed`; the old pool is retained on validation failure, so a failed rotation is
non-disruptive but leaves the app on the previous credential until the file is valid again.

---

### Token signing key / certificate mismatch or invalid PEM encoding

**When you see this:** At startup, when the store provisioning strategy loads and parses
certificate material. Strings include:

- `{certificate|signing key} material must be PEM text or base64/base64url-encoded DER`
- `signing key PEM is not valid UTF-8: ...`
- `failed to read certificate file '...': ...` / `failed to read signing key file '...': ...`
- `store certificate key '...' was not found` / `store signing key '...' was not found`
- Store validation: both-paths-and-keys, missing file, or missing key errors from
  `store_certificate_strategy`

_Source: `src/utils/cert_manager/strategy.rs:92-222`, `src/setup.rs:831` (`store_certificate_strategy`), `src/setup.rs:487` (call site)_

**Root cause:** The cert and signing key do not match (a rotated key paired with the old cert), a
file/key is missing or unreadable, or the stored value is neither PEM nor base64 DER (e.g. a
secret written as plain text or with a stray newline).

**Diagnostics:**

```bash
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=50
# List the secret's key names (never values):
kubectl get secret statuslist-secret -n statuslist-production \
  -o go-template='{{range $k,$v := .data}}{{println $k}}{{end}}'
```

**Fix:** Replace the material with a **matching** cert + PKCS#8 key pair in the expected encoding
(PEM containing `-----BEGIN ...`, or standard/base64url DER). Confirm both keys exist and are
readable at the configured path/store-key. When the signing material is file-mounted under the
`store` strategy, `spawn_acme_store_rotation` (`src/setup.rs:246`) reloads it in-process on file
change; a rollout is only needed to re-read a changed value when it is delivered another way:

```bash
kubectl rollout restart deployment/statuslist-status-list-server-deployment -n statuslist-production
```

**Prevention:** Rotate cert and key together in one transaction, and validate the pair locally
(`openssl x509 -noout -pubkey -in cert.pem` vs `openssl pkey -pubout -in key.pem`) before
writing it to the store/mount.

---

### Vault token renewal / re-authentication failures

**When you see this:** Runtime only (Vault is used as the crypto-material backend). The
`TokenManager` renews at 80% of TTL via `renew-self`, then re-logs-in if renewal fails. Failure
strings include:

- `Token renewal failed, re-authenticating: <err>` (renewal failed, re-login attempted)
- `vault authentication in cooldown backoff after recent failure` (5s cooldown after a failure)
- `token renewal failed: HTTP <status>: <body>`
- `vault access denied for path '<path>'` (login OK, but the token lacks the KV policy)
- `vault load failed for path '<path>': HTTP <status>` / `vault store failed ...`

_Source: `src/outbound/vault.rs:619-780` (TokenManager), `src/outbound/vault.rs:843-920` (KV ops)_

**Root cause:** The Vault token or the underlying role no longer has access (403 on read/write),
the AppRole `secret_id` was revoked/rotated, the Service Account JWT was rotated and Vault no
longer honors it, or the Vault server is unreachable during renewal.

**Diagnostics:**

```bash
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=100
# Vault-side (run against your Vault/OpenBao):
vault token lookup   # confirm the client token is alive and renewable
vault policy list
```

**Fix:** Recreate the AppRole `secret_id` / K8s auth role binding, or restore Vault reachability.
Because the app re-authenticates automatically, repairing the credential is usually enough — no
restart required unless the KV policy/path prefix is wrong (fix `vault.path_prefix`, `vault.mount`).

**Prevention:** Keep `vault.secret_id` in a secret (not plaintext config), and prefer renewable
tokens with adequate `lease_duration` so the 80% renewal window has headroom. Ensure the token
policy grants the KV paths actually used.

---

## Kubernetes & External Secrets Operator Issues

### Pod `CrashLoopBackOff` waiting for database or secret mount

**When you see this:** `kubectl get pods` shows `CrashLoopBackOff`; the container is starting and
exiting with one of the startup errors in the first section.

**Root cause:** The pod cannot reach the database or cannot read a required secret at startup
(config errors above surface as a crash, not a healthy retry). Initializing containers
(`statuslist.initContainers`, e.g. a `wait-for-postgres` probe) may also be failing, keeping the
app from ever starting.

**Diagnostics:**

```bash
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n statuslist-production
kubectl get events -n statuslist-production --sort-by=.lastTimestamp | tail -40
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=200 --previous
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=200
```

**Fix:** Resolve the underlying startup error (see Section 1). If an init container is the
gate, confirm the DB service name/DNS (`<release>-postgres.<ns>.svc.cluster.local`) is correct
and reachable.

**Prevention:** Verify the manifest renders with `helm template --validate` before applying, and
confirm the DB/Secret exist ahead of the rollout.

---

### ExternalSecret sync errors (`Synced=False` / `SecretSyncedError`)

**When you see this:** The app Secret (`statuslist-secret`) is missing or stale, so the pod
fails readiness/startup. This is a **platform scenario**: the `ExternalSecret` CR reports a sync
condition — the term `SecretSyncedError` appears as the `Condition.Reason` on the ExternalSecret,
not as an application log line.

**Root cause:** The ESO controller could not reconcile the ExternalSecret to the SecretStore:
provider auth failure, wrong `secretStoreRef` name/kind, a `refreshInterval` not yet elapsed, or
the SecretStore itself is unhealthy.

**Diagnostics:**

```bash
kubectl get externalsecret statuslist-external-secret -n statuslist-production
kubectl describe externalsecret statuslist-external-secret -n statuslist-production
kubectl get secretstore statuslist-secret-store -n statuslist-production
kubectl describe secretstore statuslist-secret-store -n statuslist-production
kubectl get externalsecret statuslist-external-secret -n statuslist-production \
  -o jsonpath='{.status.conditions[?(@.type=="Ready")]}'
# List app-secret key names (never values):
kubectl get secret statuslist-secret -n statuslist-production \
  -o go-template='{{range $k,$v := .data}}{{println $k}}{{end}}'
```

Check the `Ready`/`Synced` conditions and the `Message` for the specific provider error. Confirm
`spec.secretStoreRef.name` = `statuslist-secret-store` and `kind` = `SecretStore` (they are
validated at render time — see the Helm section).

**Fix:** Depends on the reported provider error, e.g.:

- AWS: the ESO SecretStore needs an explicit `region` (ESO does not read pod instance metadata).
- Vault: verify the provider `auth` block and that the policy grants the KV path.
- Azure WorkloadIdentity: `secretStore.azure.serviceAccountRef.name` must reference the **ESO
  controller** ServiceAccount, not the app one.

After fixing the provider, force a refresh if you do not want to wait `refreshInterval`:

```bash
kubectl annotate externalsecret statuslist-external-secret -n statuslist-production \
  force-sync=$(date +%s) --overwrite
```

**Prevention:** Deliver the SecretStore provider credentials correctly up front, and monitor the
`ExternalSecret` `Ready=True` condition as the source of truth that the app Secret will be
present.

---

### Pod `Running` but never binds the HTTP port — `connection refused` on the liveness probe (ACME provisioning blocks startup)

**When you see this:** The pod reaches `Running` but stays `NotReady` and keeps restarting; the
liveness probe fails with `Get "http://<pod-ip>:<port>/health/live": connect: connection refused`,
and `curl` against the service/NodePort returns `000`/empty reply. The application log stops
immediately after `telemetry initialized` with no further startup lines — the HTTP server never
binds its `APP_SERVER__PORT` (e.g. `8000`).

**Root cause:** The container image is built with the `acme` Cargo feature, and under that feature
the **default `server.cert.provisioning_strategy` is `acme`** (`src/config.rs:1044-1045`). With
strategy `acme`, the application attempts ACME DNS-01 certificate provisioning at startup, which
requires a DNS provider and credentials (see `dns-providers.md`). `values-local.yaml` and
`LOCAL_DEPLOYMENT.md` do not override the cert values, so they inherit the production defaults
from `values.yaml` — `APP_SERVER__CERT__DNS__PROVIDER=route53`,
`APP_SERVER__CERT__EMAIL=info@adorsys.com`, `APP_SERVER__DOMAIN=statuslist.eudi-adorsys.com`, and
the Let's Encrypt directory URL — and block before binding the HTTP server.

**Diagnostics:**

```bash
kubectl get pod -n <namespace> -o wide
kubectl describe pod -n <namespace> -l app.kubernetes.io/name=status-list-server | grep -iA3 "liveness probe failed\|connection refused"
kubectl logs -n <namespace> -l app.kubernetes.io/name=status-list-server --tail=20
# Confirm the acme strategy is in effect:
kubectl get deploy -n <namespace> <release>-status-list-server-deployment \
  -o jsonpath='{.spec.template.spec.containers[0].env}' | grep -i provisioning
```

**Fix (two options):**

- Point the DNS provider at a local/dev ACME server, e.g. set `APP_SERVER__CERT__DNS__PROVIDER`
  to `pebble` and `APP_SERVER__CERT__DNS_CHALLENGE_SERVER_URL` at your Pebble instance (dev only),
  **or**
- Switch the provisioning strategy to `store` and provide matching certificate + signing-key
  material, e.g. `--set-string statuslist.env.APP_SERVER__CERT__PROVISIONING_STRATEGY=store` plus
  `statuslist.secretMounts` provisioning `APP_SERVER__CERT__STORE__CERTIFICATE_PATH` /
  `APP_SERVER__CERT__STORE__SIGNING_KEY_PATH` from a Secret (see `values.yaml` `secretMounts`
  example and the `-fscert` variant in the runbook).

**Prevention:** For any local/dev run, decide up front whether you want certificate provisioning
at all. Disable or retarget ACME *before* installing; the runbook's "Expose the service (Ingress)"
note already advises this, but neither `values-local.yaml` nor `LOCAL_DEPLOYMENT.md` actually
turns it off — a gap that should be fixed in the local values.

---

### Readiness probe failures (`/health/ready`)

**When you see this:** Pods are `Running` but `NotReady`; the Deployment's readiness probe on
`/health/ready` returns `503` (`NOT_READY`) while `/health/live` keeps returning `200` (`OK`).
Liveness is deliberately decoupled from downstream dependencies; readiness flips only when a
critical dependency check fails or times out (5s), with results cached 1s.

_Source: `src/server/health.rs:149-155` (ready, `readiness check failed`), checks `src/server/health.rs:183-269`_

**Root cause:** One of the registered readiness checks fails. Checks are named `database`
(`DbCheck`, pings the pool — reason `database unreachable: ...`) and `cert_store`
(`CertStoreCheck` for Vault/secret-store reachability, or `FilesystemCertCheck` for the
filesystem cert paths).

**Diagnostics:**

```bash
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n statuslist-production
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=200
# Replicate the probe against a running pod (or a local instance):
curl -s -o /dev/null -w '%{http_code}\n' http://<pod-ip>:<port>/health/ready
curl -s http://<pod-ip>:<port>/health/ready
```

The detailed failure reasons are logged at `WARN` (`readiness check failed`) rather than
exposed in the unauthenticated response — read the pod logs.

**Fix:** Address the failing dependency: DB reachable/auth OK, or the cert store reachable /
cert files present and readable. In filesystem mode, `FilesystemCertCheck` fails if the cert or
key path is missing or unreadable, independent of the key parses as PEM.

**Prevention:** Treat `/health/ready` as the only gate for the readiness probe, and alert on the
`ready=false` transition rather than process liveness.

---

### Network policy egress blocks DB, Vault, or OTLP collector

**When you see this:** The app logs timeout/connection errors to Postgres, Vault, or the OTLP
collector, or readiness fails on `database unreachable`, while the services are verifiably up.

_Source (chart): `helm/chart/templates/network-policy.yaml`_

**Root cause:** When `statuslist.networkPolicy.enabled`, the rendered `NetworkPolicy` scopes
egress as follows:

- the `postgres` pods (selector `app.kubernetes.io/name=postgres`) plus anything appended via
  `statuslist.networkPolicy.egressInternal` — on the database port only;
- **any destination** on TCP `443` and TCP/UDP `53` (DNS/HTTPS) — this egress rule has no
  destination selector, so it is not limited to the pod selectors;
- and, when the `opentelemetry-collector` subchart is enabled, the collector pods on `4317`/`4318`.

Any other egress — a Vault/OpenBao server on a non-443 port, a different DB service name, an OTLP
collector on a different port, or a `podSelector` that does not match the target labels — is
silently dropped. Note that a Vault server exposing 443 may actually be reachable (the 443/53 rule
is open to all destinations); if it is blocked, it is usually on a non-443 port or because egress
`ipBlock`/`podSelector` coverage is missing.

**Diagnostics:**

```bash
kubectl get networkpolicy statuslist-status-list-server-network-policy -n statuslist-production -o yaml
kubectl describe networkpolicy statuslist-status-list-server-network-policy -n statuslist-production
kubectl get pods -l app.kubernetes.io/name=postgres -n statuslist-production
kubectl get pods -l app.kubernetes.io/name=opentelemetry-collector -n statuslist-production
```

**Fix:** Understand the chart's current limitation before changing anything:
`statuslist.networkPolicy.egressInternal` only appends destination `to` selectors **beneath the
existing database-port rule** (`network-policy.yaml:33-39`) — it cannot open a new port. There is
no chart value today for arbitrary extra egress rules. So:

- A **database** whose pods/labels differ from `app.kubernetes.io/name=postgres` can be reached by
  adding its selector under `statuslist.networkPolicy.egressInternal` (the port stays the
  database port).
- A **Vault/OpenBao or other backend on a non-443 port** (e.g. `8200`) **cannot** be unblocked
  with `egressInternal`. Realistic options:
  - expose Vault so the app can reach it on an already-allowed port (e.g. `443` — the `443/53`
    rule has no destination selector, so it is open to all destinations); or
  - set `statuslist.networkPolicy.enabled=false` and provide your own `NetworkPolicy` that opens
    the ports your deployment actually needs; or
  - extend the chart to render configurable extra egress rules (a chart change, not a values
    change).

Confirm target pods carry the selector labels the policy expects (`postgres`,
`opentelemetry-collector`) and that `$otel.enabled` matches the OTLP rule.

**Prevention:** Enumerate every runtime dependency (DB, Vault/secret backend, OTLP) up front and
make sure each is reachable on an allowed port under the default policy. If you need a port the
chart does not open (Vault on a non-443 port), plan on providing your own `NetworkPolicy`
(`statuslist.networkPolicy.enabled=false`) rather than relying on `egressInternal`.

---

## Helm & Upgrade Issues

### Values schema validation rejections

**When you see this:** `helm upgrade`/`helm install` fails at validation with a schema/render
error. Validation comes from two layers: the JSON Schema at `helm/chart/values.schema.json` and
explicit `fail` guards in the templates.

Template `fail` messages you may hit include (from the chart source):

- `externalSecret.enabled requires secretStore.enabled: ...` (`external-secrets.yaml:3`)
- `externalSecret.spec.target.name must be 'statuslist-secret' to match ...` (`external-secrets.yaml:6`)
- `secretStore.provider '<p>' is not supported. Supported providers: aws, vault, gcp, azure, raw` (`secret-store.yaml:10`)
- For `vault`/`gcp`/`azure`: missing `server`, `projectID`, `vaultUrl`, `tenantId`, identity fields (`secret-store.yaml:17-42`)
- `statuslist.image.digest must be sha256:<64 hex chars>, got ...` (`deployment.yaml:75`)
- `statuslist.env.APP_DATABASE__URL is not supported ...` / `...APP_DATABASE__PASSWORD must not be set as a plain env value...` (`deployment.yaml:104-109`)
- `statuslist.env.APP_DATABASE__PORT is required ...` (`deployment.yaml:110-112`)
- `externalSecret.enabled and statuslist.fallbackSecret.enabled cannot both be true ...` (`deployment.yaml:2-4`)

**Root cause:** Values violate the schema or a template invariant (wrong provider, missing
required secret fields, a digest not in `sha256:<64 hex>` form, mutually exclusive features both
enabled).

**Diagnostics / Fix:**

```bash
helm lint helm/chart -f <your-values>.yaml
helm template statuslist helm/chart -f <your-values>.yaml --namespace statuslist-production \
  --debug --validate
# Show just the failing assertion when present:
helm template statuslist helm/chart -f <your-values>.yaml --namespace statuslist-production 2>&1 | head -40
```

Correct the flagged value. Fixes are implied by each message: pick one, mutually-exclusive mode;
provide the provider-required fields; use split DB env (never `APP_DATABASE__URL`/literal
`APP_DATABASE__PASSWORD`); set `APP_DATABASE__PORT`; give a real digest.

**Prevention:** Validate locally with `helm template --validate` before applying, and keep the
values file schema-conformant. The chart deliberately fails at render time instead of producing
a cluster that later shows `ImagePullBackOff`/`CrashLoopBackOff`.

---

### Image pull errors on variant tags

**When you see this:** Pods report `ErrImagePull` / `ImagePullBackOff` after a release.

**Observed with the default chart install:** the chart's `appVersion` is `1.0.1-aws`
(`Chart.yaml`), so with `statuslist.image.tag` empty the Deployment resolves the image
`ghcr.io/adorsys/status-list-server:1.0.1-aws`. That specific tag is **not published**: the GHCR
package currently carries only unsuffixed tags (`latest`, `main`, `1.0.0`, `1.0.1`, `1.0`, `sha-…`),
and **no `*-aws`/`*-gcp`/`*-fscert` variant tags exist**. The result is exactly this symptom:

```text
Failed to pull image "ghcr.io/adorsys/status-list-server:1.0.1-aws":
rpc error: code = NotFound ... ghcr.io/adorsys/status-list-server:1.0.1-aws: not found
```

To proceed, pin an image tag that actually exists, e.g.
`--set statuslist.image.tag=latest` (or `main`, `1.0.1`). See the runbook's "Pinning the image".

**Root cause:** The image reference does not exist or is not pullable — wrong tag, a typo in the
repository/tag, `pullPolicy` behavior, or variant tags differing across builds. In the chart,
`statuslist.image.digest` (when set) takes precedence over `statuslist.image.tag`; an empty tag
falls back to `appVersion` (`deployment.yaml:69-82`). A digest not matching `sha256:<64 hex>`
fails at template time, so a pull-backoff here means the reference was validly shaped but not
present/permitted.

**Diagnostics:**

```bash
kubectl get pod -l app.kubernetes.io/name=status-list-server -n statuslist-production -o yaml | grep -A3 'image:'
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n statuslist-production | grep -i -A3 'pulled\|image'
kubectl get events -n statuslist-production --sort-by=.lastTimestamp | tail -20
helm history statuslist -n statuslist-production
```

**Fix:** Set a valid, present tag/digest. Because digest precedence means a stored digest wins
over a changed tag, when re-promoting a digest-only change you must pass the new digest (or clear
it with `--set statuslist.image.digest=null`) — a plain tag change under `--reuse-values` will
"succeed" and change nothing.

```bash
helm upgrade statuslist helm/chart -n statuslist-production \
  --reuse-values \
  --set statuslist.image.repository=<repo> \
  --set statuslist.image.tag=<tag> \
  --set statuslist.image.digest=<sha256:... or null>
```

**Prevention:** Pin `statuslist.image.digest` to the exact scanned artifact (the release workflow
does this) and keep the tag human-readable in `helm history`. Use `--rollback-on-failure --wait` so a pull
failure rolls back instead of wedging the release.

---

## Index of exact error strings

For quick grep, the application emits these verbatim (with the primary source file):

- `Failed to connect to database (kind=..., ...)` — `src/setup.rs`
- `Database backend '...' configured, but feature flag for it was not compiled in.` — `src/setup.rs`
  (and `Database backend 'memory' configured, but 'memory' feature flag was not compiled in.`) — `src/setup.rs:184-187`
- `URL scheme does not match configured backend '...'` — `src/setup.rs`
- `Ambiguous database configuration: use either database.url or split database fields, not both` — `src/config.rs`
- `Missing required config field: database.password` (and `database.host`, `database.username`, `database.name`, `database.url or split database fields`) — `src/config.rs`
- `Invalid database.host: expected a hostname or IP address without scheme, port, ...` — `src/config.rs`
- `Invalid database.query: ...` (two variants) — `src/config.rs`
- `Vault auth_method=approle requires 'role_id' to be configured` / `...'k8s_role'...` — `src/setup.rs`
- `Vault configuration missing secret_id: provide 'secret_id' or 'secret_id_path'` — `src/config.rs`
- `Failed to read Vault secret_id from file '...'` — `src/config.rs`
- `vault AppRole|Kubernetes login denied (HTTP 403)` / `vault ... login failed: HTTP <status>` — `src/outbound/vault.rs`
- `failed to read Kubernetes service account token from '...'` / `Kubernetes service account token in '...' is empty` — `src/outbound/vault.rs`
- `Token renewal failed, re-authenticating: ...` / `token renewal failed: HTTP <status>` / `vault authentication in cooldown backoff after recent failure` — `src/outbound/vault.rs`
- `vault access denied for path '...'` / `vault load|store|delete failed for path '...': HTTP <status>` — `src/outbound/vault.rs`
- `... material must be PEM text or base64/base64url-encoded DER` / `signing key PEM is not valid UTF-8: ...` — `src/utils/cert_manager/strategy.rs`
- `failed to read certificate|signing key file '...'` — `src/utils/cert_manager/strategy.rs`
- `store certificate key '...' was not found` / `store signing key '...' was not found` — `src/utils/cert_manager/strategy.rs`
- `readiness check failed` (WARN) — `src/server/health.rs`

Platform-only (no matching application string): `ImagePullBackOff`, `ErrImagePull`,
`CrashLoopBackOff`, `SecretSyncedError` / `Synced=False`, and all Helm `fail` guards listed in
the Helm section.

Local-k3d `ErrImagePull` with the default chart install is caused by the unpublished
`appVersion` variant tag `1.0.1-aws` (pin a real tag such as `latest`); a pod stuck `Running` but
never binding its HTTP port with `connection refused` on `/health/live` is the ACME
provisioning-strategy block (see the "Pod Running but never binds the HTTP port" entry above).
