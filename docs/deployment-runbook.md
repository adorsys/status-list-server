# Deployment Runbook

This runbook describes how to deploy the Status List Server project on a Kubernetes cluster. It lays out the deployment options available and the steps to follow.

## Deployment Options at a Glance

You have three broad ways to run the Status List Server:

- **Local / development** (Minikube, kind, Docker Desktop): manual testing and iteration, using [`chart/values-local.yaml`](../deploy/helm/chart/values-local.yaml).
- **Self-managed deploy** (recommended; any cluster you own): a real, repeatable deployment using `chart/values.yaml` plus your own overrides.
- **Bundled chart only**: bring your own containers or compose workflows (non-Helm).

The project ships a Helm chart (`deploy/helm/chart`) that is the recommended, supported way to deploy. The chart bundles:

- the **Status List Server** application Deployment, Service, and (optionally) Ingress;
- a **PostgreSQL** subchart for the database;
- an **OpenTelemetry Collector** subchart for traces/metrics/logs (optional).

Everything below assumes you deploy with Helm. The chart is the source of truth for how the application is configured and run; see [`deploy/helm/README.md`](../deploy/helm/README.md) for the full value reference and the [Next steps](#next-steps) section for supporting topics (secrets, DNS providers, database backends, observability).

## Prerequisites

- A Kubernetes cluster you can talk to (`kubectl` configured with the right context).
- `kubectl` and Helm 4 installed.
- Network access from the cluster to pull images, and if you use the ACME certificate provisioning, to the certificate authority and your DNS provider.
- A way to get images: either a registry account you control, or a local image load (Minikube/kind).

### Decide on your image

The chart's default `statuslist.image.repository` points at `ghcr.io/adorsys/status-list-server` for convenience. For your own deployment you will normally:

- **Build and push to your own registry**, then point `statuslist.image.repository` and `statuslist.image.tag` (or `digest`) at it, or
- **Load a locally built image** into a local cluster (Minikube `minikube image load`, kind `kind load docker-image`) and use `pullPolicy: IfNotPresent`.

Set `statuslist.image.tag` explicitly for ad hoc tags, or set `statuslist.image.variant` and leave `tag` empty to derive the matching variant tag from the chart `appVersion`. If both `tag` and `digest` are empty, the base chart uses the provider-neutral `fscert` variant. AWS production deployments select the `aws` variant explicitly through their values and deploy inputs. Prefer a `sha256:` `digest` for reproducible production deploys (see [Pinning the image](#pinning-the-image)).

## Option 1: Local / Development Deployment

The quickest path to a running instance, using `values-local.yaml`. It disables the Ingress, the External Secrets Operator and SecretStore CRs, and the OpenTelemetry Collector, and uses non-persistent PostgreSQL with lighter resources so it runs on a laptop.

### Steps

```bash
# 1. Start a local cluster (example: Minikube)
minikube start
kubectl config use-context minikube

# 2. Namespace
kubectl create namespace local

# 3. Pull chart dependencies and install
helm dependency update ./deploy/helm/chart

# NOTE: only variant-suffixed tags are published. With an empty tag, the chart
# uses its provider-neutral appVersion (-fscert). Override the tag only when
# you want a specific cloud variant or a locally loaded image.
helm install statuslist-local ./deploy/helm/chart \
  -n local -f ./deploy/helm/chart/values-local.yaml

# 4. Verify
kubectl get pods -n local
# Public listener (status-list reads, liveness) on service port 8081.
kubectl port-forward -n local svc/statuslist-local-status-list-server-service 8081:8081
curl http://localhost:8081/health/live
# Admin listener (readiness, metrics) lives on the internal ClusterIP service.
kubectl port-forward -n local svc/statuslist-local-status-list-server-internal-service 8002:8002
curl http://localhost:8002/health/ready
```

> **Certificate caveat for local runs:** the provider-neutral `-fscert` image requires certificate
> and signing-key files mounted into the pod. `values-local.yaml` includes disposable local sample
> material and mounts it through `statuslist.secretMounts`; for non-local runs, provide your own
> Secret-backed files or choose an image/provider configuration that matches your environment.
> See the entry "Pod `Running` but never binds the HTTP port" in `troubleshooting.md`.

`values-local.yaml` only overrides what differs from the neutral defaults (disabled Ingress/ESO, NodePort/external reachability, lighter resource requests). The chart renders `statuslist-secret` by default through `statuslist.fallbackSecret.enabled=true`. If pods fail with `CreateContainerConfigError`, confirm that either the fallback Secret rendered or your ESO/existing-Secret mode creates `statuslist-secret` in the namespace. See [LOCAL_DEPLOYMENT.md](LOCAL_DEPLOYMENT.md) for a more detailed local walkthrough.

## Option 2: Self-Managed Deployment (any cluster)

This is the path to a real deployment on a cluster you own. It uses the production-oriented `values.yaml` defaults, which you override for your environment.

### High-level steps

1. Choose your secret and credential delivery (see [Secrets delivery](#secrets-delivery)).
2. Configure the application for your runtime (database, certificates, DNS provider, region).
3. (Optional) Enable an Ingress + TLS and route your domain to the service.
4. Install the chart with Helm and verify.

### Prepare the database password Secret

The application reads the database password from a Kubernetes Secret named `statuslist-secret`. The chart-managed fallback Secret renders both `database-password` and legacy `postgres-password` with the same value, and on upgrade it can reuse an existing legacy `postgres-password` value. For upgrade safety with customer-managed Secrets and custom ESO mappings, the default mount still uses `postgres-password` as `/var/run/status-list-server/database/password`. Switch `statuslist.secretMounts[0].items[0].key` or `statuslist.database.passwordSecretKey` to `database-password` only after that key is guaranteed to exist. The chart deliberately does **not** inject `APP_DATABASE__PASSWORD` as a literal environment variable, and rejects it if you try.

How the Secret is created depends on your [secrets mode](#secrets-delivery): via an ExternalSecret (ESO) or a plain fallback Secret the chart renders for you.

### Configure for your runtime

The chart's `statuslist.env` holds the application configuration. Set the values your deployment needs:

- **Database port**: `APP_DATABASE__PORT` (e.g. `5432` for PostgreSQL, `3306` for MySQL). If omitted, the chart derives it from `APP_DATABASE__BACKEND`.
- **Certificate files or ACME**: the default `-fscert` image reads the certificate and signing key from files mounted into the pod. ACME-enabled image variants perform DNS-01 certificate issuance at startup, so configure `APP_SERVER__CERT__*` values for the DNS provider and deliver provider credentials from a Secret, not plain env values. See [dns-providers.md](dns-providers.md) for what each provider (`route53`, `cloudflare`, `gcloud`, `azure`, `acmedns`) requires.
- **Region** (`statuslist.aws.region`, renders `APP_AWS__REGION`): only required when you use an AWS-backed secret or DNS backend; omit it for other providers.
- **Issuer trust registry**: provide an operator-managed `issuers.yaml` file through any volume the chart mounts as a directory at `/etc/status-list-server` (a ConfigMap, a Secret, or a CSI volume) and set `statuslist.issuerRegistry.volume` to that volume source (for example `configMap: {name: issuers}`). The chart mounts the registry only when a volume is provided; do not use `subPath`, because the server watches the whole mounted directory for rotation. ConfigMap propagation is eventual, so verify the reload log after publishing a rotation. Production Helm renders fail without a registry volume; without one in development, the server warns and trusts no issuers. The release-tag workflow deploys with `statuslist.issuerRegistry.volume.configMap.name=status-list-server-issuers` and nothing creates that ConfigMap, so it must already exist in the target namespace before the first release; the deploy job fails fast with a clear message when it is missing, and without it the pods would sit in `ContainerCreating` for the whole `--wait` window and then roll back.
- To validate a registry before starting the server, run `status-list-server issuer-registry`; it reads `APP_MANAGEMENT_AUTH__ISSUERS_FILE` and exits non-zero for invalid YAML, schema, or key material.
- **Telemetry / limits / rate limiting / cache**: defaults are sensible; over-ride only what your sizing needs.

### Rotate or revoke issuer keys

Keep the registry in the operator-controlled source used to publish the mount.
It contains public keys only. Never put an issuer's private key in the registry.

To start a new registry (there is no committed file), create the three-line skeleton:

```yaml
version: 1
issuers: []
admins: []
```

`cargo xtask issuer add` and `issuer add-key` write into an existing file, so the
file must exist with at least this structure before you add keys.

For a zero-downtime rotation:

1. Add the new public key while retaining the old key:
   `cargo xtask issuer add-key --file <registry-file> --issuer <issuer-id> --jwk '<public-jwk-json>' --alg ES256`.
2. Validate the complete file with `APP_MANAGEMENT_AUTH__ISSUERS_FILE=<registry-file> status-list-server issuer-registry`.
3. Publish the updated registry (the ConfigMap/Secret/CSI volume backing the mount) and wait for Kubernetes to propagate it to every pod. Hash the exact bytes delivered by the selected volume source, then compare the result with the `fingerprint` in each pod's `issuer_registry_reloaded` log. For a ConfigMap, use `kubectl get configmap <name> -n <namespace> -o jsonpath='{.data.issuers\.yaml}' | shasum -a 256`. For a Secret, decode the base64 value first: `kubectl get secret <name> -n <namespace> -o jsonpath='{.data.issuers\.yaml}' | base64 --decode | shasum -a 256` (use the platform's equivalent decode flag if needed). For a CSI volume, hash the file from the provider's source or another copy of the exact mounted bytes; there is no Kubernetes API object to query. `issuer_registry_keys` shows the count but cannot identify a key replacement.
4. Move the issuer to the new key. Keep both keys trusted for the agreed overlap period.
5. Remove the old key from that issuer's `keys` list, validate the file again, and publish the registry. Confirm reload on every pod; requests signed with the removed key should then be rejected.

To revoke one key, remove its entry from `keys`; to disable the whole issuer, set its `disabled` field to `true`. Removing a registry-only issuer stops trusting its keys, but the durable issuer mapping remains in the database, so its aggregation URL continues resolving while its lists remain public. Keep the registry entry only while the issuer still needs to authenticate. Do not delete the durable mapping while published tokens may still reference its URL. Validate and publish the file, then confirm every pod reloaded it. An invalid update leaves the previous registry active, so a failed reload does not complete a revocation. Monitor `issuer_registry_reload_failures_total` and repair the mounted registry source if it increases. ConfigMap delivery can take a kubelet sync period plus cache delay, often a minute or two; for an urgent revocation, update the mounted registry (or use `kubectl rollout restart` so new pods mount it), then verify the fingerprint and rejection on every pod.

When migrating an issuer with a stored credential, preserve its existing issuer and `aggregation_id`; `cargo xtask issuer add` generates fresh IDs and is for new issuers. The server adopts the registry's `aggregation_id` for a legacy credential that has no stored ID, and rejects a conflicting stored mapping.

## Redis Status-List Cache

Redis is an optional runtime cache backend; the chart does not deploy it. In
production use a managed Redis with TLS and a password: set
`APP_CACHE__BACKEND=redis`, `APP_CACHE__HOST` and `APP_CACHE__TLS=true`, and
deliver `APP_CACHE__PASSWORD` through `statuslist.secretEnv`. For a private CA,
mount it with `statuslist.secretMounts` and set `APP_CACHE__CA_FILE`. With
NetworkPolicy enabled, set `statuslist.networkPolicy.cacheEgress`, or the chart
refuses to render.

The password is read at pod start, so a rotation needs a rollout restart. Use
the service's dual-token rotation, if it has one, to avoid auth errors in
between. Readiness doesn't depend on Redis and the server keeps serving
without it, so watch the `RedisCacheErrors` alert.

Our EKS pipeline needs the `APP_CACHE_HOST` environment variable and a
`statuslist-redis-password` Secrets Manager entry with a `PASSWORD` field
before the first deploy.

Use a dedicated Redis ACL user scoped to `APP_CACHE__KEY_PREFIX`; do not share a broad
write-capable Redis user with other applications. For the default prefix, create one with:

```text
ACL SETUSER status-list-server reset on >REPLACE_WITH_A_STRONG_PASSWORD ~status-list-server:status-list:* +get +del +hget +hset +expire +set +select +evalsha +script|load
```

`SET` maintains durable invalidation fences, `SELECT` is needed when
`APP_CACHE__DATABASE` is non-zero, and `SCRIPT|LOAD` lets `redis::Script` recover
after a Redis restart. Restrict the key pattern when you configure a custom prefix.

Configure Redis with `maxmemory-policy volatile-lru` (or `volatile-lfu`). Cache record
keys have a TTL and remain eligible for eviction, while durable marker keys have no TTL
and stay resident to preserve stale-fill fencing. Do not use any `allkeys-*` policy: it
can evict a marker and allow a delayed pre-PATCH fill to make a revoked credential look
valid. Size Redis for one durable marker per distinct status-list ID that has been
invalidated, in addition to the TTL-bound records; markers deliberately outlive records
and are not bounded by `APP_CACHE__MAX_CAPACITY`.

The cache supports private CA bundles (`APP_CACHE__CA_FILE`) and configurable
response, connection, and reconnect-cooldown timeouts. See
[`deploy/helm/chart/values.yaml`](../deploy/helm/chart/values.yaml) for the full
Helm value reference.

### Install

```bash
# Pull and package dependencies once
helm dependency update ./deploy/helm/chart

# Install with your values file (or inline --set overrides)
helm upgrade --install statuslist ./deploy/helm/chart \
  --namespace statuslist \
  --create-namespace \
  --rollback-on-failure \
  --wait \
  --timeout 10m \
  -f ./deploy/helm/chart/values.yaml \
  -f ./my-deployment-values.yaml
```

Use `helm upgrade --install` rather than `helm install` so the same command both creates and later updates the release. `--rollback-on-failure --wait --timeout 10m` makes failed upgrades roll back automatically during the pipeline. (This is the Helm 4 name; Helm 3 also accepts the legacy `--atomic` flag.) If the failed upgrade had already migrated the database, the rolled-back pods cannot start; see [Rolling back across migrations](#rolling-back-across-migrations).

### Expose the service (Ingress)

`values.yaml` ships with Ingress enabled, a neutral `localhost` host, and no TLS/cert-manager redirect annotations. For your own public deployment:

- Set `global.domain` to derive `statuslist.<global.domain>` and `*.<global.domain>` from one chart-wide value, or set `statuslist.ingress.externalDnsHostname` and `statuslist.ingress.tls.hosts` explicitly.
- Ensure your Ingress controller (e.g. ingress-nginx) and certificate issuer (e.g. cert-manager) actually exist in your cluster, then add TLS/cert-manager annotations such as `cert-manager.io/cluster-issuer` and nginx SSL redirects in your environment overlay.
- Or set `statuslist.ingress.enabled=false` and expose the `ClusterIP` Service another way (NodePort, port-forward, or a LoadBalancer).

The AWS overlay shows the Ingress + cert-manager path explicitly. Direct AWS NLB exposure lives in `values-aws-nlb.yaml` and disables Ingress so the two public paths are not active at the same time.

**Certificate host vs. token `sub` host.** With ACME, the server obtains a
certificate for `server.domain` (derived from `statuslist.ingress.externalDnsHostname`).
The status list `sub` URI, however, is built from `server.public_base_url`
(defaulting to `https://{server.domain}/api/v1`). If you set `APP_SERVER__PUBLIC_BASE_URL`
to a different host than `server.domain`, the certificate will not cover the
host in `sub`, and relying parties that pin the token signature to the host in
`sub` will reject the tokens. Keep the two hosts the same unless you have a
separate TLS-terminating layer covering the public URL. If the service is
reachable only on a non-443 port, put the port in `APP_SERVER__PUBLIC_BASE_URL`
(e.g. `https://host:8443/api/v1`), since `server.domain` cannot carry a port.

The subject URI is fixed when a status list is published. Changing
`server.public_base_url` or `server.domain` affects only new lists; existing lists retain their original URI. Keep the old endpoint serving those lists because already-issued credentials still reference it. A hostname change does not migrate published lists or update those credentials.

### Content negotiation at the edge

The `GET /api/v1/status-lists/{list_id}` endpoint negotiates the token format
(JWT vs CWT) from the client's `Accept` header per RFC 9110 §12.5.1 and serves
`Vary: Accept, Accept-Encoding` on its `200`, `304` and `406` responses. Two
operational consequences follow:

- **Normalize `Accept` at the CDN/edge.** Most HTTP clients and CDNs send a
  catch-all `Accept` (e.g. `*/*` or the legacy JDK default) that the server now
  accepts and answers with the default JWT format instead of a `406`. If you
  run a caching CDN in front of the service, make sure it keys its cache on
  `Vary: Accept` and, if you can, normalize or collapse the `Accept` header at
  the edge (for example strip wildcard-only values down to
  `application/statuslist+jwt`) so downstream cache-hit ratios stay high and
  one canonical variant is served per client class.
- **Plan for signing load.** Because wildcard/absent `Accept` headers now return
  `200 OK` (previously `406`), clients that were failing will suddenly start
  receiving freshly signed tokens. Every `200` triggers a token re-sign on the
  hot path (subject to the conditional-revalidation ETag window), so watch
  signing throughput and CPU after rollout — a large fleet of previously-`406`
  clients can add sustained signing work that was not there before. The Redis
  status-list cache and the conditional-revalidation metrics
  (`conditional_revalidation_total`) help you confirm the new traffic is being
  served efficiently rather than re-signing every request.

### Pinning the image

For a stable, reproducible deploy, pin the exact image:

```yaml
statuslist:
  image:
    repository: <your-registry>/status-list-server
    tag: "1.2.0-aws" # variant-suffixed; used when digest is empty
    digest: "sha256:<64 hex chars>" # takes precedence over tag
```

When `digest` is set it takes precedence over `tag`, and Kubernetes runs `repository@digest`. `pullPolicy` derives automatically (`IfNotPresent` for a digest, `Always` for a mutable tag). A malformed digest (`not sha256:` + 64 hex) is rejected at template time rather than failing at pull time.

## Secrets Delivery

The chart supports fallback Secret, ESO, and Workload Identity paths. Pick the one that matches your cluster. The trade-offs for ESO vs Workload Identity are covered in [`deploy/helm/README.md`](../deploy/helm/README.md) and the database/secret backend options in [secrets-backends.md](secrets-backends.md).

### Mode A: Fallback plain Secret (default)

By default, the chart renders a plain Kubernetes Secret named `statuslist-secret`:

```yaml
externalSecret:
  enabled: false
secretStore:
  enabled: false
statuslist:
  fallbackSecret:
    enabled: true
    stringData:
      database-password: ""
```

Leave `database-password` empty to generate a password; Helm reuses an existing `database-password` or legacy `postgres-password` from the cluster Secret on upgrades when it can read it. If both existing keys are present with different values, the chart fails rather than overwriting one with the other.

### Mode B: External Secrets Operator (ESO)

Use ESO to synchronize secrets from a provider instead of storing them as Helm-rendered plain Kubernetes Secrets.

- `externalSecret.enabled=true`, `secretStore.enabled=true`, and `statuslist.fallbackSecret.enabled=false` render ESO CRs:
  - a provider-neutral `SecretStore` (`secretStore.provider` selects `aws`, `vault`, `gcp`, `azure`, or `raw`);
  - an `ExternalSecret` that syncs `database-password` and `postgres-password` into a Kubernetes Secret named `statuslist-secret`;
  - when `statuslist.aws.mountCredentials=true`, a second `ExternalSecret` that provisions `aws-credentials-secret` (the AWS shared `credentials`/`config` files mounted under `/home/nobody/.aws`).

**To use ESO** you must install External Secrets Operator in your cluster and configure:

- the provider (`secretStore.provider` and the matching provider block, e.g. AWS region + Secrets Manager/Parameter Store service);
- the remote keys your `ExternalSecret` references (e.g. a key holding the `POSTGRES_PASSWORD` property; the `aws-credentials-secret` keys holding `CREDENTIALS`/`CONFIG`).

Verify after install:

```bash
kubectl get secretstore,externalsecret -n <namespace>
kubectl describe secretstore <store> -n <namespace>
kubectl describe externalsecret <external-secret> -n <namespace>
```

A ready `ExternalSecret` shows a `SecretSynced` condition. A missing remote key or bad provider credentials appears in the status conditions.

### Mode C: Workload Identity (opt-in)

Instead of ESO-mounted static credentials, the application can use **ambient** cloud credentials via Workload Identity (EKS IRSA, GCP WI, Azure WIF):

- attach the role annotation via `serviceAccount.annotations` (e.g. `eks.amazonaws.com/role-arn` on EKS; see the [Workload Identity section of `deploy/helm/README.md`](../deploy/helm/README.md#use-workload-identity-instead-of-mounted-credentials) for GCP/Azure, and note Azure also needs the pod label `azure.workload.identity/use: "true"`);
- set `statuslist.aws.mountCredentials=false` so no credential files are mounted.

Attach a least-privilege policy to the role (see the example in the Workload Identity section of [`deploy/helm/README.md`](../deploy/helm/README.md) for Route53 / Secrets Manager / S3).

In fallback mode, `aws-credentials-secret` is not provisioned automatically: either create it yourself when `mountCredentials=true`, switch to ESO, or use Workload Identity.

## Scaling and Resilience (opt-in)

For a production-shape deployment enable scaling and disruption budgets together (disabled by default):

```yaml
statuslist:
  replicaCount: 2 # or enable autoscaling below

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 5
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 75

podDisruptionBudget:
  enabled: true
  maxUnavailable: 1
```

`replicaCount` lives under `statuslist:` (the Deployment reads `statuslist.replicaCount`); `autoscaling` and `podDisruptionBudget` are top-level values. When `autoscaling.enabled=true` the Deployment omits `replicas` so the HPA controls the count. Keep `podDisruptionBudget.maxUnavailable` below the replica count (the safe default) so node drains do not get blocked.

### Conditional GETs, ETags and the signed-token cache across replicas

The live `GET /status-lists/{id}` endpoint serves a **strong** ETag (`"..."`) derived from a SHA-256 digest of the exact served representation bytes (RFC 9110 §8.8.3.1). Because ES256 signatures are randomized, the bytes differ across replicas, restarts, cold caches, capacity evictions and window roll-overs; the strong ETag therefore differs across replicas — this is a documented, accepted deviation from cross-replica ETag equality (ticket 564 acceptance criterion: "two replicas return matching ETags *or the issue documents why they don't*"). Within a single replica the ETag is stable for the whole token window, so a client revalidating against the same replica gets a `304` with no signing. The token window is exactly the token's full lifetime (`exp_secs`); the ETag changes on content update, key/certificate rotation, window roll-over, token-format/encoding change, aggregation URI or token lifetime change, or mid-window content revert.

That cross-replica stability holds **only when replicas serve the same content with the same signing material and token configuration for the same representation and window**. During a rolling certificate or configuration change — or for different `token_ttl`/`token_exp` or aggregation-URI settings — ETags deliberately differ between replicas, so a revalidation against a replica on the other side of the change returns a freshly signed `200`. Coordinate certificate rotation and configuration rollout so the window during which replicas disagree is brief.

The signed-token bytes cache (`token_bytes_cache`) is **per-replica and byte-budgeted**:

- `token_bytes_cache.max_capacity` is a **byte** budget (entries are weighed by their size; a small list is a few hundred bytes, a large one can exceed 1 MiB), not an entry count. The default (64 MiB) is sized to hold several maximum-permitted lists (each near 1 MiB once wrapped in JWT/base64) plus many small ones. `0` disables the cache (every request re-signs).
- Each entry expires at the **end of its own validity window** (window width is `exp_secs`), independent of any global TTL, so a closed window's bytes are reclaimed promptly. There is no `token_bytes_cache.ttl` setting.
- The cache avoids re-signing *unchanged* tokens within a window on one replica, even under capacity pressure. A two-tier design (protected tier for latest-generation entries within their window, cold tier for superseded/expired entries) guarantees at most one signature per `(list, window, format)` per replica. A content change, a signer/certificate rotation, or a mid-window content revert to an earlier state always re-signs immediately (all are part of the cache key and the ETag). The monotonic `version` — not `iat` — guarantees a revert to earlier content produces a new key and ETag: a same-second A → B → A revert can leave `iat` unchanged, but `version` advances, so the new representation identity never collides with the pre-revert one.
- Encoded variants (gzip for JWT, identity for both) and their strong ETags are pre-computed at cache insertion time and stored alongside the uncompressed bytes, so revalidation requests (including `304`) never need to re-compress.

`status_list.token_ttl_secs` must be **strictly less than** `status_list.token_exp_secs` (validated at startup); a config with `ttl >= exp` or `exp == 0` is refused because it would let a `304` (whose `max-age = min(ttl, exp - now)`) vouch for a token that expires sooner.

### Upgrade strategy for this release

This release changes how status-list updates are fenced for concurrency: updates are now
guarded on a dedicated `version` column (and the `meta:{id}:version` Redis marker) instead of
the `updated_at` timestamp (and the `meta:{id}:updated` marker). The two guards are **not
mutually compatible during a rolling deploy**: old pods guard only on `updated_at` and never
touch `version`, while new pods guard only on `version` and can write a same-second
`updated_at`. While both versions run they can overwrite each other's update without a
conflict, and on the Redis path neither side's invalidation fences the other side's delayed
fills — so a status change can be silently lost.

Deploy this release with a **`Recreate` rollout strategy** so that no old and new pods ever
run concurrently. The chart exposes the Deployment strategy through
`statuslist.strategy`; set its type to `Recreate` for this upgrade:

```bash
helm upgrade --install statuslist ./deploy/helm/chart \
  --set statuslist.strategy.type=Recreate \
  ... # your other values
```

Do **not** use the default rolling update for this release: with a plain `RollingUpdate`,
`maxSurge` rounds up to 1, so the new pod starts while the old one is still running and the
two incompatible versions overlap. Scaling `statuslist.replicaCount`/HPA min/max down to `1`
alone does **not** avoid that overlap either. If you cannot use `Recreate`, the only safe
fallback is to scale the workload to **zero** before the upgrade and back up after (a short
outage):

```bash
kubectl scale deployment statuslist-status-list-server-deployment -n <namespace> --replicas=0
# kubectl scale returns immediately, but old pods can take up to the 30s default
# grace period to finish shutting down in-flight requests. Wait for them to be
# gone before upgrading, otherwise the helm upgrade on the next line scales
# replicas back up and new pods can start while old ones are still draining.
kubectl wait --for=delete pod -l app.kubernetes.io/instance=statuslist,app.kubernetes.io/name=status-list-server -n <namespace> --timeout=120s
helm upgrade --install statuslist ./deploy/helm/chart --set statuslist.strategy.type=Recreate ...
kubectl scale deployment statuslist-status-list-server-deployment -n <namespace> --replicas=<n>
```

Only scale back out after all pods are on the new version.

The issuer-ownership migration also changes the foreign keys on `credentials` and
`status_lists`. An old pod cannot register credentials or publish lists against the new
schema, so the `Recreate` rollout is required for this migration as well. On MySQL, adding
the `status_lists` foreign key can rebuild that table; plan the maintenance window based on
the table's size and test the upgrade duration on a production-sized copy first.

## Status List Aggregation

Set `APP_SERVER__AGGREGATION_URI` to the aggregation endpoint's public URL, for
example `https://statuslist.example.com/api/v1/aggregation`, to advertise it in
status list tokens. It must be an `https` URL (`http` is accepted outside
production) with no credentials, its path must be `/aggregation` under
`APP_SERVER__PUBLIC_BASE_URL`'s path (`/api/v1/aggregation` by default), and it
must have no query or fragment: each token carries its issuer's URI, the
configured one plus `/<aggregation_id>`. Pods refuse to start otherwise. Unset,
tokens carry no `aggregation_uri`. The endpoints are served either way.

Setting it lets anyone who holds one of an issuer's tokens list all of that
issuer's status lists; see
[architecture](architecture.md#status-list-aggregation) before enabling it on a
server shared by several issuers.

`APP_LIMITS__MAX_LISTS_PER_ISSUER` cannot exceed 1000, the default aggregation
page size. That keeps every issuer's aggregation complete in one response, for
relying parties that do not page; pods refuse to start above it (see
[troubleshooting](troubleshooting.md#startup-refused-max_lists_per_issuer-exceeds-the-aggregation-page-size)).
It only holds while the list quota is enforced. With
`APP_LIMITS__LIST_QUOTA_TRANSITION` set, publishes past the cap are accepted and
an issuer can outgrow one page, so tokens carry no `aggregation_uri` until the
quota is enforced. An issuer that still holds more than 1000 lists from under an
earlier, higher cap gets no `aggregation_uri` in its own tokens; other issuers
keep theirs. Pods decide this at startup and name such issuers, so it lasts until
the issuer is back under the cap and every pod has restarted. Pods that started
at different times can disagree meanwhile, so that issuer's tokens may differ
from pod to pod.

### Upgrading to issuer-scoped aggregation

Before the upgrade:

- Make sure `APP_LIMITS__MAX_LISTS_PER_ISSUER` is at most `1000`.
- Find issuers at or near 1000 lists. Those above it keep their lists, but
  their own tokens carry no `aggregation_uri`, and their aggregation requests
  without `limit` get `409 paging_required` instead of a multi-page answer.
  While the quota is enforced, **every further publish is refused** with
  `400 list_quota_exceeded` until they are back under the cap, which only
  deleting lists does. Those near it reach it sooner than under a higher cap:

  ```sql
  SELECT issuer, COUNT(*) AS lists FROM status_lists
  GROUP BY issuer HAVING COUNT(*) >= 900 ORDER BY lists DESC;
  ```

- On PostgreSQL, build the new index beforehand. Left to the migration, a plain
  `CREATE INDEX` blocks publishes and status updates, revocations included,
  until it finishes, which takes longer the more status lists there are. The
  migration skips an index that already exists:

  ```sql
  CREATE INDEX CONCURRENTLY idx_status_lists_issuer_list_id
    ON status_lists (issuer, list_id);
  SELECT indisvalid FROM pg_index
  WHERE indexrelid = 'idx_status_lists_issuer_list_id'::regclass;
  ```

  A concurrent build that fails leaves an invalid index, which the migration
  would skip too: if `indisvalid` is false, drop it and build it again. MySQL
  builds the index online.

During the upgrade:

- The migrations add `credentials.aggregation_id` and an `(issuer, list_id)`
  index on `status_lists`, and create `issuers` to keep registry
  mappings immutable across pod restarts.
- Pods of the previous release do not serve `/api/v1/aggregation/<id>`, so a
  relying party following a token from a new pod may get a `404` from an old
  one until the rollout completes. The claim is optional, and relying parties
  still fetch each status list directly.
- Issuers registered before the upgrade get an
  aggregation ID the first time one of their tokens is served. They can read it
  from `GET /api/v1/credentials`.
- The signed-token cache is per pod and starts empty, so every token a new pod
  serves carries the scoped URI. Tokens relying parties cached earlier carry
  the unscoped one, which keeps working.

### Rolling back

The previous release refuses to start while the database records migrations it
does not know, so `helm rollback` alone leaves its pods crash-looping. Follow
[Rolling back across migrations](#rolling-back-across-migrations). This upgrade
adds the five versions below. Rolling back to a release older than the list
quota, such as v1.2.0, crosses more, and its pods' logs name every one. The
schema changes stay, and so do the credential and registry aggregation IDs.
If rolling back across `m20261022_000001_issuer_ownership`, follow the
instructions in [Rolling back across migrations](#rolling-back-across-migrations).
The previous release cannot create ownership rows for new issuer registrations
or update the new quota counter, and it can publish only for existing owners.

- `m20260929_000001_credentials_aggregation_id`
- `m20260929_000002_status_lists_issuer_list_id_index`
- `m20261014_000001_credentials_key_id`
- `m20261020_000001_issuer_aggregations`
- `m20261022_000001_issuer_ownership`

Upgrading again re-runs these migrations, which find their changes already made.
Tokens served meanwhile carry the unscoped URI again, and scoped URIs relying
parties already hold return `404` until the upgrade.

**Never undo `credentials.aggregation_id` or `issuers`** once tokens
with scoped URIs have been served. The server refuses their down migrations;
do not drop the column or table by hand either. The IDs are lost, new ones are
assigned, and every URI already in tokens or issuer metadata returns `404`.
Restoring a backup from before either migration has the same effect and loses
status changes too; see
[Restoring a backup taken before the upgrade](#restoring-a-backup-taken-before-the-upgrade).
Deleting an issuer's credential in the database and registering it again does
the same to that issuer.

If the ownership migration stops because an issuer has different aggregation
IDs in `issuer_aggregations` and `credentials`, follow
[Resolving issuer aggregation ID conflicts](troubleshooting.md#resolving-issuer-aggregation-id-conflicts)
before retrying the upgrade. This schema keeps one ID per issuer; URLs carrying
the other ID will return `404` after the migration.

### Metrics

- `aggregation_pages_total{scope="issuer",outcome="refused"}` should stay at
  `0`. Anything else counts requests refused with `409 paging_required` because
  an issuer's aggregation did not fit in one page: an issuer from the
  pre-upgrade query above, or any issuer while the list quota is off.
- `aggregation_pages_total{scope="all"}` counts requests to the deprecated
  unscoped form. Remove that form once `token_exp_secs` has passed since the
  rollout and this stays at zero.
- `aggregation_uri_omitted_total` counts tokens served without
  `aggregation_uri` because looking up the issuer's aggregation ID failed.

## Verification

```bash
helm status statuslist -n <namespace>
helm history statuslist -n <namespace>
kubectl get pods -n <namespace>
kubectl rollout status deployment/statuslist-status-list-server-deployment -n <namespace>
kubectl logs -l app.kubernetes.io/name=status-list-server -n <namespace> --tail=100
```

Smoke-check the service:

```bash
# Liveness is on the public listener; readiness is on the admin listener (:8002).
curl http://<service>/health/live
curl http://<service>:8002/health/ready
```

`/health/ready` (admin listener) reflects backing-store readiness (database, and cloud/secret backends if configured), so it is the best signal that the instance is truly healthy. Metrics are also served on the admin listener at `/metrics`.

## Rollback

**If the release you are leaving ran a database migration, read [Rolling back across migrations](#rolling-back-across-migrations) before anything else.** The release you return to cannot start a new pod until the migration's record is deleted. That holds for every rollback below, including the automatic ones, and including one that reports success: its pods that are already running keep serving until a restart, scale-up or node drain replaces them.

- **Failed upgrade**: automatic. `--rollback-on-failure --wait --timeout 10m` rolls the release back during the upgrade when readiness fails or the timeout is hit. If a pod of the new release started, it may have migrated the database first, so check `seaql_migrations` even when the rollback succeeded.
- **ExternalSecrets that do not sync**: automatic. After a successful upgrade, the release workflow (`deploy.yml`) runs `helm rollback` when the release's ExternalSecrets do not sync. Every migration the release carries has run by then.
- **Bad-but-successful deploy**: manual. List revisions and roll back:

```bash
helm history statuslist -n <namespace>
helm rollback statuslist <revision> -n <namespace> --wait --timeout 10m
kubectl rollout status deployment/statuslist-status-list-server-deployment -n <namespace>
```

Note: pinning by `digest` keeps rollbacks reproducible, since the stored digest (not a mutable tag) determines the running image. When upgrading, pass both `tag` and `digest` explicitly (or clear the digest with `--set statuslist.image.digest=null`); `helm upgrade --reuse-values` with only a changed tag will not move the image because the stored digest still wins.

### Rolling back across migrations

A pod will not start while the database records a migration its release does
not know. A release newer than v1.2.0 exits naming each of them:

```text
Failed to run database migrations
...
the database records migrations this release does not know: <version>, <version>. ...
```

v1.2.0 and earlier exit with sea-orm's message instead, one line per version:

```text
Migration file of version '<version>' is missing, this migration has been applied but its file is missing
```

So a rollback past a release that ran a migration leaves the previous release
unable to start a pod. That includes the automatic rollbacks above: a failed
upgrade whose first new pod had already migrated the database, and the release
workflow's rollback after a successful upgrade, by which point every migration
has run. Pods of the previous release that are still running keep serving, but
a restart, scale-up or node drain replaces them with pods that crash-loop.

When the rollback does have to start pods, it stalls, and `helm rollback --wait`
times out: the pods it starts never become ready. Under a rolling update the
newer release's pods keep serving meanwhile, except the ones
[`maxUnavailable`](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#max-unavailable)
lets the stalled rollback replace with pods that crash-loop.

**An upgrade deployed with `Recreate` is different.** `Recreate` stops every
pod of the previous release before the first new pod starts. If that upgrade
fails after migrating, the automatic rollback has no running pod to fall back
on and cannot start one, so nothing serves until the records are deleted.
Treat it as an outage and go straight to the steps below.

The recovery is to delete the records of the migrations the previous release
does not know, and keep the schema. Under a rolling update the newer release's
pods keep serving throughout, alongside the previous release's pods as they
come up. One migration does not allow that overlap; see
[Rolling back past `add_status_list_version`](#rolling-back-past-add_status_list_version)
before you start if the rollback crosses it.

You need a SQL session on the server's database, as the account the server
uses: the deployment's `APP_DATABASE__USERNAME`, on `APP_DATABASE__NAME`. With
the chart's PostgreSQL, open `psql` in its pod:

```bash
kubectl get pods -n <namespace>   # the PostgreSQL pod
kubectl exec -it <postgres-pod> -n <namespace> -- psql -U <username> -d <database>
```

For an external database, MySQL included, connect with its usual client.

1. Find the versions. The log of a pod of the previous release names every one
   (`kubectl logs <pod> -n <namespace> --previous`); use it. Without such a
   pod, list the records newest first, and compare them with the migrations
   the previous release knows. `applied_at` has one-second resolution, and a
   rollback can cross several releases, so the newest records alone are not
   the answer:

   ```sql
   SELECT version, applied_at FROM seaql_migrations ORDER BY applied_at DESC;
   ```

2. Look each version up in
   [which migrations are safe to leave in place](#which-migrations-are-safe-to-leave-in-place),
   and do what it says before going on. If one is not safe and you cannot
   accept what that costs, do not delete the records: roll forward instead,
   with `helm rollback` to the newer revision, whose pods are still serving.
3. Delete the records inside a transaction, and check the count before
   committing:

   ```sql
   BEGIN;
   DELETE FROM seaql_migrations WHERE version IN ('<version>', '<version>');
   ```

   The client reports the rows deleted (`DELETE 2` in `psql`, `2 rows
   affected` in `mysql`). If that is the number of versions you listed, run
   `COMMIT;`. If it is anything else, run `ROLLBACK;` and check the versions.

   Never delete the records of the four oldest migrations (the first four rows
   of the table below). Every release knows them, and they cannot run twice:
   the next pod to start would fail on them.
4. Delete the crash-looping pods, so their replacements start without waiting
   out the back-off. As they become ready, the rollout finishes and removes the
   newer release's pods.
5. Once the rollout has finished, run the query from step 1 again. A pod of the
   newer release that restarted before then ran the migrations again and
   recorded them; delete the records again and repeat step 4.

Do not scale the newer release down first: until the previous release's pods
are ready, its pods are the only ones serving. The exception is a rollback
past `add_status_list_version`, below.

Upgrading again re-runs the deleted migrations, which find their changes
already made and skip them. Steps a particular release needs on top of this
still apply; the table below lists them. Re-running
`m20260923_000001_credentials_list_count` recounts every issuer, an `UPDATE`
of every row of `credentials`. On PostgreSQL the migrations run in one
transaction, so those rows stay locked until every pending migration has run,
and registrations, credential updates and publishes that update the count
wait for it. With many issuers, upgrade again in a quiet period.

There is no other way back. The server refuses to run down migrations, and
undoing a migration by hand can lose data nothing can recreate, such as the
[aggregation IDs](#rolling-back).

#### Rolling back past `add_status_list_version`

Pods from before this migration and pods from after it must never serve at
the same time: each guards updates on a column the other ignores, so they
overwrite each other's status changes without a conflict, revocations
included ([Upgrade strategy for this release](#upgrade-strategy-for-this-release)).
The steps above let both serve while the rollout finishes, so a rollback that
crosses this migration takes a short outage instead:

1. Do steps 1 and 2 above.
2. Stop every pod, and wait for them to be gone:

   ```bash
   kubectl scale deployment statuslist-status-list-server-deployment -n <namespace> --replicas=0
   kubectl wait --for=delete pod -l app.kubernetes.io/instance=statuslist,app.kubernetes.io/name=status-list-server -n <namespace> --timeout=120s
   ```

3. Delete the records, as in step 3 above.
4. Scale back up. Only the previous release's pods start:

   ```bash
   kubectl scale deployment statuslist-status-list-server-deployment -n <namespace> --replicas=<n>
   ```

5. With the Redis cache, clear it before serving traffic again.

If you cannot take the outage, roll forward instead: `helm rollback` to the
newer revision, whose pods are still serving. Upgrading again later is the
same `Recreate` upgrade as the first time.

#### Which migrations are safe to leave in place

A migration is safe to leave in place when the release that does not know it
still runs correctly on the database it leaves. Every new migration adds a row
here; a test fails until it does.

| Migration | Safe to leave in place? | Before deleting its record | When upgrading again |
|---|---|---|---|
| `mod` | Never deleted: every release from v1.0.0 on knows it | None | None |
| `add_updated_at` | Never deleted, as above | None | None |
| `m20250101_000003_status_list_history` | Never deleted, as above | None | None |
| `m20260727_000001_status_list_history_exp_index` | Never deleted, as above | None | None |
| `m20260923_000001_credentials_list_count` | Yes: the column defaults to `0` | `list-quota disable`, or the quota undercounts the previous release's publishes | Pods refuse to start without `APP_LIMITS__LIST_QUOTA_TRANSITION`; follow [Upgrading to the list quota](troubleshooting.md#upgrading-to-the-list-quota) |
| `m20260923_000002_list_quota` | Yes, once the quota is disabled | As above | As above |
| `m20260925_000001_status_list_allocations` | **No, for fixed-size lists** (see below) | Decide whether to roll forward instead | Find the lists the previous release converted |
| `add_status_list_version` | **Only if old and new pods never serve together**: the column defaults to `1`, but the two lose each other's status changes | Follow [Rolling back past `add_status_list_version`](#rolling-back-past-add_status_list_version) | Deploy with `Recreate` again. With the Redis cache, clear it: the previous release changes lists without advancing `version`, so cached tokens can be stale |
| `add_status_list_history_version` | Yes: the column defaults to `0` | None | None |
| `m20260929_000001_credentials_aggregation_id` | Yes: the column is nullable, and the IDs are kept | None | Nothing; until then, scoped URIs return `404` (see [Rolling back](#rolling-back)) |
| `m20260929_000002_status_lists_issuer_list_id_index` | Yes: an index | None | None |
| `m20261014_000001_credentials_key_id` | Yes: the column is nullable, and the unique index is additive | Follow [Preparing existing management credentials](#preparing-existing-management-credentials); reconcile duplicate IDs and thumbprints before upgrade | Existing IDs are preserved; absent/null IDs on parseable public JWKs get an RFC 7638 SHA-256 thumbprint in both JSON and `key_id`. Algorithms are unchanged. Repair both columns after migration; changing JSON alone is insufficient |
| `m20261020_000001_issuer_aggregations` | Yes: the table is additive, and an older release ignores it | None; keep the table and its mappings | Existing issuer-to-aggregation mappings remain immutable and the migration keeps the existing table and unique index |
| `m20261022_000001_issuer_ownership` | **No**: the previous release does not update the new quota counter and cannot create issuer-owner rows | Run `list-quota disable` before deleting its migration record; the old release can publish only for existing owners and cannot register new issuers | Recreate the new release; the migration safely reruns, preserves owner IDs and recomputes counts from `status_lists`. If it reports conflicting aggregation IDs, follow [the repair steps](troubleshooting.md#resolving-issuer-aggregation-id-conflicts) first |

### Preparing existing management credentials

Helm deployments must explicitly set
`statuslist.env.APP_MANAGEMENT_AUTH__AUDIENCES` to an audience unique to that
deployment (for example, `https://statuslist.prod.example.com/api/v1`). Give
staging a different value, even if both environments register the same issuer
key. Production chart rendering fails if the audience is empty. Issuers must
include that configured value in their management tokens' `aud` claim.

The release-tag deployment uses `values-aws.yaml` followed by
`values-production.yaml`. Its management audience is
`https://statuslist.eudi-adorsys.com/api/v1`. Issuers calling that production
deployment must put this exact value in `aud` (as a string or an array member).
The release workflow selects the `status-list-server-issuers` ConfigMap as its
registry source; the production values file leaves the source empty so other
deployments can choose a ConfigMap, Secret, or CSI volume.
Deployments reusing the production overlay for another environment or hostname
must explicitly override `APP_MANAGEMENT_AUTH__AUDIENCES`; staging must not use
the production value.

Before upgrading, back up the database and inventory existing credentials with
the read-only queries below. Run them before the new migration: they use only
the existing `issuer` and `public_key` columns. `duplicate_kid_count > 1` blocks
the unique index. Absent/null IDs on parseable public JWKs are generated during
migration; issuers must use those generated IDs in subsequent JWTs. Empty,
overlong, or malformed IDs, missing/unsupported algorithms, and unparsable keys
need operator repair before they can authenticate after upgrade.

```sql
-- PostgreSQL
WITH keys AS (
  SELECT issuer, public_key ->> 'kid' AS kid,
         public_key ->> 'alg' AS alg,
         jsonb_typeof(public_key::jsonb -> 'kid') AS kid_type,
         jsonb_typeof(public_key::jsonb -> 'alg') AS alg_type,
         public_key ->> 'kty' AS kty, public_key ->> 'crv' AS crv
  FROM credentials
), inventory AS (
  SELECT *, COUNT(*) OVER (PARTITION BY kid) AS duplicate_kid_count FROM keys
)
SELECT * FROM inventory
WHERE kid IS NULL OR kid = '' OR length(kid) > 255
   OR duplicate_kid_count > 1 OR alg IS NULL
   OR kid_type <> 'string' OR alg_type <> 'string'
   OR NOT COALESCE(((kty = 'EC' AND crv = 'P-256' AND alg = 'ES256')
        OR (kty = 'EC' AND crv = 'P-384' AND alg = 'ES384')
        OR (kty = 'OKP' AND crv = 'Ed25519' AND alg = 'EdDSA')
        OR (kty = 'RSA' AND alg = 'PS256')), FALSE);
```

```sql
-- MySQL 8+
SET @management_saved_collation = @@session.collation_connection;
SET @management_kid_collation = COALESCE(
  (SELECT COLLATION_NAME FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'credentials' AND COLUMN_NAME = 'key_id'),
  (SELECT TABLE_COLLATION FROM information_schema.TABLES
   WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'credentials')
);
SET SESSION collation_connection = @management_kid_collation;
WITH key_values AS (
  SELECT issuer, CAST(JSON_UNQUOTE(JSON_EXTRACT(public_key, '$.kid')) AS CHAR) AS kid,
         JSON_UNQUOTE(JSON_EXTRACT(public_key, '$.alg')) AS alg,
         JSON_TYPE(JSON_EXTRACT(public_key, '$.kid')) AS kid_type,
         JSON_TYPE(JSON_EXTRACT(public_key, '$.alg')) AS alg_type,
         JSON_UNQUOTE(JSON_EXTRACT(public_key, '$.kty')) AS kty,
         JSON_UNQUOTE(JSON_EXTRACT(public_key, '$.crv')) AS crv
  FROM credentials
), inventory AS (
  SELECT *, COUNT(*) OVER (PARTITION BY kid) AS duplicate_kid_count FROM key_values
)
SELECT * FROM inventory
WHERE kid IS NULL OR kid = '' OR CHAR_LENGTH(kid) > 255
   OR duplicate_kid_count > 1 OR alg IS NULL
   OR kid_type <> 'STRING' OR alg_type <> 'STRING'
   OR NOT COALESCE(((kty = 'EC' AND crv = 'P-256' AND alg = 'ES256')
        OR (kty = 'EC' AND crv = 'P-384' AND alg = 'ES384')
        OR (kty = 'OKP' AND crv = 'Ed25519' AND alg = 'EdDSA')
        OR (kty = 'RSA' AND alg = 'PS256')), FALSE);
SET SESSION collation_connection = @management_saved_collation;
```

```sql
-- SQLite
WITH keys AS (
  SELECT issuer, json_extract(public_key, '$.kid') AS kid,
         json_extract(public_key, '$.alg') AS alg,
         json_type(public_key, '$.kid') AS kid_type,
         json_type(public_key, '$.alg') AS alg_type,
         json_extract(public_key, '$.kty') AS kty,
         json_extract(public_key, '$.crv') AS crv
  FROM credentials
), inventory AS (
  SELECT *, COUNT(*) OVER (PARTITION BY kid) AS duplicate_kid_count FROM keys
)
SELECT * FROM inventory
WHERE kid IS NULL OR kid = '' OR length(kid) > 255
   OR duplicate_kid_count > 1 OR alg IS NULL
   OR kid_type <> 'text' OR alg_type <> 'text'
   OR NOT COALESCE(((kty = 'EC' AND crv = 'P-256' AND alg = 'ES256')
        OR (kty = 'EC' AND crv = 'P-384' AND alg = 'ES384')
        OR (kty = 'OKP' AND crv = 'Ed25519' AND alg = 'EdDSA')
        OR (kty = 'RSA' AND alg = 'PS256')), FALSE);
```

Run the entire MySQL block in one session. It temporarily uses the `key_id`
column's collation, or the table's default before that column exists, for the
`kid` cast and comparisons. This catches IDs such as `Key-1` and `key-1` that
would collide under a case-insensitive unique index. The final statement
restores the session's original collation; no stored data is changed.

These queries flag metadata incompatibilities; also inspect the complete public
JWK for private members, invalid key material, an encryption-only `use`, and RSA
moduli below 2048 bits. Do not copy private key material into the database.

Coordinate repairs with each issuer before enabling the new verifier:

1. Agree on the exact supported signing algorithm. The migration preserves
   every supplied ID. For an absent/null `kid`, it computes the base64url-encoded
   RFC 7638 SHA-256 public JWK thumbprint, without padding, and writes it into
   both `public_key.kid` and `key_id` in one statement. Inspect generated IDs
   after migration with `SELECT issuer, key_id FROM credentials` and communicate
   them to issuers. Check for collisions beforehand: identical public keys
   produce identical thumbprints, which can also clash with a supplied ID.
   Before writing generated IDs, the migration checks for collisions between
   generated thumbprints and against existing IDs. It stops with an error naming
   the affected issuers, so operators can repair those registrations before
   retrying. The unique constraint remains the final safeguard; the migration
   never silently assigns a different ID.
2. Add the agreed `kid` and `alg` to the stored public JWK. Do not infer an RSA
   signing algorithm from key type alone or silently relabel an existing RS256
   key as PS256. The issuer must explicitly switch its signer to PS256 or supply
   another supported public key. Preserve the credential's issuer, aggregation
   ID, list count, and associated lists.
3. Before migration, update `public_key`; the migration copies its `kid` into
   `key_id`, generating a thumbprint only when the ID is absent/null. It does not
   infer or replace `alg`, and does not generate IDs for symmetric keys, keys
   containing private members, or keys it cannot parse. If the migration has
   already run, stop management writes and update
   **both columns in one transaction**. Use bound parameters with the database
   client: `UPDATE credentials SET public_key = :public_jwk, key_id = :kid
   WHERE issuer = :issuer`. Cast the JSON parameter as required by the driver.
   Do not delete and re-register the issuer to work around a 409.
4. Rerun the inventory query. After migration, verify `key_id` equals the
   JWK's `kid`, then have each issuer authenticate using its agreed algorithm,
   `typ: statuslist-management+jwt`, matching `kid`, configured audience, and
   a lifetime within the configured maximum (300 seconds by default).

There is no public credential-update endpoint in this release. An operator must
perform these repairs; re-registering an existing issuer returns 409. Plan a
coordinated cutover if old and new servers overlap, because their accepted token
contracts differ.

This release does not change the format of IDs already supplied by issuers.
The onboarding design in [#369](https://github.com/adorsys/status-list-server/issues/369)
and [#373](https://github.com/adorsys/status-list-server/issues/373) must support
several independently managed keys per issuer while preserving existing `kid`
values. Whether newly onboarded keys receive assigned IDs or thumbprint IDs is
a decision for that work, not a reason to rename existing keys again.

**`m20260925_000001_status_list_allocations`.** The schema change is additive,
but a release before it, such as v1.2.0, rewrites a list without its `size`
and `default_status` whenever it updates the list's statuses, and it allocates
nothing. Each fixed-size list it updates becomes a grow-on-write list: after
upgrading again, allocating on it is refused, and updates to it are no longer
checked against allocations. Nothing restores `size`; issuers allocate from new
lists instead. To find the lists it converted:

```sql
-- PostgreSQL
SELECT DISTINCT a.list_id FROM status_list_allocations a
JOIN status_lists l ON l.list_id = a.list_id
WHERE l.status_list->>'size' IS NULL;

-- MySQL
SELECT DISTINCT a.list_id FROM status_list_allocations a
JOIN status_lists l ON l.list_id = a.list_id
WHERE JSON_EXTRACT(l.status_list, '$.size') IS NULL;
```

#### Restoring a backup taken before the upgrade

**Do not restore one.** This runbook has no restore procedure yet, and
restoring without one does damage that nothing done afterwards repairs:

- **Status indices are handed out twice.** Allocation gives each credential the
  lowest index no allocation record claims, and a restore removes every record
  written after the backup. The next credentials issued then get the indices of
  the last ones issued before the restore. A list published after the backup
  and published again under the same ID hands out its indices from `0` again.
  Two credentials then share one status bit for good: revoking either revokes
  both, and each holder's status is the other's.
- **Revoked credentials read as valid again.** Every status change made after
  the backup is lost, revocations included.

If the database is damaged and the recovery above cannot work, escalate rather
than restore.

## Failure Triage

### Image pull failure

- Pods show `ImagePullBackOff` / `ErrImagePull`.
- Check the image `repository`/`tag`/`digest` you configured exists in the registry the cluster can reach, and that the cluster has pull credentials if the registry is private.

### Readiness failure

- `/health/ready` reports a failing backing store.
- Check database readiness (PostgreSQL pod/connection), the ExternalSecret/SecretStore status (if ESO), and application env values.

### Pod crash-loops at startup in a production profile

- The pod exits before it becomes ready, with a log line like `server.public_base_url (https://localhost/api/v1) resolves to localhost/loopback in a production profile`.
- This is a deliberate startup guard: a `localhost`/loopback `sub` can never be reached by a relying party, so a production profile (`APP_ENV=production`) refuses to start rather than silently signing tokens every relying party rejects. The Helm chart falls back to `localhost` when no host is configured, which is why an unconfigured upgrade hits this.
- Set `APP_SERVER__DOMAIN` (or `APP_SERVER__PUBLIC_BASE_URL`) to the public host and redeploy. The guard keys off `APP_ENV`, so it only blocks production profiles; private/local hosts (`.local`, private IPv4, link-local, ULA) warn instead of stopping.

### Secret not synced (ESO)

- The pod is up but not ready and reports a missing/empty Secret, or `kubectl get externalsecret` shows a condition other than `SecretSynced`.
- Common causes: the provider lacks permission to `GetSecretValue` on the referenced key; the `SecretStore` region/settings do not match where the key lives; the remote key or property name does not match what `externalSecret.spec.data` / `statuslist.aws.credentialsSecret` expect.

### Certificate / ACME issues

- Certificates fail to provision or renew.
- Check `APP_SERVER__CERT__ACME_DIRECTORY_URL` (staging vs production), the DNS provider settings and credentials in [dns-providers.md](dns-providers.md), and that the DNS-01 challenge can reach your DNS provider (network + IAM/cloud role).

### Image Assertion Failure

Symptoms:

- `Scan Image for Vulnerabilities` fails at `Assert published SBOMs list Rust crates`, or at `Resolve the architecture manifest to scan`.
- The image exists in GHCR under its `sha-<short_sha>` tag, but the release tags were never applied and `Deploy to Production` is skipped.

Check:

- The run artifacts and the job summary. Reports and SBOMs are uploaded before the assertion runs, so a failure here still leaves the full report attached to the run. They arrive as two artifacts per variant: `container-scan-reports-<variant>` and `container-sboms-<variant>` (e.g., `container-scan-reports-aws`, `container-sboms-aws`).
- For an SBOM failure, whether the builder-stage audit assertion also changed behaviour recently. An empty published SBOM with a passing build assertion points at BuildKit's cataloguer, not at the binary.
- For a resolution failure, the message names how many `linux/amd64` manifests were found in the index. Zero means the build stopped producing that platform; more than one means the index is not shaped the way this pipeline assumes. Neither is a scanner problem.

### Vulnerability Gate Findings

Symptoms:

- `Vulnerability gate` fails, the summary lists the blocking advisories, and the release tags are never applied.

Check:

- `trivy-gate-findings-<arch>.json` in the `container-scan-reports` artifact is the exact blocking set for that architecture. The gate's table is rendered from those same files, so the summary count and the table cannot disagree.
- The summary reports distinct advisories and package occurrences separately. One CVE affecting three crates is three rows in the table and one thing to triage.
- Whether the advisory is already argued in `deny.toml`. The two ledgers are not connected, so a release can block on something `cargo-deny` has been ignoring deliberately.

Triage steps and the exception format are in [Container Supply Chain](supply-chain.md). Fix it at the lockfile if a fix exists; add a dated ledger entry only if one does not.

### Gate Self-Test Failure

Symptoms:

- `Prove the gate can fail` fails with "the vulnerability gate cannot fail and is not protecting this release".

Check:

- This is not a finding about the image. It means `scripts/vuln-gate.sh` returned success against a fixture that contains a CRITICAL, so the gate would have passed the real scan no matter what was in it.
- Likely causes: `--exit-code` was changed or dropped in `scripts/vuln-gate.sh`, or a Trivy upgrade changed `convert`'s exit-code behaviour.
- Do not work around it by skipping the step. A release cut while this is failing has an unverified gate.

### Tag Promotion Failure

Symptoms:

- `Promote Scanned Digest to Release Tags` fails for one or more variants, and the release exists in GHCR only as `sha-<short_sha>-<variant>`.
- `Deploy to Production` is skipped because it depends on promotion.

Check:

- Whether `Verify attestations survived promotion` is the failing step. That means the retag succeeded but the SBOM or provenance manifests did not carry through, which would publish a release whose metadata silently vanished.
- The failing variant's matrix job logs to see which specific suffix (`-aws`, `-gcp`, etc.) failed.
- Re-running the job is safe: `imagetools create` is idempotent for a given digest and tag set. **Re-run `promote-tags` alone** — `deploy` depends on it, so a successful re-run unblocks production without cutting a new release. A promotion failure is not a reason to re-tag the repository.

### Builder Audit Assertion Failure

Symptoms:

- The image build fails in the builder stage at the `rust-audit-info` assertion, or at the `cargo install` layer above it, on a commit that changed nothing relevant.

Check:

- This means the binary no longer carries readable `.dep-v0` audit data, usually because the floating stable toolchain drifted away from the pinned `cargo-auditable` version. Bump `CARGO_AUDITABLE_VERSION` and `RUST_AUDIT_INFO_VERSION` in the `Dockerfile`.
- The assertion is deliberate. Without it the build would succeed and publish an empty SBOM.

### Attestation Verification Failure

Symptoms:

- `Verify Signed Provenance` fails for one or more variants, and `Promote Scanned Digest to Release Tags` is skipped because it depends on `verify-provenance`.
- The image exists in GHCR under its `sha-<short_sha>-<variant>` tag, but no release tags are applied and `Deploy to Production` never runs.

Check:

- `gh` version floor: the verification wrapper (`scripts/verify-attestation.sh`) requires `gh >= 2.67.0`. Until 2.67.0, `gh attestation verify` exited 0 when no attestation was found at all ([cli/cli#10418](https://github.com/cli/cli/issues/10418)). The runner image must provide a new enough `gh`; if it does not, the step will pass incorrectly and the failure will surface later as a missing signature on the promoted tag.
- Certificate identity mismatch: the wrapper pins the exact SubjectAlternativeName (workflow path **and** ref) via `--cert-identity` and `--source-ref`. A signature from a different ref, a different workflow, or a different repository will fail verification even if the digest is correct. The error message names the expected and actual identities.
- Transient API errors vs genuine absence: the wrapper retries three times. A failure after retries means either GitHub's attestation API is unavailable, Sigstore's trust root cannot be fetched, or no signed provenance exists for the digest. Check the step logs for `gh`'s JSON output to distinguish.
- `gh attestation verify` output: the wrapper parses `--format json` and requires a non-empty result array whose verified subject digest matches the one asked about. An empty result array means no attestation was found for that digest in this repository.

Do not bypass this gate. It is the only check that establishes a signed statement from this workflow, from this ref, over the digest that will be promoted. A digest that passes the vulnerability gate but fails provenance verification is an artifact whose builder identity cannot be confirmed — promoting it would publish a release with no verifiable origin.

## External Dependencies

- **External Secrets Operator**: needed only when you choose ESO secret delivery; the default fallback Secret path does not require ESO CRDs.
- **Ingress controller + cert-manager**: needed only if you enable the Ingress / TLS path.
- **Your cloud provider**: for Workload Identity roles and any AWS/GCP/Azure backends the application uses.

## Upgrading to the Three-Listener Architecture

If you deployed before the three-listener split (public :8000 / management :8001 / admin :8002), this section guides you through the breaking changes and the issuer migration.

### What changed

| Listener | Old (single port) | New |
|---|---|---|
| Public reads (`GET /api/v1/status-lists/…`) | `:8000` | `:8000` (unchanged) |
| Management writes (`PUT`/`PATCH`/`POST` writes) | `:8000` | `:8001` |
| Readiness (`/health/ready`) | `:8000` | `:8002` |
| Metrics (`/metrics`) | `:8000` | `:8002` |

### Required Helm value changes

```yaml
statuslist:
  ingress:
    management:
      # Enable the management listener Ingress so issuer writes reach :8001.
      # Without this every write returns 404 even though the pod starts fine.
      enabled: true
      annotations:
        # Match the public Ingress body-size limit (default 10m).
        nginx.ingress.kubernetes.io/proxy-body-size: "10m"

  networkPolicy:
    # If networkPolicy.enabled=true, you must now explicitly allow the
    # Ingress controller to reach the management port, and Prometheus to
    # reach the admin port. Previously both went through the public port.
    managementIngress:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
    adminIngress:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: monitoring
        podSelector:
          matchLabels:
            app.kubernetes.io/name: prometheus
```

### ServiceMonitor

The ServiceMonitor must scrape the **admin** port (`:8002`) now that `/metrics` has moved. If you use the chart-bundled `serviceMonitor`, this is automatic. If you have a custom ServiceMonitor CRD, update its `port` field:

```yaml
# Old:
port: http      # targeted the public port 8000
# New:
port: admin     # targets the admin port 8002
```

### Issuer migration

Existing issuers send writes to the management listener. If they were registered before the split, point them at the management hostname/port (`:8001`) via the management Ingress — the `sub` in their credential is the status-list URI, not their write destination. After the upgrade, **issuer write traffic must reach port 8001** via the management Ingress.

1. **Enable the management Ingress** (see above) before upgrading.
2. **Verify** after upgrade:

   ```bash
   # On a shared hostname (what production uses) the PUT routes through the
   # management Ingress and reaches the handler, so you get 401 (no/invalid
   # token) — not 404:
   curl -X PUT https://<host>/api/v1/status-lists/<id>/statuses
   # → 401 (management Ingress routed it; a valid token gives 200/204)
   # A 404 only appears when you hit the public port directly, since public
   # serves reads only:
   curl -X PUT http://<public-host>:8000/api/v1/status-lists/<id>/statuses
   # → 404
   # Writes to the management listener must reach the handler:
   curl -X PUT https://<mgmt-host>/api/v1/status-lists/<id>/statuses \
     -H "Authorization: Bearer <token>"
   # → 401 (no valid token) or 200/204 (valid token)
   ```

3. **Update issuer configuration** to target the management hostname/port if it differs from the public hostname.

### Readiness probe

If you use an external readiness check (load balancer health check, external monitoring), update the endpoint from `:8000/health/ready` to `:8002/health/ready`. The pod's own readiness probe in the chart already targets `:8002`.

### Rollback note

Rolling back across this upgrade reverts the three-listener split. Any issuer that was already updated to target `:8001` will fail writes until it is reverted too. Coordinate the rollback with issuer teams or stage the migration with a canary deployment.

## Next Steps

- [deploy/helm/README.md](../deploy/helm/README.md): full chart value reference and configuration guide.
- [LOCAL_DEPLOYMENT.md](LOCAL_DEPLOYMENT.md): detailed local quickstart.
- [dns-providers.md](dns-providers.md): ACME DNS-01 provider setup per provider.
- [secrets-backends.md](secrets-backends.md): database/secret backend options, and the Workload Identity opt-in in [`deploy/helm/README.md`](../deploy/helm/README.md).
- [database-backends.md](database-backends.md): supported database backends.
- [observability.md](observability.md): OpenTelemetry / metrics / logs.
