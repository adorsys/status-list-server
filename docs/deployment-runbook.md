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
kubectl port-forward -n local svc/statuslist-local-status-list-server-service 8081:8081
curl http://localhost:8081/health/live
curl http://localhost:8081/health/ready
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
- **Telemetry / limits / rate limiting / cache**: defaults are sensible; over-ride only what your sizing needs.

## Redis Status-List Cache

Redis is an optional runtime cache backend. Set `APP_CACHE__BACKEND=redis`, provide
`APP_CACHE__HOST`, and configure `APP_CACHE__TLS=true` with a password in production.
For Helm, source `APP_CACHE__PASSWORD` from `statuslist.secretEnv` and set
`statuslist.networkPolicy.cacheEgress` when NetworkPolicy is enabled.

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

## Status List Aggregation

Set `APP_SERVER__AGGREGATION_URI` to the aggregation endpoint's public URL, for
example `https://statuslist.example.com/api/v1/aggregation`, to advertise it in
status list tokens. Its path must be `/api/v1/aggregation`, and it must have no
query or fragment: each token carries its issuer's URI, the configured one plus
`/<aggregation_id>`. Pods refuse to start otherwise. Unset, tokens carry no
`aggregation_uri`. The endpoints are served either way.

Setting it lets anyone who holds one of an issuer's tokens list all of that
issuer's status lists; see
[architecture](architecture.md#status-list-aggregation) before enabling it on a
server shared by several issuers.

`APP_LIMITS__MAX_LISTS_PER_ISSUER` cannot exceed 1000, the default aggregation
page size. That keeps every issuer's aggregation complete in one response, for
relying parties that do not page; pods refuse to start above it (see
[troubleshooting](troubleshooting.md#startup-refused-max_lists_per_issuer-exceeds-the-aggregation-page-size)).
It only holds while the list quota is enforced: with
`APP_LIMITS__LIST_QUOTA_TRANSITION` set, any issuer can outgrow one page.

### Upgrading to issuer-scoped aggregation

Before the upgrade:

- Make sure `APP_LIMITS__MAX_LISTS_PER_ISSUER` is at most `1000`.
- Find issuers at or near 1000 lists. Those above it keep their lists, and their
  aggregation spans several pages, but **every further publish is refused** with
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
  index on `status_lists`.
- Pods of the previous release do not serve `/api/v1/aggregation/<id>`, so a
  relying party following a token from a new pod may get a `404` from an old
  one until the rollout completes. The claim is optional, and relying parties
  still fetch each status list directly.
- Issuers registered before the upgrade, or by an old pod during it, get an
  aggregation ID the first time one of their tokens is served. They can read it
  from `GET /api/v1/credentials`.
- Status list tokens are signed on each request, so every token served after
  the rollout carries the scoped URI. Tokens relying parties cached earlier
  carry the unscoped one, which keeps working. This changes if
  [#572](https://github.com/adorsys/status-list-server/pull/572) lands: it
  caches signed tokens per validity window, so a token signed before the rollout
  keeps the unscoped URI until its window ends.

### Rolling back

The previous release refuses to start while the database records migrations it
does not know, so `helm rollback` alone leaves its pods crash-looping. Follow
[Rolling back across migrations](#rolling-back-across-migrations). This upgrade
adds the two versions below. Rolling back to a release older than the list
quota, such as v1.2.0, crosses more, and its pods' logs name every one. The
schema changes stay, which the previous release ignores, and so do the
aggregation IDs.

- `m20260929_000001_credentials_aggregation_id`
- `m20260929_000002_status_lists_issuer_list_id_index`

Upgrading again re-runs both migrations, which find their changes already made.
Tokens served meanwhile carry the unscoped URI again, and scoped URIs relying
parties already hold return `404` until the upgrade.

**Never undo `credentials.aggregation_id`** once tokens with scoped URIs have
been served. The server refuses its down migration; do not drop the column by
hand either. The IDs are lost, new ones are assigned, and every URI already in
tokens or issuer metadata returns `404`. Restoring a backup taken before it
does the same and loses status changes too; see
[Restoring a backup taken before the upgrade](#restoring-a-backup-taken-before-the-upgrade).
Deleting an issuer's credential in the database and registering it again does
the same to that issuer.

### Metrics

- `aggregation_pages_total{scope="issuer",outcome="truncated"}` should stay at
  `0`. Anything else means an issuer's aggregation did not fit in one page: an
  issuer from the pre-upgrade query above, or any issuer while the list quota
  is in transition.
- `aggregation_pages_total{scope="all"}` counts requests to the deprecated
  unscoped form. Remove that form once `token_exp_secs` has passed since the
  rollout and this stays at zero.
- `aggregation_uri_omitted_total` counts tokens signed without
  `aggregation_uri` because looking up the issuer's aggregation ID failed; the
  tokens are still served.

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
curl http://<service>/health/live
curl http://<service>/health/ready
```

`/health/ready` reflects backing-store readiness (database, and cloud/secret backends if configured), so it is the best signal that the instance is truly healthy.

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
times out: the pods it starts never become ready. How many of the newer
release's pods keep serving meanwhile depends on the rolling-update strategy.
The chart sets none, so Kubernetes' defaults apply: a quarter of the desired
pods may be unavailable, rounded down, and a quarter more may start, rounded
up. At two or three replicas, production's usual size, every pod of the newer
release keeps serving. From four up (production's HPA allows ten) a quarter of
them are replaced by pods that crash-loop. A `Recreate` strategy or a larger
`maxUnavailable` would turn the same rollback into an outage.

The recovery is to delete the records of the migrations the previous release
does not know, and keep the schema. The newer release's pods keep serving
throughout.

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
4. Delete the crash-looping pods, so their replacements start without waiting
   out the back-off. As they become ready, the rollout finishes and removes the
   newer release's pods.
5. Once the rollout has finished, run the query from step 1 again. A pod of the
   newer release that restarted before then ran the migrations again and
   recorded them; delete the records again and repeat step 4.

Do not scale the newer release down first: until the previous release's pods
are ready, its pods are the only ones serving.

Upgrading again re-runs the deleted migrations, which find their changes
already made and skip them. Steps a particular release needs on top of this
still apply; the table below lists them. Re-running
`m20260923_000001_credentials_list_count` recounts every issuer, an `UPDATE`
of every row of `credentials`. On PostgreSQL the migrations run in one
transaction, so those rows stay locked until every pending migration has run,
and registrations, credential updates and publishes that update the count
wait for it.

There is no other way back. The server refuses to run down migrations
([ADR 0003](adr/0003-schema-migrations-are-forward-only.md)), and undoing a
migration by hand can lose data nothing can recreate, such as the
[aggregation IDs](#rolling-back).

#### Which migrations are safe to leave in place

A migration is safe to leave in place when the release that does not know it
still runs correctly on the database it leaves. Every new migration adds a row
here ([ADR 0003](adr/0003-schema-migrations-are-forward-only.md), rule 1).

| Migration | Safe to leave in place? | Before deleting its record | When upgrading again |
|---|---|---|---|
| `mod` | Never deleted: every release from v1.0.0 on knows it | — | — |
| `add_updated_at` | Never deleted, as above | — | — |
| `m20250101_000003_status_list_history` | Never deleted, as above | — | — |
| `m20260727_000001_status_list_history_exp_index` | Never deleted, as above | — | — |
| `m20260923_000001_credentials_list_count` | Yes: the column defaults to `0` | `list-quota disable`, or the quota undercounts the previous release's publishes | Pods refuse to start without `APP_LIMITS__LIST_QUOTA_TRANSITION`; follow [Upgrading to the list quota](troubleshooting.md#upgrading-to-the-list-quota) |
| `m20260923_000002_list_quota` | Yes, once the quota is disabled | As above | As above |
| `m20260925_000001_status_list_allocations` | **No, for fixed-size lists** (see below) | Decide whether to roll forward instead | Find the lists the previous release converted |
| `m20260929_000001_credentials_aggregation_id` | Yes: the column is nullable, and the IDs are kept | — | Nothing; until then, scoped URIs return `404` (see [Rolling back](#rolling-back)) |
| `m20260929_000002_status_lists_issuer_list_id_index` | Yes: an index | — | — |

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

## Next Steps

- [deploy/helm/README.md](../deploy/helm/README.md): full chart value reference and configuration guide.
- [LOCAL_DEPLOYMENT.md](LOCAL_DEPLOYMENT.md): detailed local quickstart.
- [dns-providers.md](dns-providers.md): ACME DNS-01 provider setup per provider.
- [secrets-backends.md](secrets-backends.md): database/secret backend options, and the Workload Identity opt-in in [`deploy/helm/README.md`](../deploy/helm/README.md).
- [database-backends.md](database-backends.md): supported database backends.
- [observability.md](observability.md): OpenTelemetry / metrics / logs.
