# Deployment Runbook

This runbook is for **you**: you have the Status List Server project and want to deploy it on **your own** Kubernetes cluster. It lays out the deployment options available and the steps to follow, regardless of where the cluster runs (EKS, GKE, AKS, or a local cluster such as Minikube or kind).

## Deployment Options at a Glance

You have three broad ways to run the Status List Server:

| Option | Cluster | Purpose | Chart values |
| --- | --- | --- | --- |
| **Local / development** | Minikube, kind, Docker Desktop | Manual testing, iteration | `values-local.yaml` |
| **Self-managed deploy (recommended)** | Any cluster you own | A real, repeatable deployment | `values.yaml` (+ your own overrides) |
| **Bundled chart only** | Any cluster | Bring-your-own containers / compose (non-Helm) | n/a (Docker / Kubernetes manifests) |

The project ships a Helm chart (`helm/chart`) that is the recommended, supported way to deploy. The chart bundles:

- the **Status List Server** application Deployment, Service, and (optionally) Ingress;
- a **PostgreSQL** subchart for the database;
- an **OpenTelemetry Collector** subchart for traces/metrics/logs (optional).

Everything below assumes you deploy with Helm. The chart is the source of truth for how the application is configured and run; see `helm/README.md` for the full value reference and `docs/` for supporting topics (secrets, DNS providers, database backends, observability).

## Prerequisites

- A Kubernetes cluster you can talk to (`kubectl` configured with the right context).
- `kubectl` and Helm 3 (≥ v3.8) installed.
- Network access from the cluster to pull images, and — if you use the ACME certificate provisioning — to the certificate authority and your DNS provider.
- A way to get images: either a registry account you control, or a local image load (Minikube/kind).

### Decide on your image

The chart's default `statuslist.image.repository` points at `ghcr.io/adorsys/status-list-server` for convenience. For your own deployment you will normally:

- **Build and push to your own registry**, then point `statuslist.image.repository` and `statuslist.image.tag` (or `digest`) at it, or
- **Load a locally built image** into a local cluster (Minikube `minikube image load`, kind `kind load docker-image`) and use `pullPolicy: IfNotPresent`.

Set `statuslist.image.tag` explicitly. If both `tag` and `digest` are empty, the chart falls back to its `appVersion`. Prefer a `sha256:` `digest` for reproducible production deploys (see [Pinning the image](#pinning-the-image)`).

## Option 1 — Local / Development Deployment

The quickest path to a running instance, using `values-local.yaml`. It disables the Ingress, the External Secrets Operator and SecretStore CRs, and the OpenTelemetry Collector, and uses non-persistent PostgreSQL with lighter resources so it runs on a laptop.

### Steps

```bash
# 1. Start a local cluster (example: Minikube)
minikube start
kubectl config use-context minikube

# 2. Namespace
kubectl create namespace local

# 3. Seed the fallback database password Secret (any non-empty value)
kubectl create secret generic statuslist-secret -n local \
  --from-literal=postgres-password=postgres

# 4. Pull chart dependencies and install
helm dependency update ./helm/chart
helm install statuslist-local ./helm/chart \
  -n local -f ./helm/chart/values-local.yaml

# 5. Verify
kubectl get pods -n local
kubectl port-forward -n local svc/statuslist-local-status-list-server-service 8081:8081
curl http://localhost:8081/health/live
curl http://localhost:8081/health/ready
```

`values-local.yaml` only overrides what differs from the production defaults (disabled Ingress/ESO, NodePort/external reachability, lighter resource requests). If pods fail with `CreateContainerConfigError`, confirm the `statuslist-secret` Secret exists in the namespace. See `docs/LOCAL_DEPLOYMENT.md` for a more detailed local walkthrough.

## Option 2 — Self-Managed Deployment (any cluster)

This is the path to a real deployment on a cluster you own. It uses the production-oriented `values.yaml` defaults, which you override for your environment.

### High-level steps

1. Choose your secret and credential delivery (see [Secrets delivery](#secrets-delivery)).
2. Configure the application for your runtime (database, certificates, DNS provider, region).
3. (Optional) Enable an Ingress + TLS and route your domain to the service.
4. Install the chart with Helm and verify.

### Prepare the database password Secret

The application reads `POSTGRES_PASSWORD` from a Kubernetes Secret named `statuslist-secret` (key `postgres-password`), and the bundled PostgreSQL subchart references the same Secret. How that Secret is created depends on your [secrets mode](#secrets-delivery): via an ExternalSecret (ESO) or a plain fallback Secret you create by hand.

### Configure for your runtime

The chart's `statuslist.env` holds the application configuration. Set the values your deployment needs:

- **Database port**: `APP_DATABASE__PORT` (e.g. `5432`). This is **not** inferred from the PostgreSQL subchart — set it explicitly.
- **Certificate provisioning / ACME**: `APP_SERVER__CERT__*` values, including the ACME directory URL and the DNS provider for DNS-01 challenges. See [dns-providers.md](dns-providers.md) for what each provider (`route53`, `cloudflare`, `gcloud`, `azure`, `acmedns`) requires. Provider credentials must come from a Secret, not plain env values.
- **Region**: `statuslist.aws.region` (plain) renders `APP_AWS__REGION`.
- **Telemetry / limits / rate limiting / cache**: defaults are sensible; over-ride only what your sizing needs.

### Install

```bash
# Pull and package dependencies once
helm dependency update ./helm/chart

# Install with your values file (or inline --set overrides)
helm upgrade --install statuslist ./helm/chart \
  --namespace statuslist \
  --create-namespace \
  --atomic \
  --wait \
  --timeout 10m \
  -f ./helm/chart/values.yaml \
  -f ./my-deployment-values.yaml
```

Use `helm upgrade --install` rather than `helm install` so the same command both creates and later updates the release. `--atomic --wait --timeout 10m` makes failed upgrades roll back automatically during the pipeline.

### Expose the service (Ingress)

`values.yaml` ships with the Ingress enabled and nginx + cert-manager annotations, but they reference adorsys's domain (`*.eudi-adorsys.com`, `statuslist.eudi-adorsys.com`). For your own deployment:

- Set `statuslist.ingress.hosts`, `statuslist.ingress.tls.secretName`, and `statuslist.ingress.externalDnsHostname` to your domain.
- Ensure your Ingress controller (e.g. ingress-nginx) and certificate issuer (e.g. cert-manager) actually exist in your cluster, and adjust the `cert-manager.io/cluster-issuer` annotation to an issuer you own.
- Or set `statuslist.ingress.enabled=false` and expose the `ClusterIP` Service another way (NodePort, port-forward, or a LoadBalancer).

Because a default DNS-01 certificate provider is usually wired in, decide whether you want certificate provisioning at all. If you do not, disable it and terminate TLS at your ingress/load balancer instead (see [dns-providers.md](dns-providers.md) and [deployment-architecture.md](deployment-architecture.md)).

### Pinning the image

For a stable, reproducible deploy, pin the exact image:

```yaml
statuslist:
  image:
    repository: <your-registry>/status-list-server
    tag: "1.0.1"          # used when digest is empty
    digest: "sha256:<64 hex chars>"   # takes precedence over tag
```

When `digest` is set it takes precedence over `tag`, and Kubernetes runs `repository@digest`. `pullPolicy` derives automatically (`IfNotPresent` for a digest, `Always` for a mutable tag). A malformed digest (`not sha256:` + 64 hex) is rejected at template time rather than failing at pull time.

## Secrets Delivery

The chart supports two secret-delivery modes, plus a no-secret-manager fallback. Pick the one that matches your cluster. See [secrets-risk-eso-vs-workload-identity.md](secrets-risk-eso-vs-workload-identity.md) for the trade-offs in depth.

### Mode A — External Secrets Operator (ESO) [default]

The chart defaults to **External Secrets Operator** to synchronize secrets from a provider instead of storing them as plain Kubernetes Secrets.

- `externalSecret.enabled=true` and `secretStore.enabled=true` (both chart defaults) render ESO CRs:
  - a provider-neutral `SecretStore` (`secretStore.provider` selects `aws`, `vault`, `gcp`, `azure`, or `raw`);
  - an `ExternalSecret` that syncs `postgres-password` into a Kubernetes Secret named `statuslist-secret`;
  - (when `statuslist.aws.mountCredentials=true`, the default) a second `ExternalSecret` that provisions `aws-credentials-secret` — the AWS shared `credentials`/`config` files Mounted under `/home/nobody/.aws`.

**To use ESO** you must install External Secrets Operator in your cluster and configure:

- the provider (`secretStore.provider` and the matching provider block — e.g. AWS region + Secrets Manager/Parameter Store service);
- the remote keys your `ExternalSecret` references (e.g. a key holding the `POSTGRES_PASSWORD` property; the `aws-credentials-secret` keys holding `CREDENTIALS`/`CONFIG`).

Verify after install:

```bash
kubectl get secretstore,externalsecret -n <namespace>
kubectl describe secretstore <store> -n <namespace>
kubectl describe externalsecret <external-secret> -n <namespace>
```

A ready `ExternalSecret` shows a `SecretSynced` condition. A missing remote key or bad provider credentials appears in the status conditions.

### Mode B — Workload Identity (opt-in)

Instead of ESO-mounted static credentials, the application can use **ambient** cloud credentials via Workload Identity (EKS IRSA, GCP WI, Azure WIF):

- attach the role annotation via `serviceAccount.annotations` (e.g. `eks.amazonaws.com/role-arn` on EKS; see `helm/README.md` for GCP/Azure, and note Azure also needs the pod label `azure.workload.identity/use: "true"`);
- set `statuslist.aws.mountCredentials=false` so no credential files are mounted.

Attach a least-privilege policy to the role (see the example in `helm/README.md` for Route53 / Secrets Manager / S3).

### Mode C — Fallback plain Secret (no ESO)

If your cluster does **not** run External Secrets Operator, disable ESO and render a plain Kubernetes Secret:

```yaml
externalSecret:
  enabled: false
  secretStore:
    enabled: false

statuslist:
  fallbackSecret:
    enabled: true
    stringData:
      postgres-password: "change-me"
```

The fallback Secret is always named `statuslist-secret`. Because it uses `stringData`, values are base64-encoded by the API server. In this mode the `aws-credentials-secret` is not provisioned automatically — either create it yourself (for `mountCredentials=true`) or switch to Workload Identity.

## Scaling and Resilience (opt-in)

For a production-shape deployment enable scaling and disruption budgets together (disabled by default):

```yaml
replicaCount: 2   # or enable autoscaling below

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

When `autoscaling.enabled=true` the Deployment omits `replicas` so the HPA controls the count. Keep `podDisruptionBudget.maxUnavailable` below the replica count (the safe default) so node drains do not get blocked.

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

- **Failed upgrade**: automatic. `--atomic --wait --timeout 10m` rolls the release back during the upgrade when readiness fails or the timeout is hit.
- **Bad-but-successful deploy**: manual. List revisions and roll back:

```bash
helm history statuslist -n <namespace>
helm rollback statuslist <revision> -n <namespace> --wait --timeout 10m
kubectl rollout status deployment/statuslist-status-list-server-deployment -n <namespace>
```

Note: pinning by `digest` keeps rollbacks reproducible, since the stored digest — not a mutable tag — determines the running image. When upgrading, pass both `tag` and `digest` explicitly (or clear the digest with `--set statuslist.image.digest=null`); `helm upgrade --reuse-values` with only a changed tag will not move the image because the stored digest still wins.

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

## External Dependencies

- **External Secrets Operator** — needed for the default ESO secret path; install it in your cluster (or use Mode B / Mode C to avoid it).
- **Ingress controller + cert-manager** — needed only if you enable the Ingress / TLS path.
- **Your cloud provider** — for Workload Identity roles and any AWS/GCP/Azure backends the application uses.

## Next Steps

- [helm/README.md](../helm/README.md) — full chart value reference and configuration guide.
- [LOCAL_DEPLOYMENT.md](LOCAL_DEPLOYMENT.md) — detailed local quickstart.
- [dns-providers.md](dns-providers.md) — ACME DNS-01 provider setup per provider.
- [secrets-backends.md](secrets-backends.md), [secrets-risk-eso-vs-workload-identity.md](secrets-risk-eso-vs-workload-identity.md) — choosing a secrets delivery model.
- [database-backends.md](database-backends.md) — supported database backends.
- [observability.md](observability.md) — OpenTelemetry / metrics / logs.
