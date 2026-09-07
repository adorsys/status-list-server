# Deployment Runbook

This runbook describes how to deploy the Status List Server project on a Kubernetes cluster. It lays out the deployment options available and the steps to follow.

## Deployment Options at a Glance

You have three broad ways to run the Status List Server:

- **Local / development** (Minikube, kind, Docker Desktop): manual testing and iteration, using [`chart/values-local.yaml`](../helm/chart/values-local.yaml).
- **Self-managed deploy** (recommended; any cluster you own): a real, repeatable deployment using `chart/values.yaml` plus your own overrides.
- **Bundled chart only**: bring your own containers or compose workflows (non-Helm).

The project ships a Helm chart (`helm/chart`) that is the recommended, supported way to deploy. The chart bundles:

- the **Status List Server** application Deployment, Service, and (optionally) Ingress;
- a **PostgreSQL** subchart for the database;
- an **OpenTelemetry Collector** subchart for traces/metrics/logs (optional).

Everything below assumes you deploy with Helm. The chart is the source of truth for how the application is configured and run; see [`helm/README.md`](../helm/README.md) for the full value reference and the [Next steps](#next-steps) section for supporting topics (secrets, DNS providers, database backends, observability).

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
helm dependency update ./helm/chart

# NOTE: only variant-suffixed tags are published. With an empty tag, the chart
# uses its provider-neutral appVersion (-fscert). Override the tag only when
# you want a specific cloud variant or a locally loaded image.
helm install statuslist-local ./helm/chart \
  -n local -f ./helm/chart/values-local.yaml

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

The application reads the database password from a Kubernetes Secret named `statuslist-secret` (key `postgres-password`), and the bundled PostgreSQL subchart references the same Secret. The chart mounts that Secret as a file (default `mountPath: /var/run/status-list-server/database`, item `postgres-password` → `password`) and exposes it through `APP_DATABASE__PASSWORD_FILE`. It deliberately does **not** inject `APP_DATABASE__PASSWORD` as a literal environment variable, and rejects it if you try.

How the Secret is created depends on your [secrets mode](#secrets-delivery): via an ExternalSecret (ESO) or a plain fallback Secret the chart renders for you.

### Configure for your runtime

The chart's `statuslist.env` holds the application configuration. Set the values your deployment needs:

- **Database port**: `APP_DATABASE__PORT` (e.g. `5432`). This is **not** inferred from the PostgreSQL subchart: set it explicitly.
- **Certificate files or ACME**: the default `-fscert` image reads the certificate and signing key from files mounted into the pod. ACME-enabled image variants perform DNS-01 certificate issuance at startup, so configure `APP_SERVER__CERT__*` values for the DNS provider and deliver provider credentials from a Secret, not plain env values. See [dns-providers.md](dns-providers.md) for what each provider (`route53`, `cloudflare`, `gcloud`, `azure`, `acmedns`) requires.
- **Region** (`statuslist.aws.region`, renders `APP_AWS__REGION`): only required when you use an AWS-backed secret or DNS backend; omit it for other providers.
- **Telemetry / limits / rate limiting / cache**: defaults are sensible; over-ride only what your sizing needs.

### Install

```bash
# Pull and package dependencies once
helm dependency update ./helm/chart

# Install with your values file (or inline --set overrides)
helm upgrade --install statuslist ./helm/chart \
  --namespace statuslist \
  --create-namespace \
  --rollback-on-failure \
  --wait \
  --timeout 10m \
  -f ./helm/chart/values.yaml \
  -f ./my-deployment-values.yaml
```

Use `helm upgrade --install` rather than `helm install` so the same command both creates and later updates the release. `--rollback-on-failure --wait --timeout 10m` makes failed upgrades roll back automatically during the pipeline. (This is the Helm 4 name; Helm 3 also accepts the legacy `--atomic` flag.)

### Expose the service (Ingress)

`values.yaml` ships with Ingress enabled, a neutral `localhost` host, and no TLS/cert-manager redirect annotations. For your own public deployment:

- Set `global.domain` to derive `statuslist.<global.domain>` and `*.<global.domain>` from one chart-wide value, or set `statuslist.ingress.externalDnsHostname` and `statuslist.ingress.tls.hosts` explicitly.
- Ensure your Ingress controller (e.g. ingress-nginx) and certificate issuer (e.g. cert-manager) actually exist in your cluster, then add TLS/cert-manager annotations such as `cert-manager.io/cluster-issuer` and nginx SSL redirects in your environment overlay.
- Or set `statuslist.ingress.enabled=false` and expose the `ClusterIP` Service another way (NodePort, port-forward, or a LoadBalancer).

The AWS overlay shows the Ingress + cert-manager path explicitly. Direct AWS NLB exposure lives in `values-aws-nlb.yaml` and disables Ingress so the two public paths are not active at the same time.

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

The chart supports fallback Secret, ESO, and Workload Identity paths. Pick the one that matches your cluster. The trade-offs for ESO vs Workload Identity are covered in [`helm/README.md`](../helm/README.md) and the database/secret backend options in [secrets-backends.md](secrets-backends.md).

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
      postgres-password: ""
```

Leave `postgres-password` empty to generate a password; Helm reuses the existing cluster Secret on upgrades when it can read it.

### Mode B: External Secrets Operator (ESO)

Use ESO to synchronize secrets from a provider instead of storing them as Helm-rendered plain Kubernetes Secrets.

- `externalSecret.enabled=true`, `secretStore.enabled=true`, and `statuslist.fallbackSecret.enabled=false` render ESO CRs:
  - a provider-neutral `SecretStore` (`secretStore.provider` selects `aws`, `vault`, `gcp`, `azure`, or `raw`);
  - an `ExternalSecret` that syncs `postgres-password` into a Kubernetes Secret named `statuslist-secret`;
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

- attach the role annotation via `serviceAccount.annotations` (e.g. `eks.amazonaws.com/role-arn` on EKS; see the [Workload Identity section of `helm/README.md`](../helm/README.md#use-workload-identity-instead-of-mounted-credentials) for GCP/Azure, and note Azure also needs the pod label `azure.workload.identity/use: "true"`);
- set `statuslist.aws.mountCredentials=false` so no credential files are mounted.

Attach a least-privilege policy to the role (see the example in the Workload Identity section of [`helm/README.md`](../helm/README.md) for Route53 / Secrets Manager / S3).

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

- **Failed upgrade**: automatic. `--rollback-on-failure --wait --timeout 10m` rolls the release back during the upgrade when readiness fails or the timeout is hit.
- **Bad-but-successful deploy**: manual. List revisions and roll back:

```bash
helm history statuslist -n <namespace>
helm rollback statuslist <revision> -n <namespace> --wait --timeout 10m
kubectl rollout status deployment/statuslist-status-list-server-deployment -n <namespace>
```

Note: pinning by `digest` keeps rollbacks reproducible, since the stored digest (not a mutable tag) determines the running image. When upgrading, pass both `tag` and `digest` explicitly (or clear the digest with `--set statuslist.image.digest=null`); `helm upgrade --reuse-values` with only a changed tag will not move the image because the stored digest still wins.

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

- **External Secrets Operator**: needed only when you choose ESO secret delivery; the default fallback Secret path does not require ESO CRDs.
- **Ingress controller + cert-manager**: needed only if you enable the Ingress / TLS path.
- **Your cloud provider**: for Workload Identity roles and any AWS/GCP/Azure backends the application uses.

## Next Steps

- [helm/README.md](../helm/README.md): full chart value reference and configuration guide.
- [LOCAL_DEPLOYMENT.md](LOCAL_DEPLOYMENT.md): detailed local quickstart.
- [dns-providers.md](dns-providers.md): ACME DNS-01 provider setup per provider.
- [secrets-backends.md](secrets-backends.md): database/secret backend options, and the Workload Identity opt-in in [`helm/README.md`](../helm/README.md).
- [database-backends.md](database-backends.md): supported database backends.
- [observability.md](observability.md): OpenTelemetry / metrics / logs.
