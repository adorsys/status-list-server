# Deployment Guide

This guide provides instructions for deploying the Status List Server using the provided Helm chart.

## Prerequisites

- Kubernetes cluster (e.g., AWS EKS)
- Helm 3 installed
- `kubectl` configured to connect to your cluster

## Chart Dependencies

This chart has the following dependencies:

- **PostgreSQL**: A relational database for storing application data.
- **Redis HA**: Optional high-availability Redis cluster for the distributed certificate-material cache.
- **OpenTelemetry Collector**: Official subchart (`open-telemetry/opentelemetry-collector`) for collecting and routing traces, metrics, and logs.

These dependencies are managed by the Helm chart. PostgreSQL is enabled by default; Redis HA is disabled by default and is installed only when `redis-ha.enabled=true`.

## Configuration

The following files are used to configure the deployment:

- [`chart/values.yaml`](chart/values.yaml): Default configuration for production environments.
- [`chart/values-local.yaml`](chart/values-local.yaml): Configuration for local development.

### Key Configuration Options

- **`statuslist.image.repository`**: The Docker image for the application.
- **`statuslist.image.tag`**: The Docker image tag.
- **`postgres.persistence.enabled`**: Enable or disable persistent storage for PostgreSQL.
- **`redis-ha.persistentVolume.enabled`**: Enable or disable persistent storage for Redis.
- **`redis-ha.enabled`**: Enable the optional Redis HA dependency and application Redis environment variables.

## ServiceAccount and Workload Identity

The chart renders a `ServiceAccount` for the application pod by default (`serviceAccount.create=true`) and wires it into the Deployment via `serviceAccountName`. This is required for Kubernetes **Workload Identity** so the pod receives the ambient cloud credentials it needs to reach AWS/GCP/Azure.

Attach Workload Identity / IRSA role annotations through `serviceAccount.annotations`, for example on EKS:

```yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/status-list-server
```

For GCP or Azure Workload Identity, set the provider-specific annotation instead. Use `serviceAccount.labels` for any additional labels. Set `serviceAccount.automountServiceAccountToken=false` to harden the pod when it has no Kubernetes API access needs.

- `serviceAccount.create`: render a ServiceAccount (default `true`). When `false`, the Deployment uses the `default` service account.
- `serviceAccount.name`: override the ServiceAccount name (default: the chart fullname).
- `serviceAccount.automountServiceAccountToken`: default `true`; harden to `false` if the API token is not needed.

### Pod labels and Azure Workload Identity

Azure Workload Identity requires the pod label `azure.workload.identity/use: "true"` in addition to the ServiceAccount annotation. Add it (and any other pod labels) via `statuslist.podLabels`:

```yaml
statuslist:
  podLabels:
    azure.workload.identity/use: "true"
```

The ServiceAccount annotation alone is not sufficient for Azure; both the annotation and this pod label must be present.

## AWS Configuration and Workload Identity vs. Static Credentials

```yaml
statuslist:
  aws:
    mountCredentials: false   # opt-in static credential files (legacy / non-IRSA)
    region: ""                # plain, non-secret; renders APP_AWS__REGION
```

By default (`statuslist.aws.mountCredentials=false`, Workload Identity mode) **no AWS credentials are mounted** into the pod. The application authenticates using ambient credentials provided by the ServiceAccount role annotation. `statuslist.aws.region` is a plain (non-secret) value; `APP_AWS__REGION` is rendered whenever an effective region is set, independent of `secretStore.provider` and `mountCredentials`.

**Upgrade compatibility:** The effective `APP_AWS__REGION` resolves as `statuslist.aws.region`, falling back to the legacy `secretStore.aws.region` and then `eu-central-1`. Installations that previously set only `secretStore.aws.region` keep that region for the application across upgrade.

To preserve legacy static-credential behavior (pre-Workload-Identity), set `statuslist.aws.mountCredentials=true`. This mounts the operator-created `aws-credentials-secret` at `/home/nobody/.aws` and sets `AWS_SHARED_CREDENTIALS_FILE` / `AWS_CONFIG_FILE`.

## SecretStore Providers

External Secret Operator's `SecretStore` is provider-neutral via `secretStore.provider` (`aws` | `vault` | `gcp` | `azure` | `raw`). The shipped default is `aws`. A `SecretStore` is rendered **only** when `externalSecret.enabled=true` **and** `secretStore.enabled=true` — in the no-ESO fallback mode it is never emitted, so a cluster without ESO CRDs accepts the release.

```yaml
secretStore:
  enabled: true
  provider: aws
  aws:
    service: SecretsManager   # SecretsManager | ParameterStore
    region: "eu-central-1"    # applies to the AWS SecretStore; APP_AWS__REGION falls back to statuslist.aws.region
  vault:
    server: ""
    path: "secret"
    auth: {}
  gcp:
    projectID: ""
    auth: {}
  azure:
    tenantId: ""
    clientId: ""
    vaultUrl: ""
    authType: WorkloadIdentity      # WorkloadIdentity | ManagedIdentity | ClientSecret
    serviceAccountRef:
      name: ""                      # ESO's own least-privilege identity
      namespace: ""
    auth: {}
  raw: {}                           # full provider spec passthrough (must include a `provider` key)
```

- **aws** (`SecretsManager` or `ParameterStore`): `service` and `region`. `region` falls back to the effective app region when empty.
- **vault** (Vault / OpenBao-compatible): `server`, `path`, and an optional `auth` block.
- **gcp**: `projectID` plus an optional `auth` block (use Workload Identity for ambient auth).
- **azure**: `tenantId`, `clientId` (optional), `vaultUrl`, and an `authType`. For Workload Identity use `authType: WorkloadIdentity` and bind `serviceAccountRef` to **External Secrets Operator's own identity** (least privilege) — **not** the application ServiceAccount. Managed-identity or client-secret auth uses `authType` `ManagedIdentity` / `ClientSecret` together with the `auth` block.
- **raw**: pass the full `spec.provider` through `secretStore.raw` for unsupported ESO providers without editing the chart. `secretStore.raw` must include a top-level `provider` key; an empty `raw: {}` is **rejected** so this path never silently emits a weakened SecretStore.

Provider selection is fail-closed: an unsupported `secretStore.provider` value is rejected by the chart's `values.schema.json` and a Helm `fail`, and contradictory mode combinations (ESO disabled while a SecretStore is requested) do not render the ESO CR.

## Fallback Kubernetes Secret (no External Secrets Operator)

For clusters that do **not** run External Secret Operator, the chart can render a plain Kubernetes `Secret` that the Deployment references:

```yaml
externalSecret:
  enabled: false

statuslist:
  fallbackSecret:
    enabled: true
    stringData:
      postgres-password: "change-me"
      redis-password: "change-me"   # only needed when redis-ha.enabled=true
```

The fallback `Secret` is rendered only when `externalSecret.enabled=false` **and** `statuslist.fallbackSecret.enabled=true`. It uses `stringData`, so plain string values are base64-encoded by the API server. The fallback secret is always named `statuslist-secret` — the single supported name that the Deployment's `POSTGRES_PASSWORD` / `REDIS_PASSWORD` `secretKeyRef`, `postgres.auth.existingSecret`, and `redis-ha.existingSecret` all reference, so it is not independently configurable.

## Horizontal Autoscaling and Pod Disruption Budget

Scaling is opt-in and disabled by default. Enable autoscaling and a Pod Disruption Budget together for multi-replica production deployments:

```yaml
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
  # With HPA enabled the Deployment omits `replicas`, so prefer maxUnavailable (or set
  # minAvailable below autoscaling.minReplicas) to keep the PDB valid.
  maxUnavailable: 1
```

When `autoscaling.enabled=true` the Deployment's `replicas` field is omitted (HPA controls the count). Scaled Pods share the application ServiceAccount; each Pod receives its own short-lived Workload Identity token, so no per-Pod cloud registration is required.

## Migration: Static Credentials to Workload Identity

Deployments currently relying on the implicit static credential mount (`secretStore.enabled=true` with an external `aws-credentials-secret`) must opt back in explicitly until Workload Identity is configured:

1. Until IRSA/WI is ready, set `statuslist.aws.mountCredentials=true` to keep mounting the static credentials.
2. Configure Workload Identity: attach the role annotation via `serviceAccount.annotations` (e.g. `eks.amazonaws.com/role-arn` for EKS IRSA).
3. Flip to Workload Identity: set `statuslist.aws.mountCredentials=false` (the default).
4. After verification, delete the mounted `aws-credentials-secret` and any legacy static AWS GitHub secrets.

## Redis Role

Redis is optional. The server does not use Redis for status-list persistence or status-list reads; those use the configured repository backend and the in-process Moka status-list cache. Certificate and signing-key material are managed together by the feature-selected cryptographic-material backend; prefer the built-in material read-cache TTLs before adding Redis.

Keep Redis disabled for a simpler deployment. Enable it only for explicit adapter-level integrations that still require Redis and where the extra dependency, credentials, TLS configuration, monitoring, and HA operations are worth it.

### No-Redis Deployment

The default `chart/values.yaml` path keeps `redis-ha.enabled=false`, does not render Redis application env vars, does not render the Redis TLS sync CronJob, and does not require a `redis-password` secret key.

```bash
helm dependency update ./chart
helm template statuslist ./chart --namespace statuslist
```

### Redis-Enabled Certificate Cache

To enable Redis, use an application image built with `redis,aws-secrets,acme` features, set `redis-ha.enabled=true`, provide a `redis-password` in the configured secret or ExternalSecret, and keep `APP_REDIS__URI` unset in `statuslist.env` so the chart can generate it from the Redis HA service. Set `APP_REDIS__REQUIRE_CLIENT_AUTH` and Redis HAProxy TLS values only when your Redis endpoint requires them.

## Production Deployment Instructions

For GitHub Actions deployments to production, see the [Deployment Runbook](../docs/deployment-runbook.md). CI/CD owns production image tag injection with `statuslist.image.repository` and `statuslist.image.tag`; operators should avoid patching live images imperatively because Helm will reconcile the chart state on the next deploy. Failed upgrades roll back automatically through Helm `--atomic`; rollbacks after a successful but bad deploy are manual Helm operations.

1. **Create a namespace:**

   ```bash
   kubectl create namespace statuslist
   ```

2. **Create TLS secrets, if Redis HAProxy TLS is enabled:**

   Refer to the [Redis TLS Setup Guide](../docs/REDIS_TLS_SETUP.md) for detailed instructions on creating the necessary TLS secrets for Redis and HAProxy.

3. **Deploy the chart:**

   ```bash
   helm install statuslist ./chart --namespace statuslist -f chart/values.yaml
   ```

## Local Deployment

For local testing and development, please refer to the [Local Deployment Guide](../docs/LOCAL_DEPLOYMENT.md).

## Verifying the Deployment

1. **Check the status of the pods:**

   ```bash
   kubectl get pods -n statuslist
   ```

2. **Check the application logs:**

   ```bash
   kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist
   ```
