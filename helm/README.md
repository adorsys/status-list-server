# Deployment Guide

This guide provides instructions for deploying the Status List Server using the provided Helm chart.

## Prerequisites

- Kubernetes cluster
- Helm 3 installed
- `kubectl` configured to connect to your cluster
- External Secrets Operator (ESO) installed when `externalSecret.enabled=true` (the default). The chart renders `external-secrets.io/v1` `ExternalSecret`, `SecretStore`, and `ClusterSecretStore` references, so the cluster CRDs must serve `external-secrets.io/v1` before installing or upgrading this chart. ESO v0.16 promoted these resources to `v1`; upgrade the ESO controller and CRDs together, and if CRDs are managed separately, apply the matching CRD bundle before upgrading the operator.

## Chart Dependencies

This chart has the following dependencies:

- **PostgreSQL**: A relational database for storing application data.
- **OpenTelemetry Collector**: Official subchart (`open-telemetry/opentelemetry-collector`) for collecting and routing traces, metrics, and logs.

These dependencies are managed by the Helm chart. PostgreSQL is enabled by default.

## Configuration

The following files are used to configure the deployment:

- [`chart/values.yaml`](chart/values.yaml): Provider-neutral default configuration.
- [`chart/values-local.yaml`](chart/values-local.yaml): Configuration for local development.
- [`chart/values-aws.yaml`](chart/values-aws.yaml): Explicit AWS/EKS example overlay.
- [`chart/values-production.yaml`](chart/values-production.yaml): Production overlay used by release deployments.

### Key Configuration Options

- **`statuslist.image.repository`**: The Docker image for the application.
- **`global.domain`**: Chart-wide public DNS suffix. When set, ingress defaults derive `statuslist.<global.domain>` and `*.<global.domain>` from this single value.
- **`global.storageClass` / `postgres.persistence.storageClass`**: Leave as `""` to use the cluster default StorageClass; set explicitly in environment overlays when needed.
- **`statuslist.image.tag`**: The Docker image tag. Used only when `statuslist.image.digest` is empty. Defaults to empty, which falls back to the chart's `appVersion` — the published filesystem certificate-store variant tag, not `latest`, so an upgrade that changes nothing in the chart cannot change the running image and a rollback stays reproducible. Cloud-specific images are selected explicitly in overlays such as `values-aws.yaml`.
- **`statuslist.image.pullPolicy`**: Defaults to empty, which derives the policy from how the image is named: `IfNotPresent` when a digest is set, because a digest is content-addressed and re-pulling it can only fetch the same bytes, and `Always` for a tag, which is mutable. Set it explicitly to override.
- **`statuslist.image.digest`**: An image digest as `sha256:` plus 64 hex characters; anything else is rejected at template time/schema validation. When set it takes precedence over `statuslist.image.tag`, and the deployment runs `repository@digest`. Production deploys set this so the running image is the exact artifact CI scanned; tags are mutable and a digest is not. Leave it empty for local and manual installs to get tag-based deployment.
- **`postgres.persistence.enabled`**: Enable or disable persistent storage for PostgreSQL.

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
- `serviceAccount.automountServiceAccountToken`: default `false`; set to `true` only if the application needs Kubernetes API access.

### Pod labels and Azure Workload Identity

Azure Workload Identity requires the pod label `azure.workload.identity/use: "true"` in addition to the ServiceAccount annotation. Add it (and any other pod labels) via `statuslist.podLabels`:

```yaml
statuslist:
  podLabels:
    azure.workload.identity/use: "true"
```

The ServiceAccount annotation alone is not sufficient for Azure; both the annotation and this pod label must be present.

## AWS Configuration and Static Credentials vs. Workload Identity

The base chart is provider-neutral: `externalSecret.enabled=false`, `secretStore.enabled=false`, and `statuslist.aws.mountCredentials=false`. Enable External Secrets Operator (ESO) and choose a provider explicitly in an environment overlay. The AWS example overlay restores the Secrets Manager/static credential mount path:

```yaml
statuslist:
  image:
    tag: "1.0.1-aws"
  aws:
    mountCredentials: true # mount the ESO-provisioned aws-credentials-secret under /home/nobody/.aws
    region: "" # plain, non-secret; renders APP_AWS__REGION
    credentialsSecret:
      remoteKey: "statuslist-aws-credentials" # SecretStore key holding both AWS shared files
      credentialsProperty: "CREDENTIALS" # property in remoteKey with the credentials file
      configProperty: "CONFIG" # property in remoteKey with the config file
```

`statuslist.aws.region` is a plain (non-secret) value; `APP_AWS__REGION` is rendered whenever an effective region is set, independent of `secretStore.provider` and `mountCredentials`.

For ambient Workload Identity / IRSA, keep `statuslist.aws.mountCredentials=false` (no credentials mounted) and attach the cloud role annotation via `serviceAccount.annotations` (e.g. `eks.amazonaws.com/role-arn` for EKS IRSA, or the GCP / Azure WI annotations described above). The application then authenticates using the ambient credentials provided by that role instead of mounted files.

**Upgrade compatibility:** The effective `APP_AWS__REGION` resolves as `statuslist.aws.region`, falling back to the legacy `secretStore.aws.region`. Installations that previously set only `secretStore.aws.region` keep that region for the application across upgrade. The AWS ESO `SecretStore` still falls back to `eu-central-1` when no region is configured, but that fallback is not injected into the application pod.

When `statuslist.aws.mountCredentials=true` **and** `externalSecret.enabled=true`, the chart itself renders a second `ExternalSecret` that provisions `aws-credentials-secret` — the exact Secret the Deployment's credential volume references. It synchronizes two keys into that Secret:

- `credentials` ← `remoteKey`/`credentialsProperty` (the AWS shared credentials file, INI format, e.g. `[default]\naws_access_key_id=...\naws_secret_access_key=...`)
- `config` ← `remoteKey`/`configProperty` (the AWS shared config file)

The chart mounts that Secret at `/home/nobody/.aws` and sets `AWS_SHARED_CREDENTIALS_FILE` / `AWS_CONFIG_FILE`. Because the chart now owns provisioning of `aws-credentials-secret`, a first release never mounts a Secret that nothing created. The application ExternalSecret target template is not reused for this dedicated AWS credentials Secret; use `statuslist.aws.credentialsSecret.targetTemplate` only if the AWS Secret itself needs templating. In the no-ESO fallback mode (`externalSecret.enabled=false`), the mounted path is not wired automatically — operators must create `aws-credentials-secret` themselves or use Workload Identity.

### Least-privilege IAM policy for the application role

Attach a least-privilege policy to the IRSA role referenced by `serviceAccount.annotations.eks.amazonaws.com/role-arn` (via the trust policy above), scoped to the resources the server actually uses:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Route53DNS01",
      "Effect": "Allow",
      "Action": [
        "route53:ChangeResourceRecordSets",
        "route53:ListResourceRecordSets",
        "route53:GetChange"
      ],
      "Resource": [
        "arn:aws:route53:::hostedzone/<HOSTED_ZONE_ID>",
        "arn:aws:route53:::change/*"
      ]
    },
    {
      "Sid": "SecretsManager",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:<REGION>:<ACCOUNT_ID>:secret:status-list/*"
    },
    {
      "Sid": "S3StatusList",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::status-list-adorsys/*"
    }
  ]
}
```

Replace `<HOSTED_ZONE_ID>`, `<REGION>`, and `<ACCOUNT_ID>` with your values, and drop any `Sid` the server does not need so the role stays minimal.

## SecretStore Providers

External Secret Operator's `SecretStore` is provider-neutral via `secretStore.provider` (`aws` | `vault` | `gcp` | `azure` | `raw`). The shipped default leaves the provider empty because `secretStore.enabled=false`. A `SecretStore` is rendered **only** when `externalSecret.enabled=true` **and** `secretStore.enabled=true` — in the no-ESO fallback mode it is never emitted, so a cluster without ESO CRDs accepts the release.

This chart uses the stable ESO API group/version `external-secrets.io/v1`. Before installing with ESO enabled, verify that the installed CRDs serve `v1` for `externalsecrets.external-secrets.io`, `secretstores.external-secrets.io`, `clustersecretstores.external-secrets.io`, and any cluster-scoped resources you use. Upgrade ESO and its CRDs as one unit; mismatched controller/CRD versions can cause Kubernetes to reject the rendered resources or ESO reconciliation to fail.

```yaml
secretStore:
  enabled: true
  provider: aws
  aws:
    service: SecretsManager # SecretsManager | ParameterStore
    region: "eu-central-1" # applies to the AWS SecretStore; APP_AWS__REGION falls back to statuslist.aws.region
  vault:
    server: ""
    path: "secret"
    auth: {}
  gcp:
    projectID: ""
    auth: {}
  azure:
    tenantId: ""
    vaultUrl: ""
    authType: "" # ServicePrincipal | ManagedIdentity | WorkloadIdentity
    environmentType: "" # optional: PublicCloud (default) | USGovernmentCloud | ChinaCloud | GermanCloud
    identityId: "" # ManagedIdentity: select one of multiple managed identities
    serviceAccountRef:
      name: "" # WorkloadIdentity: ESO's own least-privilege identity
      namespace: ""
    authSecretRef: {} # ServicePrincipal: clientId/clientSecret/tenantId secret selectors
  raw: {} # provider body passthrough (rendered directly under spec.provider)
```

- **aws** (`SecretsManager` or `ParameterStore`): `service` and `region`. `region` falls back to the effective app region when empty.
- **vault** (Vault / OpenBao-compatible): `server`, `path`, and an optional `auth` block.
- **gcp**: `projectID` plus an optional `auth` block (use Workload Identity for ambient auth).
- **azure**: `tenantId`, `vaultUrl`, and an `authType` validated as an enum per the ESO `AzureKVProvider` CRD — `ServicePrincipal | ManagedIdentity | WorkloadIdentity` (there is **no** `ClientSecret` authType). For Workload Identity use `authType: WorkloadIdentity` and bind `serviceAccountRef` to **External Secrets Operator's own identity** (least privilege) — **not** the application ServiceAccount. Managed-identity selection uses `identityId`; ServicePrincipal client credentials go under the `authSecretRef` block. `environmentType` is optional.
- **raw**: pass the concrete provider body through `secretStore.raw`, **rendered directly under `spec.provider`** for unsupported ESO providers without editing the chart. `secretStore.raw` holds only the provider body (no extra top-level `provider` key); an empty `raw: {}` is **rejected** so this path never silently emits a weakened SecretStore.

Provider selection is fail-closed: an unsupported `secretStore.provider` value is rejected by the chart's `values.schema.json` and a Helm `fail`, and contradictory mode combinations (ESO disabled while a SecretStore is requested) do not render the ESO CR.

## File-Based Secret Mounts and Rotation

`statuslist.secretMounts` mounts operator-managed Kubernetes Secrets as read-only files. Add `fileEnv` to a mount to expose a file path through the application environment:

```yaml
statuslist:
  secretMounts:
    - name: database-credentials
      secretName: statuslist-db-credentials
      mountPath: /etc/secrets/database
      items:
        - key: password
          path: password
      fileEnv:
        APP_DATABASE__PASSWORD_FILE: password
```

`fileEnv` values are relative to `mountPath`, and they work with or without `items`. By default, the chart mounts the application Secret's `postgres-password` key at `/var/run/status-list-server/database/password` and exposes that path through `APP_DATABASE__PASSWORD_FILE`. You can override `statuslist.secretMounts` to point at another Secret or mount path.

This chart support is preparatory for application images that implement the file-watcher and reload behavior from issue #456. Current images that only read `APP_DATABASE__PASSWORD` at startup still need a rollout after secret changes. The `checksum/secret` annotation only reacts to Helm-rendered ExternalSecret template or value changes; it does not change when External Secrets Operator later syncs new data from Vault, AWS, GCP, or Azure into a Kubernetes Secret.

For mounted Secrets that should be created by ESO, define them under `externalSecret.spec.extraExternalSecrets` and set each `target.name` to the `secretMounts[].secretName` value. If customer-side provisioning is used instead, the prerequisite Kubernetes Secret names and keys must exist before Helm deploys, otherwise Kubernetes cannot mount the volumes.

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
```

The fallback `Secret` is rendered only when `externalSecret.enabled=false` **and** `statuslist.fallbackSecret.enabled=true`. It uses `stringData`, so plain string values are base64-encoded by the API server. The fallback secret is always named `statuslist-secret` — the single supported name that the Deployment's `POSTGRES_PASSWORD` `secretKeyRef` and `postgres.auth.existingSecret` all reference, so it is not independently configurable.

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

## Migration: Static Credentials (ESO) to Workload Identity

The AWS overlay supports both the ESO-mounted static-credential path (`statuslist.aws.mountCredentials=true`, the `aws-credentials-secret`) and Workload Identity / IRSA:

1. Ensure the default ESO path works: `externalSecret.enabled=true` — the chart's `statuslist-external-secret-aws-credentials` ExternalSecret provisions `aws-credentials-secret` (holding `credentials` + `config`), which is mounted under `/home/nobody/.aws`.
2. Configure Workload Identity: attach the role annotation via `serviceAccount.annotations` (e.g. `eks.amazonaws.com/role-arn` for EKS IRSA).
3. Flip to Workload Identity: set `statuslist.aws.mountCredentials=false`.
4. After verification, delete the mounted `aws-credentials-secret` and any legacy static AWS GitHub secrets.

For production, the deploy workflow applies [`values-production.yaml`](./chart/values-production.yaml), which explicitly selects the AWS image, `global.domain`, the `high-performance` storage class, AWS Secrets Manager, and ESO-mounted credentials (`statuslist.aws.mountCredentials=true`). Migrating production to Workload Identity / IRSA is the documented step above — wire the `eks.amazonaws.com/role-arn` annotation and set `statuslist.aws.mountCredentials=false` in `values-production.yaml` **only after** the IRSA role is provisioned, otherwise the next deploy would have no AWS credentials.

## Credential Exposure Model

The chart intentionally avoids rendering fully assembled SQL database URLs in the Deployment. The application assembles the connection string inside the process from split configuration fields:

- Database: `APP_DATABASE__HOST`, `APP_DATABASE__PORT`, `APP_DATABASE__USERNAME`, `APP_DATABASE__PASSWORD_FILE`, `APP_DATABASE__NAME`, and optional `APP_DATABASE__QUERY`

Use `APP_DATABASE__QUERY` for non-secret driver parameters such as `sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt`. Do not put credentials in query parameters.

Password values are mounted as Secret volume files, so `kubectl describe pod` shows the referenced Secret name/key and file path rather than a connection string containing credentials. Operators should still restrict RBAC for pod inspection, Secret reads, exec access, ephemeral containers, and workload log access to trusted roles only, because Secret references identify where credentials live.

For external databases such as RDS, set `APP_DATABASE__HOST`, `APP_DATABASE__PORT`, `APP_DATABASE__BACKEND`, `APP_DATABASE__USERNAME`, `APP_DATABASE__NAME`, and optional `APP_DATABASE__QUERY` through `statuslist.env`. Do not set `APP_DATABASE__PASSWORD` there. The chart default reads `APP_DATABASE__PASSWORD_FILE` from the `statuslist-secret` Secret key named `postgres-password`; override `statuslist.secretMounts` when the database password lives in another Secret or key.

`APP_DATABASE__PORT` must be set in `statuslist.env`; the chart does not infer or default it from the PostgreSQL subchart. This keeps the database port an explicit runtime input and avoids silently connecting to the wrong port when operators customize database topology.

`APP_DATABASE__URL` remains supported by the application for local or custom deployments, but the Helm chart rejects it in `statuslist.env` because using it directly in Kubernetes pod specs accepts the tradeoff that users with pod-inspection permissions may see assembled connection strings. Prefer the split fields for Helm-managed deployments. When any split database field is provided, the application rejects a simultaneous custom `database.url` to avoid silent precedence surprises.

The bundled in-cluster PostgreSQL subchart is treated as a cluster-internal connection and this chart does not provision database TLS certificates by default. **In-cluster database traffic is unencrypted by default** and relies on CNI/mesh encryption (if configured in your cluster). For managed or external databases, prefer TLS and set non-secret driver parameters with `APP_DATABASE__QUERY`, for example `sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt`. The referenced CA path must exist in the container, either from the image trust store or from an operator-provided mount.

To enable TLS for external databases, set `APP_DATABASE__QUERY` to include the appropriate SSL mode, for example: `sslmode=require` for basic TLS or `sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt` for full certificate verification.

The application no longer provides a built-in `database.url` default. Non-Helm and local deployments must set either `APP_DATABASE__URL` or the split database fields explicitly; SQLite development runs should set `APP_DATABASE__URL=sqlite::memory:?cache=shared` when an in-memory database is intended.

## Production Deployment Instructions

For GitHub Actions deployments to production, see the [Deployment Runbook](../docs/deployment-runbook.md). CI/CD owns production image injection with `statuslist.image.repository`, `statuslist.image.tag` and `statuslist.image.digest`. The digest is what determines the running image; the tag is passed alongside it for readability in `helm history` and release notes. Because of that precedence, do not run `helm upgrade --reuse-values` with only a changed tag: the stored digest still wins, so the upgrade reports success and changes nothing. Pass both, or clear the digest with `--set statuslist.image.digest=null`. A digest that is not `sha256:` followed by 64 hex characters is rejected at template time. Operators should avoid patching live images imperatively because Helm will reconcile the chart state on the next deploy. Failed upgrades roll back automatically through Helm `--atomic`; rollbacks after a successful but bad deploy are manual Helm operations.

1. **Create a namespace:**

   ```bash
   kubectl create namespace statuslist
   ```

2. **Deploy the chart:**

   ```bash
   helm install statuslist ./chart --namespace statuslist
   # AWS/EKS example:
   helm install statuslist ./chart --namespace statuslist -f chart/values-aws.yaml
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
