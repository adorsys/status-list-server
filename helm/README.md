# Status List Server: Helm Deployment

This guide shows you how to deploy the Status List Server on Kubernetes with the Helm chart in this directory ([`chart/`](chart/)).

## Prerequisites

* A Kubernetes cluster (EKS, GKE, AKS, or any standard `apps/v1` cluster) running version 1.24 or newer.
* [Helm](https://helm.sh/docs/intro/install/) and [`kubectl`](https://kubernetes.io/docs/tasks/tools/).
* An ingress controller and [cert-manager](https://cert-manager.io/docs/installation/) if you expose the server over HTTPS.
* Access to the public images at `ghcr.io/adorsys/status-list-server`.
* [External Secrets Operator (ESO)](https://external-secrets.io/latest/) if you enable `externalSecret.enabled=true`. With ESO enabled, the cluster CRDs must serve `external-secrets.io/v1` for `ExternalSecret`, `SecretStore`, and any `ClusterSecretStore` references before installing or upgrading this chart.

## Choose Your Image Variant

The server is published as several image variants, each built for a different way of storing the token-signing key and issuer certificate that make up the server's signing identity.

| Image suffix | Signing-credential backend             | Best for                             |
| ------------ | -------------------------------------- | ------------------------------------ |
| `-aws`       | AWS Secrets Manager + Route53 DNS-01   | Running on EKS / using AWS           |
| `-gcp`       | GCP Secret Manager + Google Cloud DNS  | Running on GKE / using GCP           |
| `-azure`     | Azure Key Vault + Azure DNS            | Running on AKS / using Azure         |
| `-vault`     | HashiCorp Vault / OpenBao KV v2        | Operating your own Vault             |
| `-fscert`    | File-based signing key and certificate | Delivering signing material as files |

No unsuffixed image (`latest`, `1.2.0`) is published. Use a variant-suffixed tag, for example `1.2.0-aws`.

If `statuslist.image.tag` and `statuslist.image.digest` are both empty, the chart derives `<appVersion-without-suffix>-<statuslist.image.variant>`. The default variant is `fscert`, so base installs stay provider-neutral. Cloud-specific variants, including `aws`, are selected explicitly through values overlays such as [`chart/values-aws.yaml`](chart/values-aws.yaml) and [`chart/values-production.yaml`](chart/values-production.yaml).

For production, pin the exact artifact by digest rather than tag. A digest is validated as `sha256:` followed by 64 hex characters.

## Key Values

* [`chart/values.yaml`](chart/values.yaml): provider-neutral defaults.
* [`chart/values-local.yaml`](chart/values-local.yaml): local development overrides.
* [`chart/values-aws.yaml`](chart/values-aws.yaml): AWS/EKS overlay that keeps Ingress as the public entry point.
* [`chart/values-aws-nlb.yaml`](chart/values-aws-nlb.yaml): optional AWS/EKS direct Network Load Balancer overlay.
* [`chart/values-production.yaml`](chart/values-production.yaml): production delta applied after `values-aws.yaml` by release deployments.
* `global.domain`: chart-wide public DNS suffix. When set, Ingress defaults derive `statuslist.<global.domain>` and `*.<global.domain>` from this single value. Rendered hostnames are normalized to lowercase.
* `postgres.persistence.storageClass`: leave as `""` to use the cluster default StorageClass; set explicitly in environment overlays when needed.
* `statuslist.image.variant`: selected image variant when no explicit `tag` or `digest` is set (`fscert`, `aws`, `gcp`, `azure`, or `vault`).
* `statuslist.image.digest`: takes precedence over `statuslist.image.tag` and renders `repository@digest`.

## Configure Your Secrets

The application Secret is always named `statuslist-secret` and holds the database password under `postgres-password`. The application Deployment and bundled PostgreSQL both consume that same Secret name.

There are two secret delivery modes, and the chart rejects enabling both at once.

Attach Workload Identity / IRSA role annotations through `serviceAccount.annotations`, for example on EKS:

```yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/status-list-server
```

For GCP or Azure Workload Identity, set the provider-specific annotation instead. Use `serviceAccount.labels` for any additional labels. Set `serviceAccount.automountServiceAccountToken=false` to harden the pod when it has no Kubernetes API access needs.

GKE Workload Identity for Cloud DNS:

```yaml
statuslist:
  image:
    tag: "1.2.0-gcp"
  env:
    APP_SERVER__CERT__DNS__PROVIDER: "gcloud"
    APP_SERVER__CERT__DNS__GCLOUD__AUTH_MODE: "ambient"
    APP_SERVER__CERT__DNS__GCLOUD__PROJECT_ID: "dns-project-id"
serviceAccount:
  create: true
  annotations:
    iam.gke.io/gcp-service-account: status-list-server@dns-project-id.iam.gserviceaccount.com
```

* `serviceAccount.create`: render a ServiceAccount (default `true`). When `false`, the Deployment uses the `default` service account.
* `serviceAccount.name`: override the ServiceAccount name (default: the chart fullname).
* `serviceAccount.automountServiceAccountToken`: default `true`; harden to `false` if the API token is not needed.

### Pod labels and Azure Workload Identity

Azure Workload Identity requires the pod label `azure.workload.identity/use: "true"` in addition to the ServiceAccount annotation. Add it (and any other pod labels) via `statuslist.podLabels`:

```yaml
statuslist:
  image:
    tag: "1.2.0-azure"
  podLabels:
    azure.workload.identity/use: "true"
  env:
    APP_SERVER__CERT__DNS__PROVIDER: "azure"
    APP_SERVER__CERT__DNS__AZURE__AUTH_MODE: "ambient"
    APP_SERVER__CERT__DNS__AZURE__SUBSCRIPTION_ID: "subscription-id"
    APP_SERVER__CERT__DNS__AZURE__RESOURCE_GROUP: "dns-resource-group"
serviceAccount:
  create: true
  annotations:
    azure.workload.identity/client-id: "00000000-0000-0000-0000-000000000000"
```

The ServiceAccount annotation alone is not sufficient for Azure; both the annotation and this pod label must be present.

## AWS Configuration and Static Credentials vs. Workload Identity

The default secret/credential provisioning path is **External Secrets Operator (ESO)**. By default the application mounts the ESO-provisioned `aws-credentials-secret` into the pod; Workload Identity is opt-in.

```yaml
statuslist:
  aws:
    mountCredentials: true # default: mount the ESO-provisioned aws-credentials-secret under /home/nobody/.aws
    region: "" # plain, non-secret; renders APP_AWS__REGION
    credentialsSecret:
      remoteKey: "statuslist-aws-credentials" # SecretStore key holding both AWS shared files
      credentialsProperty: "CREDENTIALS" # property in remoteKey with the credentials file
      configProperty: "CONFIG" # property in remoteKey with the config file
```

`statuslist.aws.region` is a plain (non-secret) value; `APP_AWS__REGION` is rendered whenever an effective region is set, independent of `secretStore.provider` and `mountCredentials`.

**Workload Identity is opt-in:** to switch to ambient Workload Identity / IRSA, set `statuslist.aws.mountCredentials=false` (no credentials mounted) and attach the cloud role annotation via `serviceAccount.annotations` (e.g. `eks.amazonaws.com/role-arn` for EKS IRSA, or the GCP / Azure WI annotations described above). The application then authenticates using the ambient credentials provided by that role instead of mounted files.

**Upgrade compatibility:** The effective `APP_AWS__REGION` resolves as `statuslist.aws.region`, falling back to the legacy `secretStore.aws.region` and then `eu-central-1`. Installations that previously set only `secretStore.aws.region` keep that region for the application across upgrade.

When `statuslist.aws.mountCredentials=true` (the default) **and** `externalSecret.enabled=true` (the default ESO path), the chart itself renders a second `ExternalSecret` that provisions `aws-credentials-secret` — the exact Secret the Deployment's credential volume references. It synchronizes two keys into that Secret:

* `credentials` ← `remoteKey`/`credentialsProperty` (the AWS shared credentials file, INI format, e.g. `[default]\naws_access_key_id=...\naws_secret_access_key=...`)
* `config` ← `remoteKey`/`configProperty` (the AWS shared config file)

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

External Secret Operator's `SecretStore` is provider-neutral via `secretStore.provider` (`aws` | `vault` | `gcp` | `azure` | `raw`). The shipped default is `aws`. A `SecretStore` is rendered **only** when `externalSecret.enabled=true` **and** `secretStore.enabled=true` — in the no-ESO fallback mode it is never emitted, so a cluster without ESO CRDs accepts the release.

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

* **aws** (`SecretsManager` or `ParameterStore`): `service` and `region`. `region` falls back to the effective app region when empty.
* **vault** (Vault / OpenBao-compatible): `server`, `path`, and an optional `auth` block.
* **gcp**: `projectID` plus an optional `auth` block (use Workload Identity for ambient auth).
* **azure**: `tenantId`, `vaultUrl`, and an `authType` validated as an enum per the ESO `AzureKVProvider` CRD — `ServicePrincipal | ManagedIdentity | WorkloadIdentity` (there is **no** `ClientSecret` authType). For Workload Identity use `authType: WorkloadIdentity` and bind `serviceAccountRef` to **External Secrets Operator's own identity** (least privilege) — **not** the application ServiceAccount. Managed-identity selection uses `identityId`; ServicePrincipal client credentials go under the `authSecretRef` block. `environmentType` is optional.
* **raw**: pass the concrete provider body through `secretStore.raw`, **rendered directly under `spec.provider`** for unsupported ESO providers without editing the chart. `secretStore.raw` holds only the provider body (no extra top-level `provider` key); an empty `raw: {}` is **rejected** so this path never silently emits a weakened SecretStore.

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

**Fallback Secret (default).** Without ESO, the chart renders a plain Kubernetes Secret inline:

```yaml
externalSecret:
  enabled: false
statuslist:
  fallbackSecret:
    enabled: true
    stringData:
      postgres-password: ""
```

The default chart uses this mode, so a plain `helm install` creates `statuslist-secret`. Leave `postgres-password` empty to have Helm generate a random password; on upgrades, Helm reuses the existing cluster Secret when it can read it. Set a concrete value only for local or disposable environments.

GitOps caveat: tools such as Argo CD and Flux render charts with `helm template`, where Helm's live `lookup` function cannot read the existing Secret. If `postgres-password` is left empty, each render generates a new password while PostgreSQL may keep the old password in its PVC. GitOps deployments should set an explicit fallback password from their secret-management flow or use ESO mode instead. The fallback Secret is annotated with `helm.sh/resource-policy: keep` so Helm does not delete it on uninstall.

**External Secrets Operator.** ESO syncs `statuslist-secret` from a configured `SecretStore` or pre-existing `ClusterSecretStore`. Enable ESO mode explicitly:

```yaml
externalSecret:
  enabled: true
secretStore:
  enabled: true
  provider: aws # aws | vault | gcp | azure | raw
statuslist:
  fallbackSecret:
    enabled: false
```

Provider selection is fail-closed through `values.schema.json` and render-time checks. Unsupported providers, empty `raw: {}`, ESO without a SecretStore, and custom `externalSecret.spec.target.name` values fail before Kubernetes receives manifests.

Common non-secret values under `statuslist.env` are the split database fields (`APP_DATABASE__HOST`, `APP_DATABASE__PORT`, `APP_DATABASE__USERNAME`, `APP_DATABASE__NAME`) and server values (`APP_SERVER__HOST`, `APP_SERVER__PORT`, `APP_SERVER__DOMAIN`). Do not set `APP_DATABASE__PASSWORD` in Helm values; the chart wires the password from the Secret as `APP_DATABASE__PASSWORD_FILE`.

## Use Workload Identity Instead of Mounted Credentials

If your cluster uses Workload Identity (EKS IRSA, GCP Workload Identity, or Azure Workload Identity), let the pod authenticate with ambient short-lived credentials instead of mounted credential files.

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/status-list-server
statuslist:
  aws:
    mountCredentials: false
```

For Azure Workload Identity, also add the pod label `azure.workload.identity/use: "true"` via `statuslist.podLabels`.

When `statuslist.aws.mountCredentials=true` and `externalSecret.enabled=true`, the chart renders a second `ExternalSecret` for `aws-credentials-secret`, the Secret mounted at `/home/nobody/.aws`.

## AWS Ingress and Direct NLB Exposure

The general AWS overlay selects the AWS image, AWS Secrets Manager/Route53 settings, ESO mode, and keeps `statuslist.service.type=ClusterIP` so Ingress remains the only public HTTP entry point:

```bash
helm install statuslist ./chart --namespace statuslist -f chart/values-aws.yaml
```

Use the direct NLB overlay only when the Service itself should be public. It disables the inherited Ingress to avoid exposing the app through a second plaintext path:

```bash
helm install statuslist ./chart --namespace statuslist \
  -f chart/values-aws.yaml \
  -f chart/values-aws-nlb.yaml
```

## Configure Signing Credentials

Before the server reports ready it needs its token-signing key and issuer certificate. For a self-contained deployment with no cloud dependency, use the default `-fscert` image with file-based signing material stored in a Kubernetes Secret:

```bash
openssl genpkey -algorithm ED25519 -out signing-key.pem
openssl req -new -x509 -key signing-key.pem -out issuer-cert.pem -days 365 \
  -subj "/CN=statuslist.example.com"

kubectl -n statuslist create secret generic signing-credentials \
  --from-file=certificate=issuer-cert.pem \
  --from-file=signing-key=signing-key.pem
```

```yaml
statuslist:
  image:
    tag: "1.2.0-fscert"
  secretMounts:
    - name: signing-keys
      secretName: signing-credentials
      mountPath: /etc/status-list-signing
      items:
        - key: certificate
          path: certificate.pem
        - key: signing-key
          path: signing-key.pem
      fileEnv:
        APP_SERVER__CERT__STORE__CERTIFICATE_PATH: certificate.pem
        APP_SERVER__CERT__STORE__SIGNING_KEY_PATH: signing-key.pem
  env:
    APP_SERVER__DOMAIN: "statuslist.example.com"
```

With ACME or a cloud secret backend, configure `APP_SERVER__DOMAIN`, the DNS provider, and the backend credentials instead.

## Deploy With Helm

Render and validate your values first so schema errors surface before anything touches the cluster:

```bash
helm template statuslist helm/chart --namespace statuslist --values my-values.yaml
```

Then deploy:

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist --create-namespace \
  --values my-values.yaml \
  --wait --timeout 10m
```

The chart bundles PostgreSQL and an OpenTelemetry collector. To point at an external database, disable the bundled PostgreSQL subchart and set the split `APP_DATABASE__*` fields under `statuslist.env`.

## Verify the Deployment

```bash
kubectl get pods -n statuslist
kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist --tail=100

curl -s https://<your-host>/health/live
curl -s https://<your-host>/health/ready
```

`/health/ready` reflects dependency health (database reachable, certificate material loadable) and is the readiness gate for a release.

For local development with a local cluster, use [`chart/values-local.yaml`](chart/values-local.yaml) and follow the same `helm upgrade --install` flow.

## Further Reading

* [`chart/values.yaml`](chart/values.yaml): the source of truth for every Helm value.
* [Deployment runbook](../docs/deployment-runbook.md): how to deploy and how CI/CD deploys to production.
* [Troubleshooting reference](../docs/troubleshooting.md): error-indexed fixes for startup, secrets, Kubernetes/ESO, and Helm/upgrade issues.
* [Container supply chain](../docs/supply-chain.md): image scanning, SBOM, and SLSA.
* [Project README](../README.md): overview and local-development quick start.
