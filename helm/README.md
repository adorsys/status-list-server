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
    APP_SERVER__CERT__PROVISIONING_STRATEGY: "store"
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
