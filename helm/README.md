# Status List Server — Helm Deployment

This guide shows you how to deploy the Status List Server on Kubernetes with the Helm chart in
this directory ([`chart/`](chart/)).

## Prerequisites

* A Kubernetes cluster (EKS, GKE, AKS, or any standard `apps/v1` cluster) running version 1.24
  or newer.
* [Helm](https://helm.sh/docs/intro/install/) and [`kubectl`](https://kubernetes.io/docs/tasks/tools/).
* An ingress controller and [cert-manager](https://cert-manager.io/docs/installation/) if you
  expose the server over HTTPS (see `statuslist.ingress` in [`chart/values.yaml`](chart/values.yaml)).
* Access to the public images at `ghcr.io/adorsys/status-list-server`.
* [External Secrets Operator (ESO)](https://external-secrets.io/latest/) if you use the default
  secret delivery described below.

## Choose your image variant

The server is published as several image variants, each built for a different way of storing the
token-signing key and issuer certificate that make up the server's signing identity. Pick the one
that matches your environment.

| Image suffix | Signing-credential backend             | Best for                             |
| ------------ | -------------------------------------- | ------------------------------------ |
| `-aws`       | AWS Secrets Manager + Route53 DNS-01   | Running on EKS / using AWS           |
| `-gcp`       | GCP Secret Manager + Google Cloud DNS  | Running on GKE / using GCP           |
| `-azure`     | Azure Key Vault + Azure DNS            | Running on AKS / using Azure         |
| `-vault`     | HashiCorp Vault / OpenBao KV v2        | Operating your own Vault             |
| `-fscert`    | File-based signing key and certificate | Delivering signing material as files |

No unsuffixed image (`latest`, `1.2.0`) is published, so you must reference a variant
explicitly, for example `1.2.0-aws`. The chart's empty-tag default resolves to the `-aws`
variant.

For production, pin the exact artifact by digest rather than tag. A digest is validated as
`sha256:` followed by 64 hex characters.

## Configure your secrets

The application secret (always named `statuslist-secret`) holds the database password. There are
two ways to deliver it, and you cannot enable both at once.

**External Secrets Operator (default).** ESO syncs `statuslist-secret` from a configured
`SecretStore` (AWS, GCP, Azure, Vault, or raw). This requires ESO and `secretStore.enabled=true`.

**Fallback Secret.** Without ESO, the chart renders a plain Kubernetes Secret inline:

```yaml
externalSecret:
  enabled: false
statuslist:
  fallbackSecret:
    enabled: true
    stringData:
      postgres-password: "change-me"
```

Common values under `statuslist.env` are the split database fields
(`APP_DATABASE__HOST/PORT/USERNAME/NAME`; the password is wired from the Secret, never set it
here) and `APP_SERVER__HOST/PORT/DOMAIN`.

## Use Workload Identity instead of mounted credentials

The default ESO path mounts the application's cloud credentials as files. If your cluster uses
Workload Identity (EKS IRSA, GCP Workload Identity, or Azure Workload Identity), you can opt out
of mounted credentials and let the pod authenticate with a short-lived ambient token instead.
This is a hardening step that keeps the live credential material out of Kubernetes Secrets.

Turn off mounted credentials and attach the cloud role to the chart ServiceAccount:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/status-list-server
statuslist:
  aws:
    mountCredentials: false    # do not mount credential files
```

For Azure Workload Identity, also add the pod label `azure.workload.identity/use: "true"` via
`statuslist.podLabels`. The ServiceAccount annotation alone is not enough on Azure.

## Configure signing credentials

Before the server reports ready it needs its token-signing key and issuer certificate. The chart
defaults to ACME provisioning, which needs a DNS provider such as Route53 and a publicly
reachable domain. For a self-contained deployment with no cloud dependency, use the `-fscert`
image with file-based signing material stored in a Kubernetes Secret:

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

With ACME or a cloud secret backend, the signing material is provisioned by that backend. In that
case configure `APP_SERVER__DOMAIN` and the backend credentials instead.

## Deploy with Helm

Render and validate your values first so schema errors surface before anything touches the
cluster:

```bash
helm template statuslist helm/chart --namespace statuslist --values my-values.yaml
```

Then deploy. `--create-namespace` creates the namespace on the first install, so there is no need
for a separate `kubectl create namespace`, and Helm waits until the rollout is ready:

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist --create-namespace \
  --values my-values.yaml \
  --wait --timeout 10m
```

The chart bundles PostgreSQL and an OpenTelemetry collector. To point at an external database,
disable the bundled PostgreSQL subchart and set the split `APP_DATABASE__*` fields under
`statuslist.env`.

## Verify the deployment

Check that the pods are running and the health endpoints respond:

```bash
kubectl get pods -n statuslist
kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist --tail=100

curl -s https://<your-host>/health/live
curl -s https://<your-host>/health/ready
```

`/health/ready` reflects dependency health (database reachable, certificate material loadable)
and is the readiness gate for a release.

For local development with a local cluster, use [`chart/values-local.yaml`](chart/values-local.yaml)
and follow the same `helm upgrade --install` flow.

## Further reading

* [`chart/values.yaml`](chart/values.yaml) — the source of truth for every Helm value.
* [Deployment runbook](../docs/deployment-runbook.md) — how to deploy and how CI/CD deploys to production.
* [Troubleshooting reference](../docs/troubleshooting.md) — error-indexed fixes for startup, secrets,
  Kubernetes/ESO, and Helm/upgrade issues.
* [Container supply chain](../docs/supply-chain.md) — image scanning, SBOM, and SLSA.
* [Project README](../README.md) — overview and local-development quick start.
