# Status List Server — Helm Chart Deployment

This guide walks an operator through deploying the **Status List Server** on Kubernetes with
the Helm chart in this directory ([`chart/`](chart/)). It bundles the application Deployment
plus PostgreSQL and an OpenTelemetry collector. No understanding of the server's internals is
required.

## Prerequisites

- A **Kubernetes cluster** (EKS, GKE, AKS, or any standard `apps/v1` cluster), version
  **≥ 1.24**.
- **Helm 4** — [official installation](https://helm.sh/docs/intro/install/).
- **`kubectl`** — [official installation](https://kubernetes.io/docs/tasks/tools/).
- An **ingress controller** (e.g. [nginx-ingress](https://kubernetes.github.io/ingress-nginx/deploy/))
  and [cert-manager](https://cert-manager.io/docs/installation/) if you expose the server over
  HTTPS — see `statuslist.ingress` in [`chart/values.yaml`](chart/values.yaml).
- **External Secrets Operator (ESO)** — [official installation](https://external-secrets.io/latest/)
  — only when you use the default secret-delivery path (`externalSecret.enabled=true`):

  ```bash
  helm repo add external-secrets https://charts.external-secrets.io
  helm repo update
  helm install external-secrets external-secrets/external-secrets \
    --namespace external-secrets --create-namespace --set installCRDs=true
  ```

  For a self-contained deploy with no ESO, use the **fallback Secret** mode described under
  “Configure your secrets” instead.

- **Registry access** to the public `ghcr.io/adorsys/status-list-server` images.
- **OpenSSL** (for the [signing-credentials](#configure-signing-credentials) example) —
  [download](https://www.openssl.org/).

## Choose your image variant

The server is published to `ghcr.io/adorsys/status-list-server` as several **image variants**,
each built for a different way of storing the **token-signing key and issuer certificate** (the
server's signing identity). Pick the one matching your environment:

| Tag suffix | Signing-credential backend                   | Best when                                                         |
| ---------- | -------------------------------------------- | ----------------------------------------------------------------- |
| `-aws`     | AWS Secrets Manager + Route53 DNS-01         | You run on EKS / keep secrets in AWS                              |
| `-gcp`     | GCP Secret Manager + Google Cloud DNS        | You run on GKE / keep secrets in GCP                              |
| `-azure`   | Azure Key Vault + Azure DNS                  | You run on AKS / keep secrets in Azure                            |
| `-vault`   | HashiCorp Vault / OpenBao KV v2              | You operate your own Vault / want cloud-agnostic                  |
| `-fscert`  | Filesystem-mounted signing key + certificate | You deliver the signing key and cert as files; smallest footprint |

> [!IMPORTANT]
> No unsuffixed image (`latest`, `1.2.0`) is published — you **must** reference a variant
> explicitly (e.g. `1.2.0-aws`). The chart's empty-tag default resolves to the `-aws` variant.

Set the image in your values:

```yaml
statuslist:
  image:
    repository: ghcr.io/adorsys/status-list-server
    tag: "1.2.0-aws" # substitute your variant
  ingress:
    enabled: true
    hosts:
      - statuslist.example.com
    tls:
      hosts:
        - statuslist.example.com
      secretName: statuslist-tls
```

For production, pin the exact artifact by **digest** rather than tag. A digest that is not
`sha256:` followed by 64 hex characters is rejected by the chart at render time.

## Configure your secrets

The chart supports two mutually-exclusive ways to deliver the application Secret (always named
**`statuslist-secret`**, which holds the database password):

- **External Secrets Operator (default)** — ESO syncs `statuslist-secret` from a `SecretStore`
  (AWS, GCP, Azure, Vault, or raw). Requires ESO plus `secretStore.enabled=true`.
- **Fallback Secret** — the chart renders a plain Kubernetes `Secret` inline. Use this for a
  self-contained deploy with no ESO:

  ```yaml
  externalSecret:
    enabled: false
  statuslist:
    fallbackSecret:
      enabled: true
      stringData:
        postgres-password: "change-me"
  ```

The two modes **cannot** both be enabled — the chart fails at render time if you do.

Additional values you will commonly set under `statuslist.env` (all `APP_*`):
`APP_DATABASE__HOST/PORT/USERNAME/NAME` (never put the password there — the chart wires it from
the Secret) and `APP_SERVER__HOST/PORT/DOMAIN`.

Working value files ship with the chart: [`chart/values.yaml`](chart/values.yaml) (defaults),
[`chart/values-local.yaml`](chart/values-local.yaml) (local cluster),
[`chart/values-external-secrets.yaml`](chart/values-external-secrets.yaml), and
[`chart/values-production.yaml`](chart/values-production.yaml).

## Configure signing credentials

Before the server can be ready it needs its **token-signing key and issuer certificate** (its
signing identity). The chart defaults to ACME (`APP_SERVER__CERT__PROVISIONING_STRATEGY`),
which requires a DNS provider like Route53 and a publicly reachable domain. For a
**self-contained deploy with no cloud dependency**, use the `-fscert` image with store
provisioning of file-based signing material:

```bash
# Generate a signing key and issuer certificate (PKCS#8 PEM)
openssl genpkey -algorithm ED25519 -out signing-key.pem
openssl req -new -x509 -key signing-key.pem -out issuer-cert.pem -days 365 \
  -subj "/CN=statuslist.example.com"

# Store them in a Kubernetes Secret in the target namespace
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
    APP_SERVER__DOMAIN: "statuslist.example.com" # your public host; the default is project-specific
```

With ACME or a cloud secret backend, the signing material is provisioned by that backend and
`APP_SERVER__DOMAIN` plus the backend credentials must be configured instead — see the detailed
operator documentation linked under [Next steps](#next-steps).

## Deploy with Helm

Validate your values, then install. CRD-rendering and value schema errors surface here, not as
a failed upgrade:

```bash
# Render-and-validate (catches mistakes before touching the cluster)
helm template statuslist helm/chart --namespace statuslist --values my-values.yaml

# Deploy (create the namespace first time)
kubectl create namespace statuslist
helm upgrade --install statuslist helm/chart \
  --namespace statuslist --create-namespace \
  --values my-values.yaml \
  --wait --timeout 10m
```

The chart bundles PostgreSQL and an OpenTelemetry collector as dependencies. To point at an
**external database**, disable the bundled PostgreSQL subchart and set the split
`APP_DATABASE__*` env fields under `statuslist.env`.

## Verify the deployment

```bash
helm status statuslist -n statuslist
kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist
kubectl get pods -n statuslist
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist --tail=100

curl -s https://<your-host>/health/live
curl -s https://<your-host>/health/ready
```

`/health/ready` reflects dependency health (database reachable, certificate material loadable);
treat it as the release-readiness gate.

For local development without a cluster, use the bundled
[`chart/values-local.yaml`](chart/values-local.yaml) and follow the same `helm upgrade --install`
flow.

## Next steps

The detailed, topic-by-topic operator documentation has been moved to **Confluence** (covering
prerequisites, per-provider installs, the full environment-variable reference, token-signing
credentials, secret rotation, scaling, observability, upgrade/rollback, and an error-indexed
troubleshooting reference). Link to it from here once published.

In this repository you can consult the curated deep-dive pages for operational background:

- [`../docs/deployment-architecture.md`](../docs/deployment-architecture.md) — the full
  Kubernetes/Helm topology and architecture.
- [`../docs/deployment-runbook.md`](../docs/deployment-runbook.md) — the GitHub Actions
  release/deploy flow that injects the image and deploys to production.
- [`../docs/secrets-risk-eso-vs-workload-identity.md`](../docs/secrets-risk-eso-vs-workload-identity.md)
  — risk trade-offs between ESO-mounted credentials (chart default) and Workload Identity.
- [`chart/values.yaml`](chart/values.yaml) — the single source of truth for every Helm value.
- [`../docs/supply-chain.md`](../docs/supply-chain.md) — image scanning, SBOM, and SLSA.
- [`../README.md`](../README.md) — project overview and local-development quick start.
