# 01 — Prerequisites

This guide is the "you need these before you start" checklist. It covers cluster
requirements, local tooling, the External Secrets Operator (ESO) install, and registry
access. Work through it top to bottom before [02-choosing-your-image.md](02-choosing-your-image.md).

## 1. Kubernetes cluster requirements

Supported anywhere you can run standard Kubernetes `apps/v1` Deployments, Services,
Ingresses, and HorizontalPodAutoscalers (`autoscaling/v2`). Verified targets include
EKS, GKE, AKS, and OpenShift-compatible clusters, plus single-node local clusters
(kind, k3s, minikube).

Version requirements:

- **Kubernetes ≥ 1.24** — the chart uses `apps/v1`, `policy/v1` (PodDisruptionBudget)
  and `autoscaling/v2` (HPA), all GA in this range.
- A working **ingress controller** (nginx-ingress is used in the chart defaults) if you
  enable `statuslist.ingress`.
- **cert-manager** (or your ingress's native TLS) for ingress TLS, **unless** you expose
  the server differently. The Status List Token signing identity is _separate_ from
  ingress TLS — see [05-token-signing-credentials.md](05-token-signing-credentials.md).

### Required Kubernetes objects the chart creates

The chart itself creates: `Deployment`, `Service`, `Ingress`, `ServiceAccount`,
(optionally) `HorizontalPodAutoscaler`, `PodDisruptionBudget`, `NetworkPolicy`, and —
when ESO is enabled — `SecretStore` and `ExternalSecret` CRs. The last two require the
ESO CRDs installed (below).

## 2. Local tooling

Install once on the operator workstation:

```bash
helm version --short          # ≥ 3.x recommended
kubectl version --client
```

Add the display-only "status-list" release local values to your working copy by cloning
this repository:

```bash
git clone https://github.com/adorsys/status-list-server.git
cd status-list-server
```

## 3. External Secrets Operator (ESO)

The chart's **default** secret-delivery path is ESO. Unless you explicitly choose the
fallback Secret mode (`statuslist.fallbackSecret.enabled=true`, covered in
[03-helm-installation.md](03-helm-installation.md)), you must install ESO first.

Install the ESO controller and its CRDs:

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --set installCRDs=true
```

Verify the controller is running:

```bash
kubectl -n external-secrets get pods
kubectl -n external-secrets get crd | grep external-secrets
```

You should see `SecretStore`, `ClusterSecretStore`, `ExternalSecret`, and companion CRDs.

> [!NOTE]
> The chart renders a namespaced **`SecretStore`** by default (kind `SecretStore`
> referenced from `externalSecret.spec.secretStoreRef.kind`). To use a
> **`ClusterSecretStore`** instead, set `externalSecret.spec.secretStoreRef.kind:
ClusterSecretStore` and point `name` at a cluster-scoped store you create separately —
> the chart then **skips rendering a namespaced `SecretStore`** (set
> `secretStore.enabled: false`), so it must exist cluster-wide first.
> Only operators with cluster-admin can create `ClusterSecretStore` resources; a
> namespaced `SecretStore` requires no cluster-admin. ESO CRs now use apiVersion
> `external-secrets.io/v1`.

### Single app-secret contract

ESO synchronizes exactly one application Secret, always named **`statuslist-secret`**.
This name is shared by the Deployment (to read `postgres-password`), PostgreSQL
(`postgres.auth.existingSecret`), and the fallback Secret; the chart validates that
`externalSecret.spec.target.name` equals it and fails at render time otherwise. Plan
your cloud secret keys so this one target Secret can be assembled.

## 4. Registry access (GHCR)

Images are published to GitHub Container Registry under
`ghcr.io/adorsys/status-list-server`. Choose the image variant that matches your
cryptographic material backend — see [02-choosing-your-image.md](02-choosing-your-image.md).

### Public images (no pull secret)

The `ghcr.io/adorsys/status-list-server:*` images are public. If your cluster can reach
GHCR over the internet and does not require a pull secret, set:

```yaml
statuslist:
  image:
    repository: ghcr.io/adorsys/status-list-server
    tag: <version> # e.g. 0.6.0; empty falls back to chart appVersion
```

### Private/mirrored images (pull secret)

If you mirror to a private registry or need a pull secret, create it and reference it on
the ServiceAccount:

```yaml
# in your values.yaml
statuslist:
  image:
    repository: <your-registry>/status-list-server
    tag: <version>
```

```bash
kubectl -n statuslist create secret docker-registry regcred \
  --docker-server=ghcr.io \
  --docker-username=<user> \
  --docker-password=<token>
```

Then attach it:

```yaml
serviceAccount:
  create: true
  name: statuslist
imagePullSecrets:
  - name: regcred
```

> [!NOTE]
> If you set a separate `imagePullSecrets` list in your values, merge it with any
> existing list the chart already references. The chart's ServiceAccount template allows
> `serviceAccount.imagePullSecrets`.

### Pinning the exact image (recommended)

Always deploy is by **content digest** for production. It is the only immutable reference
(the tag can be overwritten). See [03-helm-installation.md](03-helm-installation.md) for
the `--set` form and [09-upgrading.md](09-upgrading.md) for why `--reuse-values` with only
a changed tag is a foot-gun.

## 5. Cloud provider prerequisites

Depending on your chosen workload-identity path, you will need one of these sets ready
before an install (full commands and examples in [03-helm-installation.md](03-helm-installation.md)):

- **AWS EKS + IRSA**: an IAM role whose trust policy allows the Kubernetes ServiceAccount
  to assume it (`eks.amazonaws.com/role-arn`), with permissions to read Secrets Manager
  secrets (and, for the `-aws` image, to manage Route53 DNS records and Secrets Manager
  material for token signing).
- **GCP GKE + Workload Identity**: a GCP Service Account with Secret Manager access and a
  Kubernetes ServiceAccount annotated `iam.gke.io/gcp-service-account`.
- **Azure AKS + Workload Identity**: an Azure AD identity with Key Vault access, an
  annotated ServiceAccount (`azure.workload.identity/client-id`,
  `azure.workload.identity/tenant-id`), and `azure.workload.identity/use: "true"` pod label.
- **HashiCorp Vault / OpenBao**: the server URL, an auth method (AppRole or Kubernetes),
  a KV v2 mount, and an ACL policy covering the secret paths.

If you use the **ESO-mounted AWS credentials** path instead of IRSA, you need the AWS
credentials available in your configured SecretStore under the key referenced by
`statuslist.aws.credentialsSecret.remoteKey` (default `statuslist-aws-credentials`).

## 6. PostgreSQL (or MySQL/SQLite)

The chart bundles a PostgreSQL subchart (`postgres.enabled=true` by default) with
persistence. For production you can point it at an external database by disabling the
subchart and configuring `statuslist.env.APP_DATABASE__*`. Supported backends and the
split-database settings are documented in
[04-configuration-reference.md](04-configuration-reference.md). The default is
`postgres`; `mysql` and `sqlite` are alternative backends.

## Next step

Decide which **image variant** matches your signing-credential backend in
[02-choosing-your-image.md](02-choosing-your-image.md).
