# 03 — Helm Installation

This guide walks through deploying the **Status List Server** chart (`helm/chart`) to
six common environments. Each section is self-contained and task-oriented.

Before any install, satisfy the prerequisites in
[01-prerequisites.md](01-prerequisites.md) (ESO where required, registry access) and
pick your image in [02-choosing-your-image.md](02-choosing-your-image.md).

## 0. The three secret-delivery modes (decide first)

The chart supports exactly two mutually-exclusive secret-delivery paths for the
application Secret (`statuslist-secret`):

| Path                | How the DB password & app secrets arrive                                    | Chart switches                                                           |
| ------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| **ESO (default)**   | External Secrets Operator syncs from a `SecretStore` -> `statuslist-secret` | `externalSecret.enabled=true`, `secretStore.enabled=true`                |
| **Fallback Secret** | A plain Kubernetes Secret rendered inline (`stringData`)                    | `externalSecret.enabled=false`, `statuslist.fallbackSecret.enabled=true` |

The chart **fails at render time** if both are enabled (`externalSecret.enabled` and
`statuslist.fallbackSecret.enabled` cannot both be `true`). ESO also requires its
`SecretStore` (`externalSecret.enabled=true` requires `secretStore.enabled=true`).

```bash
# Render-and-validate before installing (catches template errors without touching the cluster)
helm template statuslist helm/chart \
  --namespace statuslist \
  --values my-values.yaml > /tmp/rendered.yaml
```

> [!TIP]
> Always `helm template` (or `helm lint`) first. The chart performs many
> fail-fast validations — conflicting secret modes, invalid `image.digest`,
> `APP_DATABASE__URL` in env, missing `APP_DATABASE__PORT`, and more — that surface here
> rather than as a long `helm upgrade --atomic --wait` timeout.

## 1. Common values

The examples below override this common base where applicable:

```yaml
# values.yaml
statuslist:
  replicaCount: 2
  image:
    repository: ghcr.io/adorsys/status-list-server
    tag: "0.6.0-aws" # choose variant per 02-choosing-your-image.md
  ingress:
    enabled: true
    hosts:
      - statuslist.example.com
    tls:
      hosts:
        - statuslist.example.com
      secretName: statuslist-tls
  env:
    APP_ENV: "production"
    APP_SERVER__HOST: "0.0.0.0"
    APP_SERVER__PORT: "8000"
    APP_SERVER__DOMAIN: "statuslist.example.com"
    APP_DATABASE__PORT: "5432"
postgres:
  enabled: true
  auth:
    password: "" # leave empty; password comes from the secret path below
```

The single app Secret name is **always `statuslist-secret`** — the Deployment reads
`postgres-password` from it, and `postgres.auth.existingSecret` points at it. Do not try
to change that name; the chart rejects it.

## 2. AWS EKS with Secrets Manager & IRSA

Uses the `-aws` variant, ESO-backed SecretStore (AWS Secrets Manager), and IRSA for the
pod's cloud role. For the ESO-vs-IRSA trade-offs, read
[`docs/secrets-risk-eso-vs-workload-identity.md`](../secrets-risk-eso-vs-workload-identity.md).

**1. Create the IRSA role** (policy scoped to the Secrets Manager keys and Route53 zone
the server uses):

```bash
# Cluster OIDC provider must be enabled on the EKS cluster first.
eksctl create iamserviceaccount \
  --cluster <cluster-name> \
  --namespace statuslist \
  --name statuslist \
  --role-name statuslist-role \
  --attach-policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore \
  --approve
```

Prefer a least-privilege custom policy over broad managed policies. The `-aws` variant
needs at least `secretsmanager:GetSecretValue` on the specific secrets and
`route53:ChangeResourceRecordSets` on the hosted zone if ACME DNS-01 is used.

**2. Store the DB password secret** and any app secrets in Secrets Manager:

```bash
aws secretsmanager create-secret --name statuslist-secret \
  --secret-string '{"POSTGRES_PASSWORD":"<db-pass>"}'
```

**3. Point the chart at IRSA and the SecretStore:**

```yaml
# values-eks.yaml
statuslist:
  image:
    repository: ghcr.io/adorsys/status-list-server
    tag: "0.6.0-aws"
  aws:
    mountCredentials: false # IRSA ambient credentials, no mounted files
    region: eu-central-1
serviceAccount:
  create: true
  name: statuslist
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<acct>:role/statuslist-role
externalSecret:
  enabled: true
secretStore:
  enabled: true
  provider: aws
  aws:
    service: SecretsManager
    region: eu-central-1
```

**4. Install:**

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist --create-namespace \
  --values values-eks.yaml \
  --wait --timeout 10m
```

> [!NOTE]
> When you enable ESO with `mountCredentials=true` (the chart default for mounted
> credentials), the chart also provisions a second ExternalSecret
> (`statuslist-external-secret-aws-credentials`) that mounts the AWS shared credential
> files into `/home/nobody/.aws`. With pure IRSA (above) set `mountCredentials=false`, so
> no `aws-credentials-secret` is required.

## 3. GCP GKE with Secret Manager & Workload Identity

Uses the `-gcp` variant, ESO SecretStore backed by GCP Secret Manager, and Workload
Identity.

**1. Create the GCP Service Account** with Secret Manager accessor roles:

```bash
gcloud iam service-accounts create statuslist-sa \
  --display-name="Status List Server"

gcloud projects add-iam-policy-binding <project> \
  --member="serviceAccount:statuslist-sa@<project>.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

**2. Enable Workload Identity** on the namespace and bind the Kubernetes SA:

```bash
kubectl create namespace statuslist
kubectl annotate namespace statuslist \
  iam.gke.io/gcp-service-account=statuslist-sa@<project>.iam.gserviceaccount.com
kubectl create serviceaccount statuslist -n statuslist
```

**3. Store the secrets** in GCP Secret Manager:

```bash
printf '<db-pass>' | gcloud secrets versions add statuslist-secret --data-file=-
```

**4. Chart values:**

```yaml
# values-gke.yaml
statuslist:
  image:
    repository: ghcr.io/adorsys/status-list-server
    tag: "0.6.0-gcp"
serviceAccount:
  create: false # reuse the SA created above
  name: statuslist
  annotations:
    iam.gke.io/gcp-service-account: statuslist-sa@<project>.iam.gserviceaccount.com
externalSecret:
  enabled: true
secretStore:
  enabled: true
  provider: gcp
  gcp:
    projectID: <project>
```

**5. Install:**

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist \
  --values values-gke.yaml \
  --wait --timeout 10m
```

The `-gcp` image uses Application Default Credentials (ADC); no static key JSON is needed
inside the pod when Workload Identity is active.

## 4. Azure AKS with Key Vault & Azure AD Workload Identity

Uses the `-azure` variant, ESO SecretStore backed by Azure Key Vault, and Azure AD
Workload Identity.

**1. Create the app identity** and grant Key Vault access:

```bash
# Managed identity the app will use
az identity create --name statuslist-identity --resource-group <rg>
IDENTITY_CLIENT_ID=$(az identity show -n statuslist-identity -g <rg> \
  --query clientId -o tsv)

# RBAC data-plane access to the Key Vault
az role assignment create \
  --assignee "$IDENTITY_CLIENT_ID" \
  --role "Key Vault Secrets User" \
  --scope <key-vault-resource-id>
```

**2. Create the ServiceAccount** (no chart SA creation; we manage it):

```yaml
# serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: statuslist-app-sa
  namespace: statuslist
  annotations:
    azure.workload.identity/client-id: <IDENTITY_CLIENT_ID>
    azure.workload.identity/tenant-id: <TENANT_ID>
---
# Federated credential binding the identity to the SA
# (create via az identity federated-credential create, or AKS Workload Identity setup)
```

```bash
kubectl create namespace statuslist
kubectl apply -f serviceaccount.yaml
```

**3. Store secrets** in Key Vault:

```bash
az keyvault secret set --vault-name <vault> --name statuslist-secret \
  --value '{"POSTGRES_PASSWORD":"<db-pass>"}'
```

**4. Chart values** — attach the workload-identity pod label and disable chart SA
creation:

```yaml
# values-aks.yaml
statuslist:
  image:
    repository: ghcr.io/adorsys/status-list-server
    tag: "0.6.0-azure"
  podLabels:
    azure.workload.identity/use: "true"
serviceAccount:
  create: false
  name: statuslist-app-sa
externalSecret:
  enabled: true
secretStore:
  enabled: true
  provider: azure
  azure:
    vaultUrl: https://<vault>.vault.azure.net/
    authType: WorkloadIdentity
    serviceAccountRef:
      name: eso-controller-sa # ESO controller's SA bound to the ESO identity
```

**5. Install:**

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist \
  --values values-aks.yaml \
  --wait --timeout 10m
```

> [!NOTE]
> The `secretStore.azure.serviceAccountRef` should reference the **External Secrets
> Operator controller's** ServiceAccount (least privilege), **not** the application SA.
> The application itself authenticates to Key Vault via its own Workload Identity identity
> (`podLabels["azure.workload.identity/use"]="true"`), which the `-azure` image resolves
> from `AZURE_FEDERATED_TOKEN_FILE` / `AZURE_CLIENT_ID` / `AZURE_TENANT_ID`.

## 5. HashiCorp Vault / OpenBao via ESO (`SecretStore`)

Uses a `SecretStore` of kind `SecretStore` (namespaced) or `ClusterSecretStore`
(cluster-scoped) with the `vault` provider. The application can itself use the `-vault`
image to read its signing material from Vault, or a different variant while ESO still
delivers secrets from Vault — these are independent (`secretStore.provider` vs image).

**1. Ready a Vault KV v2 engine** with the app secrets (see
[docs/secrets-backends.md](../secrets-backends.md) for IAM policy examples):

```bash
vault secrets enable -path=secret kv-v2
vault kv put secret/statuslist-secret POSTGRES_PASSWORD=<db-pass>
```

**2. Chart values:**

```yaml
# values-vault.yaml
statuslist:
  image:
    repository: ghcr.io/adorsys/status-list-server
    tag: "0.6.0-vault"
externalSecret:
  enabled: true
secretStore:
  enabled: true
  provider: vault
  vault:
    server: https://vault.example.com:8200
    path: secret
    auth:
      kubernetes:
        mountPath: kubernetes
        role: statuslist-role
        serviceAccountRef:
          name: external-secrets # ESO controller SA with a Vault role
```

**3. Install:**

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist \
  --values values-vault.yaml \
  --wait --timeout 10m
```

### Using a ClusterSecretStore instead

If you prefer a cluster-scoped store (requires cluster-admin to create, but reusable
across namespaces), create it once:

```yaml
# clustersecretstore.yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: vault-cluster
spec:
  provider:
    vault:
      server: https://vault.example.com:8200
      path: secret
      auth:
        kubernetes:
          mountPath: kubernetes
          role: statuslist-role
          serviceAccountRef:
            name: external-secrets
            namespace: external-secrets
```

```bash
kubectl apply -f clustersecretstore.yaml
```

Then in the chart values:

```yaml
externalSecret:
  spec:
    secretStoreRef:
      name: vault-cluster
      kind: ClusterSecretStore
```

## 6. Filesystem-mounted token signing credentials (`-fscert`)

Use the `-fscert` image when the token **signing key and issuer certificate** are
delivered as files (mounted secret volumes, CSI drivers, or sealed-secret injection).
Here we show the simplest path with the **fallback Secret** mode (no ESO), which is also
what you want for a self-contained deployment.

> [!NOTE]
> Two distinct things can be "filesystem-mounted": (a) the **token-signing credential
> files** the application reads directly (this section), and (b) the ESO-mounted AWS
> credential files that the app loads as cloud credentials (different volume). This
> section is about (a). See [05-token-signing-credentials.md](05-token-signing-credentials.md).

**1. Create the signing key and certificate** (PKCS#8 PEM):

```bash
openssl genpkey -algorithm ED25519 -out signing-key.pem
openssl req -new -x509 -key signing-key.pem -out issuer-cert.pem -days 365 \
  -subj "/CN=statuslist.example.com"
```

**2. Put them in a Kubernetes Secret** along with the DB password:

```bash
kubectl -n statuslist create secret generic statuslist-secret \
  --from-file=postgres-password=<(echo -n '<db-pass>')
kubectl -n statuslist create secret generic signing-credentials \
  --from-file=certificate=issuer-cert.pem \
  --from-file=signing-key=signing-key.pem
```

**3. Mount them into the pod** and enable `store` provisioning via extra volume/volumeMount
values. Because the chart's built-in volumes are for AWS credentials and tmp, add the
signing material mount with a custom values overlay that appends to the container:

```yaml
# values-fscert.yaml
statuslist:
  image:
    repository: ghcr.io/adorsys/status-list-server
    tag: "0.6.0-fscert"
  env:
    APP_SERVER__CERT__PROVISIONING_STRATEGY: "store"
    APP_SERVER__CERT__STORE__CERTIFICATE_PATH: "/etc/status-list-signing/certificate.pem"
    APP_SERVER__CERT__STORE__SIGNING_KEY_PATH: "/etc/status-list-signing/signing-key.pem"
  # see section 6a below for adding the volume + mount
externalSecret:
  enabled: false
statuslist:
  fallbackSecret:
    enabled: true
    stringData:
      postgres-password: "<db-pass>"
```

**6a. Adding the signing volume.** The chart templates a fixed set of volumes, so add the
signing-key volume by mounting a Secret through an `extraVolumes`/`extraVolumeMounts`
extension (provide this via a small Helm overlay that the chart supports — check
`helm/chart/templates` for the exact key name; if not available, use a `values` that sets
an initContainer to stage the files or extend via Kustomize post-render):

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist \
  --values values-fscert.yaml \
  --post-renderer ./postrender-signing-volumes.sh \
  --wait --timeout 10m
```

If your chart version exposes `statuslist.extraVolumes` / `statuslist.extraVolumeMounts`,
use those instead — see the chart's `values.schema.json` for the supported extension keys.

> [!WARNING]
> Filesystem rotation is **not** an inotify watch. The app re-reads the key file on each
> signing-key read (or per the signing-key cache TTL). Overwriting the file in place (an
> atomic rename over the same path) is picked up on the next read with no restart. See
> [06-secret-rotation.md](06-secret-rotation.md).

## 7. Local testing with `values-local.yaml`

The repository ships `helm/chart/values-local.yaml` for a quick local cluster run against
an in-chart PostgreSQL, with the OpenTelemetry collector and external secrets disabled:

```bash
# kind / k3s / minikube cluster already running
helm upgrade --install statuslist helm/chart \
  --namespace statuslist --create-namespace \
  --values helm/chart/values-local.yaml \
  --wait --timeout 5m
```

In local mode:

- `externalSecret.enabled=false`, `secretStore.enabled=false`, and
  `statuslist.fallbackSecret` provides the Postgres password — so no ESO is required.
- The collector is disabled (`opentelemetry-collector.enabled=false`), so
  `APP_TELEMETRY__ENABLED` defaults to `false`.
- Ingress is disabled; the server is exposed via `NodePort: 32081`.
- The bundled Postgres runs without persistent storage.

Verify locally:

```bash
kubectl port-forward svc/statuslist-status-list-server 8081:8081 -n statuslist &
curl -s http://localhost:8081/health/live
curl -s http://localhost:8081/health/ready
```

## 8. Post-install verification

```bash
helm status statuslist -n statuslist
kubectl get pods -n statuslist
kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist

# ExternalSecret sync status (ESO mode)
kubectl get externalsecret -n statuslist

# Application logs
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist --tail=100
```

Smoke-test the API:

```bash
curl -s https://<your-host>/health/live
curl -s https://<your-host>/health/ready
```

## Related

- [04-configuration-reference.md](04-configuration-reference.md) — every env var.
- [05-token-signing-credentials.md](05-token-signing-credentials.md) — signing key vs TLS.
- [06-secret-rotation.md](06-secret-rotation.md) — rotating what you just deployed.
- [07-scaling-and-availability.md](07-scaling-and-availability.md) — scale out safely.
- [`docs/secrets-risk-eso-vs-workload-identity.md`](../secrets-risk-eso-vs-workload-identity.md) — risk trade-offs.
