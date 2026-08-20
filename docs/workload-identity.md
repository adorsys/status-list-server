# Workload Identity Deployment Guide

This guide covers deploying the Status List Server using cloud-provider Workload Identity and Kubernetes-native authentication patterns — eliminating static long-lived credentials.

## Table of Contents

1. [Overview](#overview)
2. [AWS EKS — IAM Roles for Service Accounts (IRSA)](#aws-eks--iam-roles-for-service-accounts-irsa)
3. [GKE — Workload Identity](#gke--workload-identity)
4. [AKS — Workload Identity Federation](#aks--workload-identity-federation)
5. [Vault Kubernetes Auth](#vault-kubernetes-auth)
6. [Checking Active Credentials](#checking-active-credentials)

---

## Overview

Workload Identity allows Kubernetes ServiceAccounts to authenticate as cloud IAM identities (AWS IAM roles, GCP service accounts, Azure managed identities) without static access keys.

| Static Credentials           | Workload Identity                         |
|------------------------------|------------------------------------------|
| Long-lived secrets that can leak | Short-lived tokens rotated automatically |
| Manual rotation required     | No rotation needed                        |
| Stored in GitHub Secrets     | No secrets to manage                      |
| Works from any context       | Only from the assigned pod                 |

The Helm chart supports Workload Identity via `serviceAccount.create` and `serviceAccount.annotations`:

```yaml
serviceAccount:
  create: true           # Render a ServiceAccount
  annotations: {}        # Cloud-provider role annotations
```

---

## AWS EKS — IAM Roles for Service Accounts (IRSA)

### Prerequisites

- EKS cluster with OIDC provider configured
- `aws` CLI with appropriate IAM permissions

### 1. Verify EKS OIDC Provider

```bash
# Get the OIDC issuer URL
aws eks describe-cluster --name my-cluster --query cluster.oidc.issuerUrl

# List OIDC providers
aws iam list-open-id-connect-providers
```

### 2. Create the IAM Role for IRSA

```bash
# Replace ACCOUNT_ID, CLUSTER_NAME, OIDC_PROVIDER, and NAMESPACE accordingly
aws iam create-role \
  --role-name statuslist-irsa \
  --assume-role-policy-document file://<(cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/OPENID_PROVIDER"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "OPENID_PROVIDER:sub": "system:serviceaccount:NAMESPACE:statuslist-sa"
        }
      }
    }
  ]
}
EOF
)
```

### 3. Attach Required Policies

The server now stores all cryptographic material (certificate chain, signing key, ACME account material) in a single backend. When compiled with `aws-secrets` (and without `vault`), that backend is AWS Secrets Manager, so the IRSA role needs Route53 (ACME DNS-01) and full Secrets Manager CRUD — S3 is no longer used at runtime:

```bash
# Inline policy for Route53 ACME DNS-01 + Secrets Manager (single crypto-material backend)
cat > /tmp/irsa-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets"],
      "Resource": "arn:aws:route53:::hostedzone/*"
    },
    {
      "Effect": "Allow",
      "Action": "route53:GetChange",
      "Resource": "arn:aws:route53:::change/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:DescribeSecret",
        "secretsmanager:CreateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:DeleteSecret"
      ],
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:statuslist/*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name statuslist-irsa \
  --policy-name statuslist-route53 \
  --policy-document file:///tmp/irsa-policy.json
```

> **Note:** If the server is compiled with the `vault` feature, cryptographic material is stored in Vault/OpenBao instead, and the pod may not need Secrets Manager permissions at all (Route53 for ACME remains unless you mount a static DNS credential).

### 4. Deploy with Helm

```bash
helm install statuslist ./chart \
  --namespace statuslist \
  -f chart/values.yaml \
  -f chart/values-aws-irsa.yaml
```

**Expected service account annotation:**

```yaml
serviceAccount:
  create: true
  name: statuslist-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/statuslist-irsa
```

---

## GKE — Workload Identity

### Prerequisites

- GKE cluster with Workload Identity enabled
- `gcloud` CLI configured

### 1. Create the GCP Service Account

```bash
gcloud iam service-accounts create statuslist-sa \
  --display-name="Status List Server" \
  --project=PROJECT_ID

SA_EMAIL=statuslist-sa@PROJECT_ID.iam.gserviceaccount.com

# Grant permissions for Secret Manager + Cloud DNS
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/secretmanager.secretAccessor"

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/dns.admin"
```

### 2. Bind the Kubernetes ServiceAccount to the GCP ServiceAccount

```bash
gcloud iam service-accounts add-iam-policy-binding $SA_EMAIL \
  --member="serviceAccount:PROJECT.svc.id.goog[statuslist/statuslist-sa]" \
  --role="roles/iam.workloadIdentityUser"
```

### 3. Deploy with Helm

```bash
helm install statuslist ./chart \
  --namespace statuslist \
  -f chart/values.yaml \
  -f chart/values-gke-wi.yaml
```

**Expected service account annotation:**

```yaml
serviceAccount:
  create: true
  name: statuslist-sa
  annotations:
    iam.gke.io/gcp-service-account: statuslist-sa@PROJECT_ID.iam.gserviceaccount.com
```

---

## AKS — Workload Identity Federation

### Prerequisites

- AKS cluster with Azure AD Workload Identity enabled
- `az` CLI configured

### 1. Create Azure Managed Identity

```bash
az identity create \
  --name statuslist-mi \
  --resource-group RESOURCE_GROUP \
  --location northeurope

MI_CLIENT_ID=$(az identity show \
  --name statuslist-mi \
  --resource-group RESOURCE_GROUP \
  --query clientId -o tsv)

MI_OBJ_ID=$(az identity show \
  --name statuslist-mi \
  --resource-group RESOURCE_GROUP \
  --query principalId -o tsv)

# Grant Key Vault access
az keyvault set-policy \
  --name KEY_VAULT_NAME \
  --spn $MI_CLIENT_ID \
  --secret-permissions get list
```

### 2. Create Federated Identity Credential

```bash
# Get the OIDC issuer URL from AKS
OIDC_ISSUER=$(az aks show \
  --name AKS_CLUSTER_NAME \
  --resource-group RESOURCE_GROUP \
  --query oidcIssuerProfile.issuerUrl -o tsv)

az identity federated-credential create \
  --name statuslist-federated \
  --identity-name statuslist-mi \
  --resource-group RESOURCE_GROUP \
  --issuer $OIDC_ISSUER \
  --subject "system:serviceaccount:statuslist:statuslist-sa"
```

### 3. Deploy with Helm

```bash
helm install statuslist ./chart \
  --namespace statuslist \
  -f chart/values.yaml \
  -f chart/values-aks-wif.yaml
```

**Expected service account annotations:**

```yaml
serviceAccount:
  create: true
  name: statuslist-sa
  annotations:
    azure.workload.identity/client-id: <managed-identity-client-id>
    azure.workload.identity/tenant-id: <azure-tenant-id>
```

---

## Vault Kubernetes Auth

The server can authenticate to Vault using the Kubernetes ServiceAccount token projected into each pod by the Kubernetes API server — no `role_id`/`secret_id` secrets required.

### The TOKEN_PATH Pattern

```
/var/run/secrets/kubernetes.io/serviceaccount/token  ← K8s projected SA token
```

Set `APP_VAULT__AUTH_MOUNT=kubernetes` and `APP_VAULT__TOKEN_PATH=/var/run/secrets/tokens/vaulttoken` (adjust the path to match your CSI driver or Vault Agent projection location).

### Server-Side Setup

1. **Enable and configure Kubernetes auth** — see [docs/secrets-backends.md](secrets-backends.md#vault-kubernetes-auth-no-static-credentials).

2. **Deploy with Helm** using `values-vault-k8s.yaml`:

```bash
helm install statuslist ./chart \
  --namespace statuslist \
  -f chart/values.yaml \
  -f chart/values-vault-k8s.yaml
```

For a hybrid deployment that uses IRSA for Route53 ACME DNS challenges and Vault K8s auth for certificate storage:

```bash
helm install statuslist ./chart \
  --namespace statuslist \
  -f chart/values.yaml \
  -f chart/values-aws-irsa.yaml \
  -f chart/values-vault-k8s.yaml
```

---

## Checking Active Credentials

Verify Workload Identity is working before deploying the full application:

### AWS IRSA

```bash
kubectl run creds-check --rm -it --image=amazon/aws-cli -- \
  aws sts get-caller-identity
```

Expected output shows the IRSA role ARN, not a user ARN.

### GCP WI

```bash
kubectl run creds-check --rm -it --image=gcr.io/google.com/cloudsdktool/cloud-sdk:slim -- \
  sh -c "gcloud auth application-default login"
```

### Verify ServiceAccount Annotations

```bash
# Check the pod uses the correct ServiceAccount
kubectl get pod -l app.kubernetes.io/name=status-list-server \
  -o jsonpath='{.items[*].spec.serviceAccountName}'

# Verify IRSA annotation
kubectl get sa statuslist-sa \
  -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}'
```

If the SA annotation matches the IAM role ARN, the cloud SDK in the container automatically uses the Workload Identity credentials — no code or configuration changes needed in the application.

### Vault K8s Auth

```bash
# Check the mounted token exists
kubectl exec deploy/statuslist-server -- cat /var/run/secrets/tokens/vaulttoken | head -c 100

# Verify the app can reach Vault
kubectl exec deploy/statuslist-server -- \
  wget -qO- http://vault.openbao.svc.cluster.local:8200/v1/sys/health 2>/dev/null || echo "Vault unreachable"
```

---

## Further Reading

- [Secrets Backends Guide](secrets-backends.md) — AppRole vs K8s auth, decision matrix
- [Helm Deployment Guide](helm/README.md) — Quick-start by platform, rendering all variants
- [Deployment Architecture](deployment-architecture.md) — Full topology overview