# Deployment Guide

This guide provides instructions for deploying the Status List Server using the provided Helm chart.

## Prerequisites

- Kubernetes cluster (e.g., AWS EKS)
- Helm 3 installed
- `kubectl` configured to connect to your cluster
- [External Secrets Operator](https://external-secrets.io/) installed in the cluster (this chart creates a `SecretStore`/`ExternalSecret` that depends on the ESO CRDs and controller already running)
- Two AWS IAM prerequisites configured **before** installing the chart — see [AWS IAM Prerequisites (IRSA)](#aws-iam-prerequisites-irsa) below
- The Postgres and Redis StatefulSets use `ReadWriteOnce` EBS-backed PVCs (`storageClass: high-performance` / `gp3` by default). On multi-AZ node groups with cluster-autoscaler, an EBS volume is zone-locked to whichever AZ its pod first schedules in; if the node group later scales down/rotates and no nodes remain in that AZ, the pod will be stuck `Pending` with `didn't match PersistentVolume's node affinity`. Either pin a minimum node count per AZ used by these StatefulSets, or be prepared to recreate the PVC (data loss) / restore from backup if a volume becomes stranded.

## AWS IAM Prerequisites (IRSA)

This chart relies on two independent IAM roles associated via IRSA (IAM Roles for Service Accounts). Both must exist and be correctly scoped before `helm install`, or the corresponding pods will fail to start.

### 1. External Secrets Operator's IRSA role

Used by ESO to pull secrets from AWS Secrets Manager into Kubernetes. Must be attached to the role bound to ESO's ServiceAccount (e.g. `external-secrets-role`).

Add this permission to the existing ESO role (or create a new one if it doesn't exist):

```bash
aws iam put-role-policy \
  --role-name external-secrets-role \
  --policy-name statuslist-secrets-read \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "ReadStatusListSecret",
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
        "Resource": "arn:aws:secretsmanager:eu-central-1:982081049921:secret:statuslist-secret-PUwXi1"
      }
    ]
  }' \
  --region eu-central-1
```

The `statuslist-secret` in AWS Secrets Manager must contain keys `POSTGRES_PASSWORD` and `REDIS_PASSWORD` as referenced under `externalSecret.spec.data` in `values.yaml`.

### 2. Application's own IRSA role

Used by the `status-list-server` pod to authenticate to AWS S3 (for TLS certificate storage) and Route53 (for ACME DNS-01 challenges) via the default AWS SDK credential chain. Values needed for the steps below:

- AWS account ID: `982081049921`
- Region: `eu-central-1`
- EKS cluster name: `datev-wallet-cluster`
- EKS OIDC provider ID: see `aws eks describe-cluster --name datev-wallet-cluster --region eu-central-1 --query 'cluster.identity.oidc.issuer'`
- S3 bucket: `status-list-adorsys`
- ServiceAccount name: `statuslist-status-list-server` (namespace: `statuslist`)

**Step 1 — Verify the cluster has OIDC enabled:**

```bash
aws eks describe-cluster --name datev-wallet-cluster --region eu-central-1 --query 'cluster.identity.oidc.issuer' --output text
```

If it returns a URL like `https://oidc.eks.eu-central-1.amazonaws.com/id/XXXXXXXX`, the cluster is ready. If it returns empty, run:

```bash
aws eks associate-iam-oidc-provider \
  --cluster-name datev-wallet-cluster \
  --region eu-central-1 \
  --no-verify-ssl
```

**Step 2 — Create the IAM role:**

```bash
aws iam create-role \
  --role-name statuslist-app-role \
  --description "IRSA role for status-list-server app (S3 + Route53)" \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Federated": "arn:aws:iam::982081049921:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/<YOUR_OIDC_PROVIDER_ID>"
        },
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
          "StringEquals": {
            "oidc.eks.eu-central-1.amazonaws.com/id/<YOUR_OIDC_PROVIDER_ID>:sub": "system:serviceaccount:statuslist:statuslist-status-list-server"
          }
        }
      }
    ]
  }' \
  --region eu-central-1
```

Replace `<YOUR_OIDC_PROVIDER_ID>` with your EKS cluster's OIDC provider ID (output from Step 1 — extract the part after `/id/`).

**Step 3 — Attach S3 and Route53 permissions:**

```bash
aws iam put-role-policy \
  --role-name statuslist-app-role \
  --policy-name StatusListAppPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "S3BucketAccess",
        "Effect": "Allow",
        "Action": ["s3:ListBucket"],
        "Resource": "arn:aws:s3:::status-list-adorsys"
      },
      {
        "Sid": "S3ObjectAccess",
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        "Resource": "arn:aws:s3:::status-list-adorsys/*"
      },
      {
        "Sid": "Route53Access",
        "Effect": "Allow",
        "Action": ["route53:GetChange", "route53:ListResourceRecordSets", "route53:ChangeResourceRecordSets"],
        "Resource": "arn:aws:route53:::hostedzone/*"
      }
    ]
  }' \
  --region eu-central-1
```

### Step 4 — Enable IRSA in values.yaml

The `values.yaml` ships with `serviceAccount.annotations` commented out. Uncomment and fill in your role ARN (or supply it via `--set` during install):

```yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::982081049921:role/statuslist-app-role"
```

The app authenticates using the AWS SDK's default credential chain (WebIdentityToken via IRSA) — no static credentials are mounted into the pod.

## Chart Dependencies

This chart has the following dependencies:

- **PostgreSQL**: A relational database for storing application data.
- **Redis HA**: A high-availability Redis cluster for caching.

These dependencies are managed by the Helm chart and will be installed automatically.

## Configuration

The following files are used to configure the deployment:

- [`chart/values.yaml`](chart/values.yaml): Default configuration for production environments.
- [`chart/values-local.yaml`](chart/values-local.yaml): Configuration for local development.

### Key Configuration Options

- **`statuslist.image.repository`**: The Docker image for the application.
- **`statuslist.image.tag`**: The Docker image tag.
- **`postgres.persistence.enabled`**: Enable or disable persistent storage for PostgreSQL.
- **`redis-ha.persistentVolume.enabled`**: Enable or disable persistent storage for Redis.

## Production Deployment Instructions

1. **Create a namespace:**

   ```bash
   kubectl create namespace statuslist
   ```

2. **Create TLS secrets:**

   Refer to the [Redis TLS Setup Guide](../docs/REDIS_TLS_SETUP.md) for detailed instructions on creating the necessary TLS secrets for Redis and HAProxy.

   The `statuslist-haproxy-tls` secret consumed by the Redis HAProxy Deployment is derived automatically from `statuslist-tls` by a `pre-install`/`pre-upgrade` Helm hook Job (`redis-cert-sync-bootstrap-<revision>`), and kept in sync afterwards by a weekly `redis-cert-sync` CronJob whenever cert-manager rotates the wildcard certificate. You do not need to create `statuslist-haproxy-tls` manually, but `statuslist-tls` must already exist (issued by cert-manager via the Ingress, or created manually per the guide above) before the hook Job can succeed — the hook retries with backoff if it isn't ready yet.

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
