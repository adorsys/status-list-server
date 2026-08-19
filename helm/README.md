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

## Workload Identity Deployment

The chart supports deploying without static cloud credentials using cloud-provider Workload Identity. See [docs/workload-identity.md](../docs/workload-identity.md) for detailed cloud-specific setup instructions covering AWS IRSA, GKE Workload Identity, AKS Workload Identity Federation, and Vault Kubernetes Auth.

### Quick-Start by Platform

| Platform     | Example Values File              | Auth Method                        |
|--------------|----------------------------------|------------------------------------|
| AWS EKS      | `values-aws-irsa.yaml`           | IAM Roles for Service Accounts     |
| GKE          | `values-gke-wi.yaml`             | GKE Workload Identity              |
| AKS          | `values-aks-wif.yaml`            | AKS Workload Identity Federation   |
| Any (Vault)  | `values-vault-k8s.yaml`          | Vault Kubernetes Auth              |

### Deploying with AWS IRSA

```bash
helm dependency build ./chart
helm install statuslist ./chart \
  --namespace statuslist \
  -f chart/values.yaml \
  -f chart/values-aws-irsa.yaml
```

### Deploying with Vault K8s Auth

```bash
helm install statuslist ./chart \
  --namespace statuslist \
  -f chart/values.yaml \
  -f chart/values-vault-k8s.yaml
```

### Decision Tree

Not sure which path to use? See the **Authentication & Secrets Delivery Decision Tree** in [docs/secrets-backends.md](../docs/secrets-backends.md) for a step-by-step guide to choosing the right configuration.

### Rendering All Provider Variants

The CI validates that all provider values files render cleanly. Run locally:

```bash
helm dependency build ./chart
for file in values-aws-irsa values-vault-k8s values-gke-wi values-aks-wif; do
  helm template statuslist ./chart -f chart/values.yaml -f "chart/${file}.yaml" > /tmp/rendered-${file}.yaml
  echo "✓ ${file}.yaml rendered $(wc -l < /tmp/rendered-${file}.yaml) lines"
done
```

## Redis Role

Redis is optional. The server does not use Redis for status-list persistence or status-list reads; those use the configured repository backend and the in-process Moka status-list cache. In this chart, Redis is intended only as a distributed certificate-material cache for multi-replica deployments that use the AWS S3 certificate storage path and compile the application with the `redis` feature.

Keep Redis disabled for a simpler deployment. Enable it when sharing certificate cache entries across replicas and reducing object-storage reads is worth the extra Redis dependency, credentials, TLS configuration, monitoring, and HA operations.

### No-Redis Deployment

The default `chart/values.yaml` path keeps `redis-ha.enabled=false`, does not render Redis application env vars, does not render the Redis TLS sync CronJob, and does not require a `redis-password` secret key.

```bash
helm dependency update ./chart
helm template statuslist ./chart --namespace statuslist
```

### Redis-Enabled Certificate Cache

To enable Redis, use an application image built with `redis,aws,acme` features, set `redis-ha.enabled=true`, provide a `redis-password` in the configured secret or ExternalSecret, and keep `APP_REDIS__URI` unset in `statuslist.env` so the chart can generate it from the Redis HA service. Set `APP_REDIS__REQUIRE_CLIENT_AUTH` and Redis HAProxy TLS values only when your Redis endpoint requires them.

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