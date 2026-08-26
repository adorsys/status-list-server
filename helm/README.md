# Deployment Guide

This guide provides instructions for deploying the Status List Server using the provided Helm chart.

## Prerequisites

- A Kubernetes cluster (the chart is cloud-agnostic; see the environment overlays below for provider-specific settings such as AWS EKS)
- Helm 3 installed
- `kubectl` configured to connect to your cluster

## Chart Dependencies

This chart has the following dependencies:

- **PostgreSQL**: A relational database for storing application data.
- **OpenTelemetry Collector**: Official subchart (`open-telemetry/opentelemetry-collector`) for collecting and routing traces, metrics, and logs.

These dependencies are managed by the Helm chart. PostgreSQL is enabled by default.

## Configuration

The chart defaults are vendor-neutral. Provider-specific settings live in environment overlays:

- [`chart/values.yaml`](chart/values.yaml): Vendor-neutral default configuration.
- [`chart/values-aws.yaml`](chart/values-aws.yaml): AWS/EKS overlay (SecretsManager SecretStore, Route53 DNS provider, public domain, provider storage class, and Service annotations).
- [`chart/values-local.yaml`](chart/values-local.yaml): Configuration for local development.

Other cloud environments (GCP Secret Manager via `secretStore.provider: gcpsm`, Azure Key Vault via `secretStore.provider: azurekv`) are supported by the external-secrets SecretStore template; provide the corresponding `secretStore.<provider>` block.

### Key Configuration Options

- **`global.domain`**: Chart-wide public domain. The ingress host and the application `APP_SERVER__DOMAIN` fall back to this when `statuslist.ingress.externalDnsHostname` is not set. Empty by default.
- **`statuslist.service.annotations`**: Arbitrary Service annotations. Provider-specific annotations (e.g. AWS NLB) belong in environment overlays, not defaults.
- **`postgres.persistence.storageClass`**: Set to `""` to use the cluster default storage class.
- **`secretStore`**: Disabled by default. When enabled, `secretStore.provider` selects the external-secrets backend (`aws`, `gcpsm`, or `azurekv`) and the corresponding config block must be provided.
- **`externalSecret`**: Disabled by default. When disabled, provision the `statuslist-secret` Secret (key `postgres-password`) out of band.
- **`statuslist.image.repository`**: The Docker image for the application.
- **`statuslist.image.tag`**: The Docker image tag.
- **`postgres.persistence.enabled`**: Enable or disable persistent storage for PostgreSQL.

## Production Deployment Instructions

For GitHub Actions deployments to production, see the [Deployment Runbook](../docs/deployment-runbook.md). CI/CD owns production image tag injection with `statuslist.image.repository` and `statuslist.image.tag`; operators should avoid patching live images imperatively because Helm will reconcile the chart state on the next deploy. Failed upgrades roll back automatically through Helm `--atomic`; rollbacks after a successful but bad deploy are manual Helm operations.

1. **Create a namespace:**

   ```bash
   kubectl create namespace statuslist
   ```

2. **Deploy the chart with an environment overlay (AWS/EKS shown):**

   ```bash
   helm install statuslist ./chart --namespace statuslist -f chart/values-aws.yaml
   ```

   Deploying without an overlay uses the vendor-neutral defaults; in that case provision the `statuslist-secret` (with `postgres-password`) out of band, as `externalSecret` and `secretStore` are disabled.

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
