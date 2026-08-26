# Deployment Guide

This guide provides instructions for deploying the Status List Server using the provided Helm chart.

## Prerequisites

- Kubernetes cluster (e.g., AWS EKS)
- Helm 3 installed
- `kubectl` configured to connect to your cluster

## Chart Dependencies

This chart has the following dependencies:

- **PostgreSQL**: A relational database for storing application data.
- **OpenTelemetry Collector**: Official subchart (`open-telemetry/opentelemetry-collector`) for collecting and routing traces, metrics, and logs.

These dependencies are managed by the Helm chart. PostgreSQL is enabled by default.

## Configuration

The following files are used to configure the deployment:

- [`chart/values.yaml`](chart/values.yaml): Default configuration for production environments.
- [`chart/values-local.yaml`](chart/values-local.yaml): Configuration for local development.

### Key Configuration Options

- **`statuslist.image.repository`**: The Docker image for the application.
- **`statuslist.image.tag`**: The Docker image tag. Used only when `statuslist.image.digest` is empty. Defaults to empty, which falls back to the chart's `appVersion` — not to `latest`, so an upgrade that changes nothing in the chart cannot change the running image and a rollback stays reproducible. `appVersion` therefore has to track the latest released application version.
- **`statuslist.image.pullPolicy`**: Defaults to empty, which derives the policy from how the image is named: `IfNotPresent` when a digest is set, because a digest is content-addressed and re-pulling it can only fetch the same bytes, and `Always` for a tag, which is mutable. Set it explicitly to override.
- **`statuslist.image.digest`**: An image digest as `sha256:` plus 64 hex characters; anything else is rejected at template time. When set it takes precedence over `statuslist.image.tag`, and the deployment runs `repository@digest`. Production deploys set this so the running image is the exact artifact CI scanned; tags are mutable and a digest is not. Leave it empty for local and manual installs to get tag-based deployment.
- **`postgres.persistence.enabled`**: Enable or disable persistent storage for PostgreSQL.

## Production Deployment Instructions

For GitHub Actions deployments to production, see the [Deployment Runbook](../docs/deployment-runbook.md). CI/CD owns production image injection with `statuslist.image.repository`, `statuslist.image.tag` and `statuslist.image.digest`. The digest is what determines the running image; the tag is passed alongside it for readability in `helm history` and release notes. Because of that precedence, do not run `helm upgrade --reuse-values` with only a changed tag: the stored digest still wins, so the upgrade reports success and changes nothing. Pass both, or clear the digest with `--set statuslist.image.digest=null`. A digest that is not `sha256:` followed by 64 hex characters is rejected at template time. Operators should avoid patching live images imperatively because Helm will reconcile the chart state on the next deploy. Failed upgrades roll back automatically through Helm `--atomic`; rollbacks after a successful but bad deploy are manual Helm operations.

1. **Create a namespace:**

   ```bash
   kubectl create namespace statuslist
   ```

2. **Deploy the chart:**

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
