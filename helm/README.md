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

## Redis Role

Redis is optional. The server does not use Redis for status-list persistence or status-list reads; those use the configured repository backend and the in-process Moka status-list cache. Certificate and signing-key material are managed together by the feature-selected cryptographic-material backend; prefer the built-in material read-cache TTLs before adding Redis.

Keep Redis disabled for a simpler deployment. Enable it only for explicit adapter-level integrations that still require Redis and where the extra dependency, credentials, TLS configuration, monitoring, and HA operations are worth it.

### No-Redis Deployment

The default `chart/values.yaml` path keeps `redis-ha.enabled=false`, does not render Redis application env vars, does not render the Redis TLS sync CronJob, and does not require a `redis-password` secret key.

```bash
helm dependency update ./chart
helm template statuslist ./chart --namespace statuslist
```

### Redis-Enabled Certificate Cache

To enable Redis, use an application image built with `redis,aws-secrets,acme` features, set `redis-ha.enabled=true`, provide a `redis-password` in the configured secret or ExternalSecret, and keep `APP_REDIS__URI` unset in `statuslist.env` so the chart can generate it from the Redis HA service. Set `APP_REDIS__REQUIRE_CLIENT_AUTH` and Redis HAProxy TLS values only when your Redis endpoint requires them.

## Production Deployment Instructions

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
