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
- **`statuslist.image.tag`**: The Docker image tag.
- **`postgres.persistence.enabled`**: Enable or disable persistent storage for PostgreSQL.

## Credential Exposure Model

The chart intentionally avoids rendering fully assembled SQL database URLs in the Deployment. The application assembles the connection string inside the process from split configuration fields:

- Database: `APP_DATABASE__HOST`, `APP_DATABASE__PORT`, `APP_DATABASE__USERNAME`, `APP_DATABASE__PASSWORD`, `APP_DATABASE__NAME`, and optional `APP_DATABASE__QUERY`

Use `APP_DATABASE__QUERY` for non-secret driver parameters such as `sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt`. Do not put credentials in query parameters.

Password fields are rendered with `valueFrom.secretKeyRef`, so `kubectl describe pod` shows the referenced Secret name/key rather than a connection string containing credentials. Operators should still restrict RBAC for pod inspection, Secret reads, exec access, ephemeral containers, and workload log access to trusted roles only, because environment variables are visible inside the running container and Secret references identify where credentials live.

For external databases such as RDS, set `APP_DATABASE__HOST`, `APP_DATABASE__PORT`, `APP_DATABASE__BACKEND`, `APP_DATABASE__USERNAME`, `APP_DATABASE__NAME`, and optional `APP_DATABASE__QUERY` through `statuslist.env`. Do not set `APP_DATABASE__PASSWORD` there. The chart always wires `APP_DATABASE__PASSWORD` from a Kubernetes Secret key named `postgres-password`: either the `externalSecret.spec.target.name` Secret when `externalSecret.enabled=true`, or the `statuslist-secret` Secret otherwise. This key name is a hard chart contract even for MySQL or MariaDB backends, so create or sync that exact Secret/key with the external database password before deploying.

`APP_DATABASE__PORT` must be set in `statuslist.env`; the chart does not infer or default it from the PostgreSQL subchart. This keeps the database port an explicit runtime input and avoids silently connecting to the wrong port when operators customize database topology.

`APP_DATABASE__URL` remains supported by the application for local or custom deployments, but the Helm chart rejects it in `statuslist.env` because using it directly in Kubernetes pod specs accepts the tradeoff that users with pod-inspection permissions may see assembled connection strings. Prefer the split fields for Helm-managed deployments. When any split database field is provided, the application rejects a simultaneous custom `database.url` to avoid silent precedence surprises.

The bundled in-cluster PostgreSQL subchart is treated as a cluster-internal connection and this chart does not provision database TLS certificates by default. **In-cluster database traffic is unencrypted by default** and relies on CNI/mesh encryption (if configured in your cluster). For managed or external databases, prefer TLS and set non-secret driver parameters with `APP_DATABASE__QUERY`, for example `sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt`. The referenced CA path must exist in the container, either from the image trust store or from an operator-provided mount.

To enable TLS for external databases, set `APP_DATABASE__QUERY` to include the appropriate SSL mode, for example: `sslmode=require` for basic TLS or `sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt` for full certificate verification.

The application no longer provides a built-in `database.url` default. Non-Helm and local deployments must set either `APP_DATABASE__URL` or the split database fields explicitly; SQLite development runs should set `APP_DATABASE__URL=sqlite::memory:?cache=shared` when an in-memory database is intended.

## Production Deployment Instructions

For GitHub Actions deployments to production, see the [Deployment Runbook](../docs/deployment-runbook.md). CI/CD owns production image tag injection with `statuslist.image.repository` and `statuslist.image.tag`; operators should avoid patching live images imperatively because Helm will reconcile the chart state on the next deploy. Failed upgrades roll back automatically through Helm `--atomic`; rollbacks after a successful but bad deploy are manual Helm operations.

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
