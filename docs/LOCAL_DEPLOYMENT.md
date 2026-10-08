# Local Testing Quickstart

## Environment Configuration

To initialize your local environment configuration:

```bash
cp .env.template .env
```

The `.env.template` file serves as a reference blueprint documenting all available environment variables, data types, and application defaults. Docker Compose automatically loads `.env` (when present) to inject container environment variables and resolve host string interpolations. `.env.template` is not loaded directly by Docker Compose, preventing unwanted placeholder overrides and configuration conflicts.

## Docker Compose profiles

`docker compose up --build` starts only the server. It uses in-memory storage and a checked-in local test certificate. This file requires Docker Compose 2.24.0 or later. The server starts with every profile; each profile adds only the selected optional services. Starting a profile does not reconfigure the server to use that service: select the matching build feature and application settings when integration is required.

- `postgres`: Add PostgreSQL (`db`) only.
- `mysql`: Add MySQL (`mysql`) only.
- `observability`: OpenTelemetry Collector, Jaeger, Prometheus, Alertmanager,
  Grafana, and Pushgateway.
- `acme`: Pebble and its challenge test server.
- `fscert`: One-shot `filesystem-cert` preparation of the checked-in local test certificate.
- `aws`: Floci (Secrets Manager, Route53).
- `redis`: Redis.

> **NOTE**: The `postgres` and `mysql` profiles are alternatives. Do not activate both for the same application instance.

Start one optional subsystem beside the default in-memory server:

```bash
docker compose --profile postgres up -d
docker compose --profile mysql up -d
docker compose --profile acme up -d
docker compose --profile aws up -d
docker compose --profile redis up -d
```

To use Redis as the server cache, build with its feature and select it at runtime:

```bash
FEATURES=redis APP_CACHE__BACKEND=redis \
  docker compose --profile redis up -d --build
```

For the telemetry stack, set `GRAFANA_ADMIN_PASSWORD` in your local `.env` or
shell before starting it. Grafana refuses to start with an empty password:

```bash
APP_TELEMETRY__ENABLED=true \
  docker compose --profile observability up -d
```

Profiles can be combined. To configure the server to use PostgreSQL and ACME, and export telemetry, set `GRAFANA_ADMIN_PASSWORD` and run:

```bash
FEATURES=postgres,aws APP_TELEMETRY__ENABLED=true \
  docker compose --profile postgres --profile acme --profile aws \
    --profile observability up -d --build
```

The `aws` feature includes ACME certificate provisioning. Local AWS builds
therefore need both the `aws` and `acme` profiles.

Dependencies are optional so the unprofiled server can start by itself. When a selected dependency is unhealthy, Compose may warn and still start the app. Check `docker compose ps`, the relevant service logs, and `/health/ready` before assuming the selected stack is ready.

Published ports bind to `127.0.0.1` by default. For development on a remote
machine, set `BIND_ADDR` to the required host interface and protect that
interface appropriately; the bundled services use development credentials.

The `fscert` tool copies the local ES256 development certificate into a shared volume with private key permissions restricted to the server user. To use that copy instead of the directly mounted sample files:

```bash
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=/etc/status-list/generated/tls.crt \
  APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=/etc/status-list/generated/tls.key \
  docker compose --profile fscert up -d --build
```

The `certdata` named volume persists across ordinary `docker compose down` and `up` cycles. `docker compose down --volumes` removes it together with the other Compose-managed data volumes. The material comes from test data and is for local development only. Never use the checked-in certificate and private key with `APP_ENV=production`.

To use MySQL, use `FEATURES=mysql`, set the `APP_DATABASE__*` values for MySQL in `.env`, and activate only the `mysql` database profile. See
[Database Backends](database-backends.md).

## Minikube quickstart

Lean checklist for running the status-list-server chart on Minikube.

### 1. Prerequisites

- Minikube ≥ v1.30 (Docker driver recommended)
- Helm ≥ v3.8
- kubectl matching the Minikube cluster

### 2. Start Minikube

```bash
minikube start
kubectl config use-context minikube
```

### 3. Prepare Namespace

The chart renders the fallback `statuslist-secret` by default. Create the namespace before installing so rendered resources land in the expected place.

```bash
kubectl create namespace local
```

### 4. Deploy

> **Image tag:** the chart's default `appVersion` (`1.0.1-fscert`) is a provider-neutral variant tag.
> The release pipeline publishes only variant-suffixed tags (`latest-aws`, `latest-gcp`,
> `latest-azure`, `latest-vault`, `latest-fscert`, and matching version/sha tags); there is no
> unsuffixed `latest` or `1.0.1`. Override the tag only when you need a specific cloud variant or a
> locally loaded image. See `docs/troubleshooting.md` -> "Image pull errors on variant tags".

```bash
helm dependency update ./deploy/helm/chart
helm install statuslist-local ./deploy/helm/chart -n local -f ./deploy/helm/chart/values-local.yaml
```

> **Certificates:** the default `-fscert` image is provider-neutral and requires certificate and
> signing-key files mounted into the pod. `values-local.yaml` includes disposable local sample
> material and mounts it through `statuslist.secretMounts`. For non-local runs, provide your own
> Secret-backed files or use an image variant tailored to your environment.

### 5. Verify Pods

```bash
kubectl get pods -n local
```

Expect these components to reach `Running`:

- `statuslist-local-postgres-0`
- `statuslist-local-status-list-server-deployment-*`

### 6. Access the API

```bash
kubectl port-forward -n local svc/statuslist-local-status-list-server-service 8081:8081
curl http://localhost:8081/health/live
curl http://localhost:8081/health/ready
```

### 7. Tear Down

```bash
helm uninstall statuslist-local -n local
kubectl delete namespace local
minikube stop
```

### Notes

- `values-local.yaml` only overrides what differs from neutral defaults (NodePorts, disabled ingress/secret-store, lighter resources).
- AWS-specific resources remain disabled; no additional setup required.
- If pods fail with `CreateContainerConfigError`, check that the rendered fallback `statuslist-secret` exists in the `local` namespace.
