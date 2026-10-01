# Local Testing Quickstart

## Docker Compose profiles

`docker compose up --build` starts only the server. It uses in-memory storage
and a checked-in local test certificate. The server starts with every profile; each profile adds only the selected optional services.

- `postgres`: Add PostgreSQL (`db`) only.
- `mysql`: Add MySQL (`mysql`) only.
- `observability`: OpenTelemetry Collector, Jaeger, Prometheus, Alertmanager,
  Grafana, and Pushgateway.
- `acme`: Pebble and its challenge test server.
- `fscert`: One-shot `filesystem-cert` preparation of the checked-in local test certificate.
- `aws`: LocalStack.
- `redis`: Redis.

Start the server with one optional subsystem:

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
docker compose --profile observability up -d
```

Profiles can be combined. To configure the server to use PostgreSQL and ACME,
and export telemetry, set `GRAFANA_ADMIN_PASSWORD` and run:

```bash
FEATURES=postgres,aws,redis APP_DATABASE__BACKEND=postgres \
  APP_SERVER__CERT__PROVISIONING_STRATEGY=acme APP_TELEMETRY__ENABLED=true \
  docker compose --profile postgres --profile acme --profile aws \
    --profile observability up -d --build
```

The server waits for selected dependencies but can start without them. The
`fscert` tool copies the local test certificate into a shared volume with
private key permissions restricted to the server user. To use that copy
instead of the directly mounted sample files:

```bash
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=/etc/status-list/generated/tls.crt \
  APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=/etc/status-list/generated/tls.key \
  docker compose --profile fscert up -d --build
```

The `fscert` material comes from `test_data/certs` and is for local development only. To use MySQL, use `FEATURES=mysql,aws` and set the `APP_DATABASE__*` values for MySQL in `.env`; activate `mysql`, `aws`, and any other profiles that configuration needs. See [Database Backends](database-backends.md).

## Minikube quickstart

Lean checklist for running the status-list-server chart on Minikube.

## 1. Prerequisites

- Minikube ≥ v1.30 (Docker driver recommended)
- Helm ≥ v3.8
- kubectl matching the Minikube cluster

## 2. Start Minikube

```bash
minikube start
kubectl config use-context minikube
```

## 3. Prepare Namespace

The chart renders the fallback `statuslist-secret` by default. Create the namespace before installing so rendered resources land in the expected place.

```bash
kubectl create namespace local
```

## 4. Deploy

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

## 5. Verify Pods

```bash
kubectl get pods -n local
```

Expect these components to reach `Running`:

- `statuslist-local-postgres-0`
- `statuslist-local-status-list-server-deployment-*`

## 6. Access the API

```bash
kubectl port-forward -n local svc/statuslist-local-status-list-server-service 8081:8081
curl http://localhost:8081/health/live
curl http://localhost:8081/health/ready
```

## 7. Tear Down

```bash
helm uninstall statuslist-local -n local
kubectl delete namespace local
minikube stop
```

## Notes

- `values-local.yaml` only overrides what differs from neutral defaults (NodePorts, disabled ingress/secret-store, lighter resources).
- AWS-specific resources remain disabled; no additional setup required.
- If pods fail with `CreateContainerConfigError`, check that the rendered fallback `statuslist-secret` exists in the `local` namespace.
