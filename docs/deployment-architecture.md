# Status List Server — Deployment Architecture

## Overview

The Status List Server is a Rust-based microservice deployed on AWS EKS. This document describes the complete deployment architecture from source code to running service.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DEPLOYMENT ARCHITECTURE                           │
└─────────────────────────────────────────────────────────────────────────────┘

   ┌──────────┐      ┌──────────────┐      ┌─────────────────┐
   │   GitHub  │ ───► │  GitHub      │ ───► │   AWS EKS        │
   │  (main)   │      │  Actions     │      │   Kubernetes    │
   └──────────┘      │  CI/CD       │      │   Cluster       │
                      └──────────────┘      └────────┬────────┘
                              │                        │
                              ▼                        ▼
                     ┌──────────────┐         ┌──────────────┐
                     │   GHCR       │         │  Helm Chart  │
                     │  Container   │         │  Deployment  │
                     │  Registry    │         └──────────────┘
                     └──────────────┘
```

## Table of Contents

1. [Technology Stack](#1-technology-stack)
2. [Build & Packaging](#2-build--packaging)
3. [Container Architecture](#3-container-architecture)
4. [CI/CD Pipeline](#4-cicd-pipeline)
5. [Kubernetes Deployment](#5-kubernetes-deployment)
6. [Helm Chart Structure](#6-helm-chart-structure)
7. [Runtime Configuration](#7-runtime-configuration)
8. [Observability Stack](#8-observability-stack)
9. [Dependency Management](#9-dependency-management)
10. [Security Hardening](#10-security-hardening)
11. [Deployment Checklist](#11-deployment-checklist)

---

## 1. Technology Stack

| Component          | Technology                  | Purpose                                |
| ------------------ | --------------------------- | -------------------------------------- |
| Language           | Rust (Edition 2024)         | High-performance, memory-safe backend  |
| Web Framework      | Axum 0.8                    | Async HTTP server                      |
| Database           | PostgreSQL 18 / MySQL 9     | Persistent storage via SeaORM          |
| Container          | Docker / BuildKit           | Multi-platform builds (amd64, arm64)   |
| Orchestration      | Kubernetes (AWS EKS)        | Container orchestration                |
| Package Manager    | Helm 3                      | Kubernetes resource management         |
| Observability      | OpenTelemetry + Prometheus  | Tracing, metrics, log aggregation      |
| Secrets            | External Secrets Operator   | AWS Secrets Manager integration        |
| DNS                | External-DNS + cert-manager | Automated DNS + TLS certificates       |
| CDN/Load Balancing | AWS NLB                     | Load balancing and global distribution |

---

## 2. Build & Packaging

### 2.1 Multi-Platform Docker Build

The project uses Docker BuildKit with cross-compilation for `amd64` and `arm64`:

```dockerfile
# Multi-stage build targeting musl-based Alpine for minimal image
FROM blackdex/rust-musl:${TARGETARCH} AS builder
ARG FEATURES="postgres,aws,acme"
cargo build --release --target=${RUST_TARGET} --features "${FEATURES}"

# Minimal scratch-based runtime image
FROM scratch AS runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chown=65534:65534 /app/${APP_NAME} /app/${APP_NAME}
USER 65534
```

### 2.2 Feature Flags

Cargo features gate production backend drivers:

| Feature       | Description                                                           | Default   |
| ------------- | --------------------------------------------------------------------- | --------- |
| `memory`      | In-memory storage + Moka cache                                        | ✅ Active |
| `postgres`    | PostgreSQL via SeaORM                                                 | Opt-in    |
| `mysql`       | MySQL via SeaORM                                                      | Opt-in    |
| `sqlite`      | SQLite via SeaORM                                                     | Opt-in    |
| `redis`       | Redis certificate cache driver                                        | Opt-in    |
| `aws-secrets` | Route53 DNS-01 + AWS Secrets Manager (single crypto-material backend) | Opt-in    |
| `vault`       | Vault/OpenBao KV v2 crypto-material backend                           | Opt-in    |
| `acme`        | ACME DNS-01 certificate provisioning                                  | Opt-in    |

Production builds include: `FEATURES="postgres,aws-secrets,acme"` (or `postgres,vault,acme` to store crypto material in Vault/OpenBao).

---

## 3. Container Architecture

### 3.1 Image Structure

```text
┌─────────────────────────────────────────────────────────┐
│              status-list-server:latest                  │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Scratch base image                            │
│  Layer 2: CA certificates (TLS verification)            │
│  Layer 3: /etc/passwd (non-root user)                   │
│  Layer 4: Application binary (UID 65534)                │
├─────────────────────────────────────────────────────────┤
│  User: 65534 (nobody)                                   │
│  Entrypoint: /app/status-list-server                    │
│  Port: 8000                                             │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Container Security

- **Non-root execution**: Runs as UID 65534
- **Minimal base**: `scratch` image contains only required artifacts
- **Read-only filesystem**: Root filesystem is read-only
- **No shell access**: Attack surface minimized

---

## 4. CI/CD Pipeline

### 4.1 Pipeline Overview

```text
┌─────────────────────────────────────────────────────────────────┐
│                    GitHub Actions CI/CD                          │
└─────────────────────────────────────────────────────────────────┘

  ┌─────────┐    ┌──────────┐    ┌────────────┐    ┌──────────┐
  │  Push   │───►│   Zizmor  │───►│   Build    │───►│ Clippy   │
  │  PR     │    │ Security  │    │   Check    │    │ Lints    │
  └─────────┘    └──────────┘    └────────────┘    └──────────┘
       │                                              │
       │                                              ▼
       │                                    ┌────────────────┐
       │                                    │   Nextest      │
       │                                    │   Tests        │
       │                                    └────────────────┘
       │                                              │
       ▼                                              ▼
  ┌──────────┐    ┌─────────────┐    ┌───────┐    ┌──────────┐
  │ Markdown │    │ Trivy Config │    │ Kube  │    │ Coverage │
  │ Lint     │    │ Scan         │    │ Linter│    │ Report   │
  └──────────┘    └─────────────┘    └───────┘    └──────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │                     CD Pipeline (on push to main/tag)          │
  └─────────────────────────────────────────────────────────────────┘

  ┌─────────┐    ┌──────────────┐    ┌─────────┐    ┌──────────┐
  │  Push   │───►│    CI        │───►│ Build & │───►│  Deploy  │
  │  main   │    │   Passes     │    │  Push   │    │  to EKS  │
  │  Tag    │    │              │    │  GHCR   │    │          │
  └─────────┘    └──────────────┘    └─────────┘    └──────────┘
```

### 4.2 CI Jobs

| Job               | Purpose                            |
| ----------------- | ---------------------------------- |
| `zizmor-security` | Workflow security scanning         |
| `cargo-fmt`       | Rust formatting check              |
| `cargo-build`     | Full workspace compilation         |
| `cargo-clippy`    | Linting with clippy                |
| `cargo-nextest`   | Parallel test execution            |
| `cargo-doc`       | Documentation generation           |
| `cargo-machete`   | Unused dependency detection        |
| `cargo-vet`       | Dependency vulnerability auditing  |
| `cargo-deny`      | License and security policy checks |
| `trivy-config`    | Helm chart vulnerability scanning  |
| `kube-linter`     | Kubernetes manifests linting       |
| `cargo-coverage`  | LLVM code coverage report          |

### 4.3 CD Pipeline

```yaml
# Triggered on push to main or tag (v*.*.*)
on:
  push:
    branches: [main]
    tags: [v*.*.*]

# Image tagging strategy
tags: |
  type=semver,pattern={{version}}          # v1.2.3 → 1.2.3
  type=raw,value=latest                     # main branch → latest
  type=sha,format=short                     # commit SHA → sha-abc1234
```

---

## 5. Kubernetes Deployment

### 5.1 Architecture on EKS

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           AWS EKS Cluster                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    statuslist Namespace                         │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │                 NGINX Ingress Controller                  │   │   │
│  │  │                      (External LB)                       │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  │                            │                                   │   │
│  │  ┌────────────────────────▼───────────────────────────────┐   │   │
│  │  │              statuslist Service (ClusterIP)             │   │   │
│  │  │                       Port: 8081                        │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  │                            │                                   │   │
│  │  ┌────────────────────────▼───────────────────────────────┐   │   │
│  │  │           statuslist Deployment (1 replica)            │   │   │
│  │  │  ┌───────────────────┐  ┌───────────────────────────┐  │   │   │
│  │  │  │  statuslist-server │  │  otel-collector (sidecar)│  │   │   │
│  │  │  │   Port: 8000       │  │   Port: 4317 (gRPC)     │  │   │   │
│  │  │  └───────────────────┘  └───────────────────────────┘  │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  │                            │                                   │   │
│  │  ┌─────────────────────────┼───────────────────────────────┐  │   │
│  │  │                         │                               │  │   │
│  │  ▼                         ▼                               ▼  │   │
│  │ ┌─────────────┐    ┌─────────────────┐                      │   │
│  │ │ PostgreSQL  │    │ OTEL Collector  │                      │   │
│  │ │  (Pods)     │    │  (Standalone)   │                      │   │
│  │ └─────────────┘    └─────────────────┘                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      Infrastructure Layer                        │   │
│  │  ┌───────────────────────┐  ┌───────────────────────────────┐   │   │
│  │  │  Crypto-Material Store │  │      cert-manager / ACME      │   │   │
│  │  │  (Vault or AWS SM)     │  │  (TLS certs via Route53 DNS)  │   │   │
│  │  └───────────────────────┘  └───────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Resource Allocation

| Component                | CPU Request | Memory Request | CPU Limit | Memory Limit |
| ------------------------ | ----------- | -------------- | --------- | ------------ |
| status-list-server       | 250m        | 256Mi          | 500m      | 512Mi        |
| PostgreSQL               | 250m        | 256Mi          | 500m      | 512Mi        |
| OTEL Collector           | 100m        | 128Mi          | 200m      | 256Mi        |
| OTEL Collector (sidecar) | 50m         | 64Mi           | 100m      | 128Mi        |

---

## 6. Helm Chart Structure

```text
helm/chart/
├── Chart.yaml              # Chart metadata and dependencies
├── values.yaml             # Production default values
├── values-local.yaml       # Local development values
├── values-production.yaml  # Production values applied by the deploy workflow
├── templates/
│   ├── deployment.yaml     # Application deployment
│   ├── service.yaml        # ClusterIP service
│   ├── serviceaccount.yaml # ServiceAccount (Workload Identity / IRSA annotations)
│   ├── ingress.yaml        # NGINX ingress with TLS
│   ├── network-policy.yaml # Kubernetes network policies
│   ├── secret-store.yaml   # Provider-neutral SecretStore configuration
│   ├── external-secrets.yaml   # ESO ExternalSecret integration
│   ├── secret.yaml         # Fallback Kubernetes Secret (non-ESO clusters)
│   ├── hpa.yaml            # Horizontal Pod Autoscaler (opt-in)
│   ├── pdb.yaml            # Pod Disruption Budget (opt-in)
│   └── tests/              # Helm chart smoke tests
└── README.md               # Deployment documentation
```

### 6.1 Chart Dependencies

| Dependency              | Version | Repository                                                   | Purpose               |
| ----------------------- | ------- | ------------------------------------------------------------ | --------------------- |
| PostgreSQL              | 0.8.2   | `oci://registry-1.docker.io/cloudpirates`                    | Database storage      |
| OpenTelemetry Collector | 0.169.0 | `https://open-telemetry.github.io/opentelemetry-helm-charts` | Metrics, traces, logs |

### 6.2 Key Values

```yaml
# Image configuration
statuslist:
  image:
    repository: ghcr.io/adorsys/status-list-server
    tag: "latest" # Overridden by CD pipeline
    pullPolicy: Always

  # Service configuration
  service:
    type: ClusterIP
    port: 8081
    targetPort: 8000

  # Ingress with TLS
  ingress:
    enabled: true
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
    tls:
      hosts:
        - "*.eudi-adorsys.com"
      secretName: statuslist-tls
    externalDnsHostname: statuslist.eudi-adorsys.com
```

---

## 7. Runtime Configuration

### 7.1 Environment Variables

| Variable                          | Default          | Description                     |
| --------------------------------- | ---------------- | ------------------------------- |
| `APP_ENV`                         | `development`    | Runtime environment             |
| `APP_SERVER__PORT`                | `8000`           | Server port                     |
| `APP_DATABASE__BACKEND`           | `postgres`       | Database driver                 |
| `APP_STATUS_LIST__TOKEN_EXP_SECS` | `900`            | Status list expiration (15 min) |
| `APP_STATUS_LIST__TOKEN_TTL_SECS` | `300`            | Status list TTL (5 min)         |
| `APP_CACHE__TTL`                  | `300`            | Status list cache TTL           |
| `APP_RATE_LIMIT__*`               | Various          | Rate limiting configuration     |
| `APP_LIMITS__MAX_BODY_SIZE_BYTES` | `2097152`        | Max request body (2 MiB)        |
| `APP_SERVER__CERT__ACME_*`        | —                | ACME certificate provisioning   |
| `APP_TELEMETRY__ENABLED`          | `true`           | OpenTelemetry export            |
| `APP_TELEMETRY__OTLP_ENDPOINT`    | `localhost:4317` | OTLP gRPC endpoint              |

### 7.2 DNS Providers for ACME

| Provider         | Environment Variable Prefix            |
| ---------------- | -------------------------------------- |
| AWS Route53      | `APP_SERVER__CERT__DNS__ROUTE53__*`    |
| Cloudflare       | `APP_SERVER__CERT__DNS__CLOUDFLARE__*` |
| Google Cloud DNS | `APP_SERVER__CERT__DNS__GCLOUD__*`     |
| Azure DNS        | `APP_SERVER__CERT__DNS__AZURE__*`      |
| ACME-DNS         | `APP_SERVER__CERT__DNS__ACMEDNS__*`    |

---

## 8. Observability Stack

### 8.1 Data Flow

```text
┌─────────────────────────────────────────────────────────────────┐
│                      Observability Architecture                  │
└─────────────────────────────────────────────────────────────────┘

   ┌──────────────────┐         ┌──────────────────┐
   │ statuslist-server│         │   Application    │
   │                  │         │    Logs          │
   └────────┬─────────┘         └────────┬─────────┘
            │                          │
            ▼                          ▼
   ┌──────────────────┐         ┌──────────────────┐
   │   Prometheus     │         │  Structured      │
   │   Metrics        │         │  JSON Logs       │
   │   (:8000/metrics)│         │  (stdout)        │
   └────────┬─────────┘         └────────┬─────────┘
            │                          │
            ▼                          │
   ┌──────────────────┐                │
   │ OTEL Collector   │◄────────────────┘
   │ (sidecar/        │
   │  standalone)     │
   └────────┬─────────┘
            │
    ┌───────┼───────┐
    ▼       ▼       ▼
┌───────┐ ┌──────┐ ┌────────┐
│Traces │ │Metrics│ │ Logs   │
│(OTLP) │ │(OTLP)│ │(OTLP)  │
└───┬───┘ └──┬───┘ └───┬────┘
    ▼       ▼         ▼
┌────────────────────────────────┐
│      Backend                   │
│  ┌────────┐ ┌────────┐         │
│  │ Jaeger │ │Tempo/  │         │
│  │        │ │Loki    │         │
│  └────────┘ └────────┘         │
└────────────────────────────────┘
```

### 8.2 Local Observability Setup

When running with Docker Compose:

| Service            | URL                             |
| ------------------ | ------------------------------- |
| Status List Server | `http://localhost:8000`         |
| Prometheus UI      | `http://localhost:9090`         |
| Jaeger UI          | `http://localhost:16686`        |
| Metrics endpoint   | `http://localhost:8000/metrics` |

---

## 9. Dependency Management

### 9.1 Secrets Management

Secrets are delivered to the application through **External Secrets Operator (ESO)**, the default secret-delivery path — not Workload Identity. The chart renders:

- A `SecretStore` (`secret-store.yaml`) that is **provider-neutral** — `secretStore.provider` selects between `aws` (Secrets Manager / Parameter Store), `vault` (Vault / OpenBao), `gcp` (Secret Manager), `azure` (Key Vault), or `raw` (full provider passthrough for unsupported ESO providers).
- An `ExternalSecret` (`external-secrets.yaml`, gated on `externalSecret.enabled`) that syncs the `postgres-password` key into the `statuslist-secret` Kubernetes Secret.
- A second `ExternalSecret` that provisions `aws-credentials-secret` so the ESO-mounted credentials path is complete (rendered only when `externalSecret.enabled=true` **and** `statuslist.aws.mountCredentials=true`).
- A **fallback Kubernetes `Secret`** (`secret.yaml`) for clusters that do not run ESO, rendered only when `externalSecret.enabled=false` and `statuslist.fallbackSecret.enabled=true`.

**ESO-mounted credentials (default):** the chart defaults to `statuslist.aws.mountCredentials=true`, so the application pod mounts the ESO-provisioned `aws-credentials-secret` at `/home/nobody/.aws`. Production (`values-production.yaml`) keeps this default, so no static credential files are managed by hand and no Workload Identity annotation is required.

**Workload Identity / IRSA (opt-in):** the application pod uses a dedicated `ServiceAccount` (`serviceAccount.create=true`). AWS/GCP/Azure ambient credentials are attached via `serviceAccount.annotations` (e.g. `eks.amazonaws.com/role-arn` for EKS IRSA). To opt in, set `statuslist.aws.mountCredentials=false` and attach the cloud role annotation; the application then uses ambient credentials instead of mounted files. See [Secrets Risk: ESO vs Workload Identity](secrets-risk-eso-vs-workload-identity.md) for the trade-offs.

### 9.2 Redis

The Helm chart no longer deploys the Redis HA subchart. Status-list reads and writes use the configured repository backend plus the in-process Moka cache, so Redis is not a runtime dependency of the deployment chart. Redis remains available behind the crate-level `redis` feature for application images that require an explicit adapter-level Redis integration.

### 9.3 Database Selection

| Use Case                  | Recommended Backend |
| ------------------------- | ------------------- |
| Production HA             | PostgreSQL          |
| MySQL-compatible infra    | MySQL               |
| Single-node / Development | SQLite              |
| Distributed production    | PostgreSQL / MySQL  |

---

## 10. Security Hardening

### 10.1 Kubernetes Security Context

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  fsGroup: 65534
  seccompProfile:
    type: RuntimeDefault

# Container-level
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities:
  drop: ["ALL"]
```

### 10.2 Network Policies

```yaml
# Ingress: Allow anywhere (no IP restrictions)
ingress: []

# Egress: PostgreSQL (5432), Redis (6379/6380), DNS (53), HTTPS (443), OTLP (4317/4318)
egress:
  - ports: [5432, 6379, 6380, 443, 53, 4317, 4318]
```

### 10.3 Rate Limiting

| Tier       | Burst | Period | Routes                             |
| ---------- | ----- | ------ | ---------------------------------- |
| Strict     | 10    | 60s    | `POST /api/v1/credentials`         |
| Writes     | 10    | 60s    | `PUT/PATCH /status-lists/*`        |
| Permissive | 100   | 60s    | `GET /status-lists/*`, aggregation |

### 10.4 Request Bounds

| Bound                      | Value   | Response Code |
| -------------------------- | ------- | ------------- |
| `max_body_size_bytes`      | 2 MiB   | `413`         |
| `max_status_index`         | 100,000 | `400`         |
| `max_statuses_per_request` | 5,000   | `400`         |
| `max_serialized_list_size` | 1 MiB   | `422`         |

---

## 11. Deployment Checklist

### Pre-Deployment

- [ ] Configure AWS credentials in GitHub Secrets
- [ ] Verify Helm dependencies are up to date
- [ ] Validate `values.yaml` for production environment
- [ ] Confirm database credentials in AWS Secrets Manager
- [ ] Verify DNS provider credentials for ACME

### Infrastructure Setup

- [ ] Create `statuslist` namespace
- [ ] Configure `high-performance` StorageClass (or adjust)
- [ ] Set up cert-manager ClusterIssuer for Let's Encrypt
- [ ] Configure External-DNS with DNS provider
- [ ] Create TLS secrets for Redis HAProxy (if using Redis)

### Application Deployment

- [ ] Deploy PostgreSQL: `helm install statuslist-postgres ./chart`
- [ ] Deploy Redis HA (optional): `redis-ha.enabled=true`
- [ ] Deploy application: `helm install statuslist ./chart -f chart/values.yaml`
- [ ] Verify pods are running: `kubectl get pods -n statuslist`
- [ ] Check application logs: `kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist`

### Post-Deployment Verification

- [ ] Access application at configured domain
- [ ] Verify TLS certificate provisioning
- [ ] Check OpenTelemetry traces in Jaeger
- [ ] Verify Prometheus metrics endpoint
- [ ] Test API endpoints (health, credentials, status lists)
- [ ] Validate network policies are enforced

### Monitoring Setup

- [ ] Configure Grafana dashboards (if applicable)
- [ ] Set up alerting rules for:
  - [ ] Pod restarts
  - [ ] High error rates
  - [ ] Certificate expiration
  - [ ] Database connectivity
- [ ] Verify log aggregation

---

## Appendix: API Endpoints

| Method | Endpoint                             | Auth | Description                    |
| ------ | ------------------------------------ | ---- | ------------------------------ |
| GET    | `/api/v1/status-lists/{id}`          | No   | Retrieve status list (JWT/CWT) |
| GET    | `/api/v1/aggregation`                | No   | List all status list URIs      |
| POST   | `/api/v1/credentials`                | No   | Register issuer credentials    |
| PUT    | `/api/v1/status-lists/{id}/statuses` | JWT  | Publish full status list       |
| PATCH  | `/api/v1/status-lists/{id}/statuses` | JWT  | Partial status update          |
| GET    | `/health`                            | No   | Health check endpoint          |
| GET    | `/metrics`                           | No   | Prometheus metrics             |

---

## Appendix: Error Codes

| Code | Meaning                                     |
| ---- | ------------------------------------------- |
| 400  | Invalid request / bound exceeded            |
| 401  | Missing or invalid Bearer token             |
| 403  | Issuer does not own the list                |
| 404  | Status list not found                       |
| 406  | Unsupported Accept header                   |
| 409  | Resource already exists / concurrent update |
| 413  | Request body too large                      |
| 422  | Serialized list too large / unparsable JWK  |
| 429  | Rate limit quota exhausted                  |
| 500  | Internal server error                       |
| 503  | Service unavailable                         |

---

## Further Reading

- [Secrets Risk: ESO vs Workload Identity](secrets-risk-eso-vs-workload-identity.md)
- [Database Backend Guidance](docs/database-backends.md)
- [Observability Guide](docs/observability.md)
- [DNS Provider Setup](docs/dns-providers.md)
- [Secrets Backend Guidance](docs/secrets-backends.md)
- [Helm Deployment Guide](helm/README.md)
- [Deployment Runbook](docs/deployment-runbook.md)
