# Status List Server — Operator Deployment & Operations Guide

This guide empowers infrastructure engineers to deploy, configure, and maintain the
**Status List Server** across Kubernetes environments **without reading source code**.
Everything here is task-oriented and backed by copy-pasteable `helm` and `kubectl`
commands. The chart referenced throughout is `helm/chart` in this repository and the
published container image is `ghcr.io/adorsys/status-list-server`.

> [!IMPORTANT]
> **Two completely different kinds of "certificates".** This server deals with two
> unrelated credential families and it is easy to confuse them:
>
> 1. **Status List Token signing credentials** (JWT/CWT) — the private signing key and
>    issuer certificate used to cryptographically sign Status List Tokens. This is the
>    server's core identity. Covered in [05-token-signing-credentials.md](05-token-signing-credentials.md).
> 2. **Network TLS** — the certificate used by the Kubernetes **ingress** to terminate
>    HTTPS for external clients. This is ordinary TLS handled by your ingress controller
>    / cert-manager, entirely separate from token signing.
>
> When running ACME, the server _also_ provisions an ACME-issued certificate for its own
> exposed API — but even that is **not** the ingress TLS and must not be confused with the
> ingress certificate. Sections [05](05-token-signing-credentials.md) and
> [06](06-secret-rotation.md) make the distinction explicit.

## What the server does

The Status List Server implements the IETF **Token Status List** specification
([draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)).
Credential issuers register, publish, and update status lists; verifiers retrieve and
validate them. It signs Status List Tokens in either **JWT** or **CWT** format using
ECDSA, EdDSA, or RSA (data is stored encrypted at rest in a database; tokens are signed
with the configured signing key before each response).

Architecture context: see [docs/architecture.md](../architecture.md) for a detailed
hexagonal-architecture walkthrough.

## Guide map

| Guide                                                              | What it gives you                                                                   |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| [01-prerequisites.md](01-prerequisites.md)                         | Cluster, Helm, External Secrets Operator, and registry access requirements          |
| [02-choosing-your-image.md](02-choosing-your-image.md)             | Decision matrix for the 5 image variants and their feature sets                     |
| [03-helm-installation.md](03-helm-installation.md)                 | Step-by-step installs: EKS, GKE, AKS, Vault/OpenBao, filesystem credentials, local  |
| [04-configuration-reference.md](04-configuration-reference.md)     | Exhaustive reference of every `APP_*` environment variable and validation rule      |
| [05-token-signing-credentials.md](05-token-signing-credentials.md) | Status List token signing keys and issuer certificates vs. ingress TLS              |
| [06-secret-rotation.md](06-secret-rotation.md)                     | Zero-downtime rotation of keys, certificates, and Vault leases                      |
| [07-scaling-and-availability.md](07-scaling-and-availability.md)   | Connection pools, HPA, PodDisruptionBudgets, resource quotas                        |
| [08-observability.md](08-observability.md)                         | Prometheus metrics, rotation telemetry, OpenTelemetry, health endpoints             |
| [09-upgrading.md](09-upgrading.md)                                 | Version migrations, database schema migrations, Helm upgrade procedures             |
| [10-troubleshooting.md](10-troubleshooting.md)                     | Error-indexed troubleshooting: startup, rotation, ESO/Kubernetes, and upgrade fixes |

## Quick start (TL;DR)

The fastest full end-to-end path for a production-like local cluster:

```bash
# 1. Install External Secrets Operator (see 01-prerequisites.md)
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets --create-namespace

# 2. Deploy the chart with your provider (pick one from 03-helm-installation.md)
helm upgrade --install statuslist helm/chart \
  --namespace statuslist \
  --create-namespace \
  --values my-values.yaml \
  --wait --timeout 10m
```

Then verify (see [08-observability.md](08-observability.md)):

```bash
kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist
kubectl get pods -n statuslist
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist --tail=100
curl -s https://<your-host>/health/live
curl -s https://<your-host>/health/ready
```

If any step fails, jump to the error-indexed
[10-troubleshooting.md](10-troubleshooting.md) reference — it maps the exact error message
or symptom to its root cause, diagnostics, and fix.

## Files you should read before deploying

- `helm/chart/values.yaml` — the **single source of truth** for every Helm value.
  Every section of this guide references keys there.
- `helm/chart/values-local.yaml` — a working local/cluster reference configuration.
- `.env.template` — canonical list of application environment variables, mirrored in
  [04-configuration-reference.md](04-configuration-reference.md).
- Existing deep-dive docs:
  - [docs/deployment-architecture.md](../deployment-architecture.md) — the full technical architecture: build, CI/CD, Kubernetes topology, and Helm structure.
  - [docs/deployment-runbook.md](../deployment-runbook.md) — the GitHub Actions release/deploy flow.
  - [docs/secrets-risk-eso-vs-workload-identity.md](../secrets-risk-eso-vs-workload-identity.md) — the risk trade-offs between ESO-mounted credentials (chart default) and Workload Identity. **Read this before choosing in [03-helm-installation.md](03-helm-installation.md).**
  - [docs/secrets-backends.md](../secrets-backends.md) — backend-specific IAM/Vault details.
  - [docs/observability.md](../observability.md) — OpenTelemetry wiring and metric labels.
  - [docs/supply-chain.md](../supply-chain.md) — image scanning and SBOMs.

## How this guide relates to the existing docs

The existing `docs/deployment-runbook.md` documents the **GitHub Actions release pipeline**
that publishes and deploys the server. This operator guide is complementary: it is the
**human-centric, repeatable operations manual** an infrastructure engineer follows to
deploy to any Kubernetes environment (managed cloud, on-prem, or local), regardless of
whether they use the GitHub Actions pipeline.

## Conventions

- `statuslist` is the Helm release name used throughout the examples; substitute your own.
- All examples target namespace `statuslist` unless noted.
- `helm/chart` refers to the chart directory; run Helm commands from the repository root
  unless a `<chart-dir>` placeholder says otherwise.
- The application runs as non-root (UID `65534`, `nobody`) with a read-only root
  filesystem. Any path the app must write is an explicit mounted volume (e.g. `/tmp`).
