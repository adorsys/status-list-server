# Secrets Risk: ESO-mounted Credentials vs Workload Identity

The Status List Server chart defaults to delivering credentials through **External Secrets Operator (ESO)** with mounted static credential files (`statuslist.aws.mountCredentials=true`). **Workload Identity** (EKS IRSA / GCP WI / AKS WIF) is the opt-in alternative. This document is a risk-oriented comparison of the two choices so operators can decide which trade-offs to accept for a given environment.

It does not argue that one is universally "better" — it lays out the threats, blast radius, and operational properties of each so the choice is explicit and informed.

## Scope: two different secrets layers

Do not confuse the two layers that both deal with "secrets":

- **ESO SecretStore / ExternalSecret** (the delivery mechanism): how a provider (AWS Secrets Manager, Vault, GCP, Azure, …) is turned into a Kubernetes `Secret` that the pod mounts. Selecting **ESO** or **Workload Identity** only changes *how the pod obtains the remote material*, not which material backend the application reads at runtime.
- **The application's crypto-material backend** (`APP_*__*`, e.g. AWS Secrets Manager, Vault/OpenBao, GCP Secret Manager, Azure Key Vault): where the application stores ACME account keys, signing keys, and certificate chains. This is selected by Cargo features and is independent of the delivery mechanism. See [Secrets Backend Guidance](secrets-backends.md).

The comparison below is about the **delivery** layer.

## What each option looks like in the chart

### ESO with mounted credentials (default)

```yaml
externalSecret:
  enabled: true
secretStore:
  enabled: true
  provider: aws
statuslist:
  aws:
    mountCredentials: true     # default; chart renders aws-credentials-secret
```

The ESO controller assumes a provider credential (for `aws` a Secrets Manager role/policy) and synchronizes remote values into Kubernetes `Secret` objects:

- `statuslist-external-secret` → `statuslist-secret` (holds `postgres-password`)
- `statuslist-external-secret-aws-credentials` → `aws-credentials-secret` (holds the application's AWS shared `credentials` + `config` files, mounted at `/home/nobody/.aws`)

### Workload Identity (opt-in)

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/status-list-server
statuslist:
  aws:
    mountCredentials: false    # no mounted credential files
```

The pod receives a short-lived, projected OIDC token bound to a cloud role (IRSA / GCP WI / AKS WIF). The application authenticates with ambient credentials; no static files are mounted.

## Threat comparison

| Threat property           | ESO mounted credentials (default)  | Workload Identity (opt-in)     |
| ------------------------- | ---------------------------------- | ------------------------------ |
| Secret at rest            | Static file + K8s Secret in etcd   | None; short-lived OIDC token   |
| Credential lifetime       | Until rotated / ESO re-sync        | Minutes-to-hours, auto per pod |
| Blast radius of one leak  | May span all synced secrets        | Scoped to the pod's own role   |
| Where the token lives     | On disk + in the Secret (etcd)     | Injected; not written to etcd  |
| Rotation model            | Operator rotates source + re-sync  | Automatic; no operator action  |
| Extra privileged identity | ESO controller holds provider cred | None for delivery              |
| Portability               | Any cluster / provider-neutral     | Requires platform WI plumbing  |

## Primary risks of choosing ESO

### 1. A second, privileged, long-lived credential

ESO's whole point is that a controller with provider access writes Kubernetes `Secrets`. That means a cluster without ESO now carries a credential (for `aws`, the role the controller assumes) that can read the referenced Secrets Manager/Parameter Store keys for every release it manages. Compromise of the ESO controller (or its credentials) is a single pivot point to all synced secrets.

Risk: **high**. It concentrates many secrets behind one identity.

### 2. Static, mounted credentials are longer-lived secrets at rest

With `mountCredentials=true` the application's AWS shared credential file is a real long-lived secret materialized on the pod filesystem and stored in a Kubernetes `Secret` (etcd). The blast radius of leaking `aws-credentials-secret` includes the live certificate infrastructure: Route 53 (ACME DNS-01), S3 (certificate storage). A leaked Workload Identity token expires on its own in roughly an hour; a mounted key does not.

Risk: **high** if the mounted key is broad; mitigated when the mounted key is scoped narrowly and rotated.

### 3. Health is only as good as the sync

The pod depends on ESO having successfully synced the Secret before (or independent of) pod start. If the `SecretStore` is misconfigured (wrong region, missing remote key) or the controller cannot assume its role, the pod stays unready. The application cannot self-heal a missing mount the way Workload Identity resolves credentials on demand at API-call time.

Risk: **medium** availability; an operator intervention (fix provider access / values, trigger a re-sync) is required.

### 4. Reconciliation and drift

ESO re-syncs on `refreshInterval` (default `30m`). Between rotations of the remote key and the next sync the pod runs a stale credential; the failure surfaces as a hard deployment/readiness problem at rotation boundaries unless the operator aligns the rotation with the sync schedule.

Risk: **medium**.

### 5. Secrets visible to cluster operators

Mounted credentials are ordinary Kubernetes `Secret`s. Anyone with `get` on Secrets (or etcd access) can read them. This broadens the set of people and processes who can retrieve the live credential material. Workload Identity keeps the material out of the `Secret` objects entirely.

Risk: **medium**; depends on your RBAC hygiene around Secrets.

## Risks of choosing Workload Identity

For balance, Workload Identity is not free of risk:

- **Platform coupling**: it only works on the cloud platform that provides the identity webhook (EKS/GKE/AKS/on-prem equivalents). Moving to a different platform or running on-prem requires reworking the credential model, whereas ESO-mounted files are platform-neutral.
- **IAM/Permissions sprawl**: you must maintain a role per workload (or per environment) and keep trust policies correct. A too-broad role recreates the same blast radius problem, just with shorter-lived credentials.
- **Token handling in-process**: the application's SDK must support the OIDC token path; a misconfigured `automountServiceAccountToken` or cloud admission webhook silently degrades authentication.
- **Harder static analysis / fewer "it's just a file" guarantees**: some operators prefer the explicit, inspectable mounted-file model.

## Recommendations

1. **Default is acceptable for low-risk/initial deployments**: ESO with mounted credentials is the chart default and is fine when the mounted key is **narrowly scoped** (least-privilege, e.g. only the specific Secrets Manager keys and S3/Route53 resources the server uses) and **rotated regularly**, with ESO's `refreshInterval` aligned to rotation.
2. **Prefer Workload Identity where you already use it or run cloud-native EKS/GKE/AKS**: the shorter-lived token and reduced secrets-at-rest surface meaningfully lower blast radius for the live certificate infrastructure.
3. **Regardless of choice**:
   - Scope the ESO provider role and the application role with least privilege (see the IAM examples in `helm/README.md`).
   - Restrict Kubernetes RBAC so only trusted operators can read `Secret`s and inspect pods.
   - Align the ESO `refreshInterval` with your provider-key rotation cadence.
   - Keep `automountServiceAccountToken=false` (the chart default) unless the pod genuinely needs the Kubernetes API token.
   - Harden the ESO controller namespace and its credential.

## Related

- [Deployment Runbook](deployment-runbook.md) — ESO-default deploy and verification steps.
- [Helm Deployment Guide](../helm/README.md) — chart values, opt-in Workload Identity migration.
- [Secrets Backend Guidance](secrets-backends.md) — the application's crypto-material backends.
