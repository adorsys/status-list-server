# Deployment Runbook

This runbook describes the GitHub Actions deployment flow for the Status List Server Helm chart on AWS EKS.

## Deployment Flow

The deploy workflow is `.github/workflows/deploy.yml`. It runs on pushes to `main` and release tags matching `v*.*.*`.

- Pushes to `main` run CI checks and build and push the Docker image to GHCR.
- Release tags matching `v*.*.*` deploy to the production cluster.

## How It Works

Every workflow run first executes the reusable CI workflow, builds and pushes a multi-architecture image to GHCR. Release tag runs then deploy the Helm chart with the semver image tag to production.

### Image Tags

| Trigger              | Image Tags                                                  |
|----------------------|-------------------------------------------------------------|
| Push to `main`       | `sha-<short_sha>`                                           |
| Release tag `v*.*.*` | `<major>.<minor>`, `<version>`, `sha-<short_sha>`, `latest` |

The `latest` tag is only applied to official release tags, not to intermediate commits from `main`. This follows standard OCI/Docker distribution conventions where `latest` represents the latest stable release.

### Production Deploy

Release tags matching `v*.*.*` deploy to:

- GitHub environment: `production`
- Kubernetes namespace: `statuslist-production`
- Helm release: `statuslist`
- Image tag: semantic version without the leading `v`

For example, tag `v0.5.0` deploys image tag `0.5.0`.

The production deploy command is equivalent to:

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist-production \
  --create-namespace \
  --atomic \
  --wait \
  --timeout 10m \
  --set-string statuslist.image.repository=ghcr.io/adorsys/status-list-server \
  --set-string statuslist.image.tag=0.5.0
```

Configure the GitHub `production` environment with required reviewers so production deploys pause for approval before AWS credentials are requested.

## Required GitHub and AWS Setup

Create the GitHub `production` environment with:

- `AWS_DEPLOY_ROLE_ARN`: IAM role ARN assumed by the deploy job through GitHub OIDC.
- Required reviewers: configure at least one approver.
- Deployment branches/tags: restrict to release tags matching `v*.*.*`.

The deploy job requires:

- GitHub Actions permission `id-token: write`
- IAM trust for `token.actions.githubusercontent.com`
- AWS permission to describe the EKS cluster and perform the Kubernetes operations needed by Helm

Recommended OIDC trust subject for production:

```text
repo:adorsys/status-list-server:environment:production
```

When a GitHub Actions job uses an environment, GitHub's default OIDC `sub` claim references the environment name. For repositories using immutable OIDC subject claims, adjust the `repo:` prefix to the immutable owner and repository ID format shown by GitHub.

## Verification

After a deploy, verify the Helm release and Kubernetes rollout:

```bash
helm status statuslist -n statuslist-production
helm history statuslist -n statuslist-production
kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist-production
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=100
```

Smoke-check the running service:

```bash
kubectl get pods -n statuslist-production
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n statuslist-production
```

If certificate provisioning or AWS-backed storage is enabled, also confirm the app can reach AWS services by checking application logs for successful S3, Secrets Manager, or certificate renewal operations.

## Rollback

There are two rollback paths:

- Failed upgrade rollback is automatic. The deploy workflow uses `--atomic --wait --timeout 10m`, so Helm rolls back during the pipeline when an upgrade fails readiness or times out.
- Successful-but-bad deploy rollback is manual. If a release passes the pipeline but later proves unhealthy or incorrect, an operator must choose a previous Helm revision and run `helm rollback`.

List available revisions:

```bash
helm history statuslist -n statuslist-production
```

Rollback to a known-good revision:

```bash
helm rollback statuslist <revision> -n statuslist-production --wait --timeout 10m
kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist-production
```

## Failure Triage

### OIDC Denied

Symptoms:

- `configure-aws-credentials` fails before `aws eks update-kubeconfig`.
- AWS STS reports that the role cannot be assumed.

Check:

- The GitHub environment name matches the IAM trust subject.
- `AWS_DEPLOY_ROLE_ARN` exists in the selected environment.
- The role trust references this repository and the correct branch or environment.
- OIDC IAM role has been created and applied (see issue #236).

### Helm Timeout

Symptoms:

- `helm upgrade --install` fails after `--timeout 10m`.
- Helm reports the release rolled back because `--atomic` is enabled.

Check:

```bash
helm history statuslist -n statuslist-production
kubectl get pods -n statuslist-production
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n statuslist-production
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-production --tail=200
```

### Image Pull Failure

Symptoms:

- Pods show `ImagePullBackOff` or `ErrImagePull`.

Check:

- The workflow pushed the expected GHCR tag with the semver format.
- The cluster can pull from GHCR.

### Readiness Failure

Symptoms:

- Helm waits until timeout.
- Pods are running but not ready.

Check:

- `/health/ready` responses in pod logs.
- PostgreSQL readiness.
- ExternalSecret and SecretStore status.
- Application configuration injected through Helm values.

## External Dependencies

- **Issue #236**: OIDC IAM role and GitHub environment setup must be completed before first deploy.
- **Issue #239**: Chart hardening (IRSA migration of cert-manager/Route53 credentials) is pending.
