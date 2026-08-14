# Deployment Runbook

This runbook describes the GitHub Actions deployment flow for the Status List Server Helm chart on AWS EKS.

## Deployment Flow

The deploy workflow is `.github/workflows/deploy.yml`. It runs on pushes to `main` and tags matching `v*.*.*`.

Every deploy run first executes the reusable CI workflow, builds and pushes a multi-architecture image to GHCR, then deploys the Helm chart with the image tag selected for the target environment.

### Staging

Pushes to `main` deploy to:

- GitHub environment: `staging`
- Kubernetes namespace: `staging`
- Helm release: `statuslist`
- Image tag: `sha-<short_sha>`

The staging deploy command is equivalent to:

```bash
helm upgrade --install statuslist helm/chart \
  --namespace staging \
  --create-namespace \
  --atomic \
  --wait \
  --timeout 10m \
  --set-string statuslist.image.repository=ghcr.io/adorsys/status-list-server \
  --set-string statuslist.image.tag=sha-<short_sha>
```

### Production

Release tags matching `v*.*.*` deploy to:

- GitHub environment: `production`
- Kubernetes namespace: `production`
- Helm release: `statuslist`
- Image tag: semantic version without the leading `v`

For example, tag `v0.5.0` deploys image tag `0.5.0`.

The production deploy command is equivalent to:

```bash
helm upgrade --install statuslist helm/chart \
  --namespace production \
  --create-namespace \
  --atomic \
  --wait \
  --timeout 10m \
  --set-string statuslist.image.repository=ghcr.io/adorsys/status-list-server \
  --set-string statuslist.image.tag=0.5.0
```

Configure the GitHub `production` environment with required reviewers so production deploys pause for approval before AWS credentials are requested.

## Required GitHub and AWS Setup

Create GitHub environments named `staging` and `production`. Each environment must expose:

- `AWS_DEPLOY_ROLE_ARN`: IAM role ARN assumed by the deploy job through GitHub OIDC.

Configure environment protection rules:

- `staging`: allow deployments from the `main` branch.
- `production`: allow deployments from protected release tags matching `v*.*.*` and require reviewers.

The deploy job requires:

- GitHub Actions permission `id-token: write`
- IAM trust for `token.actions.githubusercontent.com`
- AWS permission to describe the EKS cluster and perform the Kubernetes operations needed by Helm

Recommended OIDC trust subjects:

- Staging: `repo:adorsys/status-list-server:environment:staging`
- Production: `repo:adorsys/status-list-server:environment:production`

When a GitHub Actions job uses an environment, GitHub's default OIDC `sub` claim references the environment name. Keep branch and tag scoping in the GitHub environment protection rules. For repositories using immutable OIDC subject claims, adjust the `repo:` prefix to the immutable owner and repository ID format shown by GitHub.

## Verification

After a deploy, verify the Helm release and Kubernetes rollout:

```bash
helm status statuslist -n staging
helm history statuslist -n staging
kubectl rollout status deployment/statuslist-status-list-server-deployment -n staging
kubectl logs -l app.kubernetes.io/name=status-list-server -n staging --tail=100
```

For production, replace `staging` with `production`.

Smoke-check the running service:

```bash
kubectl get pods -n production
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n production
kubectl exec deploy/statuslist-status-list-server-deployment -n production -- test -r /home/nobody/.aws/credentials
```

If certificate provisioning or AWS-backed storage is enabled, also confirm the app can reach AWS services by checking application logs for successful S3, Secrets Manager, or certificate renewal operations.

## Rollback

There are two rollback paths:

- Failed upgrade rollback is automatic. The deploy workflow uses `--atomic --wait --timeout 10m`, so Helm rolls back during the pipeline when an upgrade fails readiness or times out.
- Successful-but-bad deploy rollback is manual. If a release passes the pipeline but later proves unhealthy or incorrect, an operator must choose a previous Helm revision and run `helm rollback`.

List available revisions:

```bash
helm history statuslist -n production
```

Rollback to a known-good revision:

```bash
helm rollback statuslist <revision> -n production --wait --timeout 10m
kubectl rollout status deployment/statuslist-status-list-server-deployment -n production
```

Use the same commands with `-n staging` for staging.

## Failure Triage

### OIDC Denied

Symptoms:

- `configure-aws-credentials` fails before `aws eks update-kubeconfig`.
- AWS STS reports that the role cannot be assumed.

Check:

- The GitHub environment name matches the IAM trust subject.
- `AWS_DEPLOY_ROLE_ARN` exists in the selected environment.
- The role trust references this repository and the correct branch or tag pattern.
- Issue #236 infrastructure has been merged and applied.

### Helm Timeout

Symptoms:

- `helm upgrade --install` fails after `--timeout 10m`.
- Helm reports the release rolled back because `--atomic` is enabled.

Check:

```bash
helm history statuslist -n <namespace>
kubectl get pods -n <namespace>
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n <namespace>
kubectl logs -l app.kubernetes.io/name=status-list-server -n <namespace> --tail=200
```

### Image Pull Failure

Symptoms:

- Pods show `ImagePullBackOff` or `ErrImagePull`.

Check:

- The workflow pushed the expected GHCR tag.
- Staging uses `sha-<short_sha>`.
- Production uses the semver tag without the leading `v`.
- The cluster can pull from GHCR.

### Readiness Failure

Symptoms:

- Helm waits until timeout.
- Pods are running but not ready.

Check:

- `/health/ready` responses in pod logs.
- PostgreSQL and optional Redis readiness.
- ExternalSecret and SecretStore status.
- Application configuration injected through Helm values.

### AWS Credential or Certificate Access Failure

Symptoms:

- The app starts but fails S3, Secrets Manager, Route53, or certificate operations.
- Logs mention missing AWS credentials or permission denied.

Check:

- The chart mounts credentials at `/home/nobody/.aws`.
- The pod runs as the configured non-root user.
- The mounted secret contains the expected files.
- The IAM permissions behind the credentials cover the configured AWS operations.

## Deferred / External Prerequisites

The following work is intentionally not implemented by issue #248.

### TODO: Issue #236 - OIDC IAM Role and Environment Setup

Owner: issue #236.

Issue #248 depends on this work. The deploy workflow expects environment-scoped `AWS_DEPLOY_ROLE_ARN` secrets and IAM roles that trust GitHub OIDC subjects for `staging` and `production`.

If this is missing, deploy jobs fail during `configure-aws-credentials` or `aws eks update-kubeconfig`.

### TODO: Issue #239 - Helm Chart Hardening

Owner: issue #239.

Issue #248 depends on the chart hardening remaining present on the target branch. The chart must include production-ready probes, resource requests and limits, network policy, non-root security context, and the non-root-compatible AWS credential mount.

If this is missing, deployments may fail security checks, fail readiness, or start pods that cannot read AWS credentials.

### TODO: Issue #247 - Release-plz Tag Behavior

Owner: issue #247.

Issue #248 depends on release tags being created correctly. Production deploys only run for tags matching `v*.*.*`, and the workflow deploys the matching semver image tag without the leading `v`.

If this is missing, production deploys will not start automatically after a release, or the workflow may not find the expected image tag.
