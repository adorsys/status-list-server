# Deployment Runbook

This runbook describes the GitHub Actions deployment flow for the Status List Server Helm chart on AWS EKS.

## Deployment Flow

The deploy workflow is `.github/workflows/deploy.yml`. It runs on pushes to `main` and tags matching `v*.*.*`.

Every deploy run first executes the reusable CI workflow, builds and pushes a multi-architecture image to GHCR, then deploys the Helm chart with the image tag selected for the target environment.

### Staging

Pushes to `main` deploy to:

- GitHub environment: `staging`
- Kubernetes namespace: `statuslist-staging`
- Helm release: `statuslist`
- Image tag: `sha-<short_sha>`

The staging deploy command is equivalent to:

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist-staging \
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
helm status statuslist -n statuslist-staging
helm history statuslist -n statuslist-staging
kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist-staging
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist-staging --tail=100
```

For production, replace `statuslist-staging` with `statuslist-production`.

Smoke-check the running service:

```bash
kubectl get pods -n statuslist-production
kubectl describe pod -l app.kubernetes.io/name=status-list-server -n statuslist-production
kubectl exec deploy/statuslist-status-list-server-deployment -n statuslist-production -- test -r /home/nobody/.aws/credentials
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

Use the same commands with `-n statuslist-staging` for staging.

## Failure Triage

### OIDC Denied

Symptoms:

- `configure-aws-credentials` fails before `aws eks update-kubeconfig`.
- AWS STS reports that the role cannot be assumed.

Check:

- The GitHub environment name matches the IAM trust subject.
- `AWS_DEPLOY_ROLE_ARN` exists in the selected environment.
- The role trust references this repository and the correct branch or tag pattern.
- The IAM OIDC provider for GitHub Actions and the trust policy for this repository are configured.

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

> **Note:** The preferred authentication path for pods is IRSA (IAM Role for Service Accounts), which eliminates the need for credential files. The credential mount check below applies only when IRSA is not yet in place.

- The chart mounts credentials at `/home/nobody/.aws` (unless IRSA is already configured).
- The pod runs as the configured non-root user.
- The mounted secret contains the expected files.
- The IAM permissions behind the credentials cover the configured AWS operations.

## Helm Chart Requirements

Before deploying to a production namespace, the chart must include production-ready probes, resource requests and limits, a network policy, a non-root security context, and a compatible AWS credentials configuration (IRSA is preferred; credential files via secret mount are supported as a fallback).

If these are missing, deployments may fail readiness, fail security scans, or start pods that cannot access AWS services.

## Release Tagging

Production deploys only trigger for tags matching `v*.*.*`. The workflow strips the leading `v` and uses the remaining version string as the image tag. Ensure release tags are created correctly — if tags are not pushed after merging the release PR, the production deploy workflow will not run.
