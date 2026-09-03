# Deployment Runbook

This runbook describes the GitHub Actions deployment flow for the Status List Server Helm chart on AWS EKS.

## Deployment Flow

The deploy workflow is `.github/workflows/deploy.yml`. It runs on release tags matching `v*.*.*` and on manual dispatch — **not** on pushes to `main`, and not on pull requests. A two-architecture build plus scan costs roughly 40 minutes and publishes to GHCR, so it is spent per release rather than per merge.

- Release tags matching `v*.*.*` run CI, build, push, scan, promote the release tags, and deploy to the production cluster.
- Manual dispatch exercises the build, scan and assertion path without promoting or deploying anything. It does still push the `sha-<short_sha>` tag to GHCR — a dispatch run publishes an image, it just never advertises or ships one.

`promote-tags` and `deploy` require `github.event_name == 'push'` in addition to a `refs/tags/v*` ref. That matters because `workflow_dispatch` accepts any ref including a tag, through both the ref picker and the REST API, so a ref test on its own would not make dispatch the non-releasing path it is documented to be.

Because the workflow does not run on pull requests, anything it is the only check for — the builder-stage audit assertion, the image scan itself — first fails during a release. Use manual dispatch to exercise the path before tagging when a change touches the `Dockerfile` or the scan job.

## How It Works

Every workflow run first executes the reusable CI workflow, then builds and pushes a multi-architecture image to GHCR under its commit SHA tag, then scans that image by digest. Release tag runs then promote the scanned digest to the release tags and deploy the Helm chart to production.

The scan job blocks both promotion and deployment. A release tag whose image fails an assertion builds and pushes, but the semver and `latest` tags are never applied to it and it never reaches production — so a rejected artifact is reachable only by its commit SHA, never as an advertised release. See [Container Supply Chain](supply-chain.md) for thresholds and triage.

The vulnerability gate blocks on any HIGH or CRITICAL finding that survives the exception ledger, as do the assertions around it. Each run also proves the gate can still fail, against a fixture, before treating a clean scan as meaningful. See the supply chain guide for thresholds and triage.

### Image Tags

The release workflow publishes **5 multi-arch image variants** with distinct suffixes for different cloud providers and secret storage models. See the image variant matrix in `values.yaml` for the full description of each variant. The chart's empty-tag default resolves to the provider-neutral filesystem certificate-store variant (`-fscert`), not to an unsuffixed image tag. AWS production deployments select the `-aws` image explicitly through their values and deploy inputs.

| Trigger              | Image Tags                                                             | Applied               |
| -------------------- | ---------------------------------------------------------------------- | --------------------- |
| Manual dispatch      | `sha-<short_sha>-<variant>`                                            | At build              |
| Release tag `v*.*.*` | `sha-<short_sha>-<variant>`                                            | At build              |
| Release tag `v*.*.*` | `<version>-<variant>`, `<major>.<minor>-<variant>`, `latest-<variant>` | After the scan passes |

Where `<variant>` is one of: `aws`, `gcp`, `azure`, `vault`, `fscert`.

Examples for tag `v1.2.0`:

- Version tags: `1.2.0-aws`, `1.2.0-gcp`, `1.2.0-azure`, `1.2.0-vault`, `1.2.0-fscert`
- Short version tags: `1.2-aws`, `1.2-gcp`, `1.2-azure`, `1.2-vault`, `1.2-fscert`
- Latest tags: `latest-aws`, `latest-gcp`, `latest-azure`, `latest-vault`, `latest-fscert`

The `latest-<variant>` tags are only applied to official release tags, never to a dispatch run. This follows standard OCI/Docker distribution conventions where `latest` represents the latest stable release. `latest` is also withheld from prereleases: `v*.*.*` matches `v1.2.3-rc1`, so the tag is guarded on the ref name containing no `-`.

**Note:** No untagged or default image (e.g., plain `latest`) is published. Every image must be pulled with an explicit variant suffix.

Release tags are applied by the `promote-tags` job using `docker buildx imagetools create`, which copies manifest descriptors by digest. Nothing is rebuilt, and the promoted tags resolve to exactly the index that was scanned, attestations included — which that job asserts rather than assumes.

### Selecting an Image Variant

Choose the variant that matches your cloud provider and secret storage model:

| Variant   | Best For                            | Required Infrastructure                          |
| --------- | ----------------------------------- | ------------------------------------------------ |
| `-aws`    | AWS EKS deployments                 | AWS Secrets Manager, Route53 DNS                 |
| `-gcp`    | GCP GKE deployments                 | GCP Secret Manager, Cloud DNS                    |
| `-azure`  | Azure AKS deployments               | Azure Key Vault, Azure DNS                       |
| `-vault`  | Multi-cloud or on-prem              | HashiCorp Vault / OpenBao cluster                |
| `-fscert` | Air-gapped/constrained environments | Filesystem-mounted signing keys and certificates |

The `-fscert` image intentionally omits the `acme` Cargo feature so the filesystem-backed certificate provider is compiled in. Configure certificate and signing-key paths through the chart or environment when selecting this variant.

To select a variant, set the image tag with the appropriate suffix in your Helm values or deployment command:

```yaml
# values.yaml override
statuslist:
  image:
    tag: "1.2.0-vault" # Use Vault variant
```

### Production Deploy

Release tags matching `v*.*.*` deploy to:

- GitHub environment: `production`
- Kubernetes namespace: `statuslist-production`
- Helm release: `statuslist`
- Image tag: semantic version without the leading `v`

For example, tag `v0.5.0` deploys the AWS variant with image tag `0.5.0-aws`. The production deployment uses the `-aws` variant by default; other variants (`-gcp`, `-azure`, `-vault`, `-fscert`) can be selected by setting the `IMAGE_VARIANT` Actions variable in the `production` environment (e.g., `gcp`, `azure`, `vault`, `fscert`). The default is `aws`.

The production deploy command is equivalent to (using the AWS variant):

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist-production \
  -f helm/chart/values-production.yaml \
  --wait \
  --rollback-on-failure \
  --timeout 10m \
  --set-string statuslist.image.repository=ghcr.io/adorsys/status-list-server \
  --set-string statuslist.image.tag=0.5.0-aws \
  --set-string statuslist.image.digest=sha256:<digest>
```

To deploy a different variant, change the tag suffix (e.g., `0.5.0-gcp`, `0.5.0-azure`, `0.5.0-vault`, `0.5.0-fscert`).

The digest is what actually determines the running image. `statuslist.image.digest` takes precedence over `statuslist.image.tag` in the chart, so production runs the exact artifact CI scanned. The tag is still passed because it is what humans read in `helm history` and release notes. Leaving `digest` empty falls back to tag-based deployment, which is the default for local and manual installs.

Because of that precedence, do not run `helm upgrade --reuse-values` with only a changed tag. The stored digest still wins, so the upgrade reports success and changes nothing. Pass both values, or clear the digest with `--set statuslist.image.digest=null`.

A digest that is not `sha256:` followed by 64 hex characters fails at template time rather than becoming an `ImagePullBackOff` ten minutes into `helm upgrade --wait --rollback-on-failure`. `deploy` also refuses to run at all without a `sha256:` digest, so a deploy can never silently fall back to the mutable tag.

Configure the GitHub `production` environment with required reviewers so production deploys pause for approval before AWS credentials are requested.

## Required GitHub and AWS Setup

Create the GitHub `production` environment with:

- `AWS_DEPLOY_ROLE_ARN`: IAM role ARN assumed by the deploy job through GitHub OIDC.
- `APP_DATABASE_PORT`: database service port passed to Helm as `statuslist.env.APP_DATABASE__PORT` (for example `5432` for PostgreSQL).
- `IMAGE_VARIANT` (optional): image variant suffix to deploy (`aws`, `gcp`, `azure`, `vault`, `fscert`). Defaults to `aws`.
  Note: changing this selects a different compiled feature-set image; the deployment target remains AWS EKS.
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

If certificate provisioning or AWS-backed storage is enabled, also confirm the app can reach AWS services by checking application logs for successful Secrets Manager or certificate renewal operations.

## File-Based Secret Rotation

The Helm chart can mount Secrets as files and inject file-path environment variables, but zero-downtime reload depends on running an application image that contains the file watcher and pool/key reload behavior from issue #456. Without that image support, treat the chart values as preparatory and perform a controlled rollout after credential or key changes.

The chart exposes the database password through `APP_DATABASE__PASSWORD_FILE` by default, using `statuslist.secretMounts` to mount the configured Kubernetes Secret as a file. This avoids a pod that mounts a rotated password file while the application silently keeps using an older startup password from an environment variable.

The Deployment `checksum/secret` annotation tracks Helm-rendered ExternalSecret manifests. It rolls pods when the chart template or Helm values change, but it does not change when External Secrets Operator syncs new secret data from Vault, AWS, GCP, or Azure. Data-only rotations rely on Kubernetes Secret volume updates plus the application watcher, or on an explicit `kubectl rollout restart` for images without reload support.

Database credential rotation must be coordinated with the database owner. Create and validate the new credential in PostgreSQL while the old credential remains valid, publish the new value to the external secret store, wait for ESO refresh plus watcher polling plus validation, and revoke the old credential only after every replica is healthy on the new pool. Roll back by restoring the old external secret value before the old database credential is revoked.

## Rollback

There are two rollback paths:

- Failed upgrade rollback is automatic. The deploy workflow uses `--wait --rollback-on-failure --timeout 10m`, so Helm rolls back during the pipeline when an upgrade fails readiness or times out.
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
- Helm reports the release rolled back because `--rollback-on-failure` is enabled.

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

- The workflow pushed the expected GHCR tag with the semver format and variant suffix (e.g., `0.5.0-aws`, not just `0.5.0`).
- The tag includes the correct variant suffix for your deployment.
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

### Image Assertion Failure

Symptoms:

- `Scan Image for Vulnerabilities` fails at `Assert published SBOMs list Rust crates`, or at `Resolve the architecture manifest to scan`.
- The image exists in GHCR under its `sha-<short_sha>` tag, but the release tags were never applied and `Deploy to Production` is skipped.

Check:

- The run artifacts and the job summary. Reports and SBOMs are uploaded before the assertion runs, so a failure here still leaves the full report attached to the run. They arrive as two artifacts per variant: `container-scan-reports-<variant>` and `container-sboms-<variant>` (e.g., `container-scan-reports-aws`, `container-sboms-aws`).
- For an SBOM failure, whether the builder-stage audit assertion also changed behaviour recently. An empty published SBOM with a passing build assertion points at BuildKit's cataloguer, not at the binary.
- For a resolution failure, the message names how many `linux/amd64` manifests were found in the index. Zero means the build stopped producing that platform; more than one means the index is not shaped the way this pipeline assumes. Neither is a scanner problem.

### Vulnerability Gate Findings

Symptoms:

- `Vulnerability gate` fails, the summary lists the blocking advisories, and the release tags are never applied.

Check:

- `trivy-gate-findings-<arch>.json` in the `container-scan-reports` artifact is the exact blocking set for that architecture. The gate's table is rendered from those same files, so the summary count and the table cannot disagree.
- The summary reports distinct advisories and package occurrences separately. One CVE affecting three crates is three rows in the table and one thing to triage.
- Whether the advisory is already argued in `deny.toml`. The two ledgers are not connected, so a release can block on something `cargo-deny` has been ignoring deliberately.

Triage steps and the exception format are in [Container Supply Chain](supply-chain.md). Fix it at the lockfile if a fix exists; add a dated ledger entry only if one does not.

### Gate Self-Test Failure

Symptoms:

- `Prove the gate can fail` fails with "the vulnerability gate cannot fail and is not protecting this release".

Check:

- This is not a finding about the image. It means `scripts/vuln-gate.sh` returned success against a fixture that contains a CRITICAL, so the gate would have passed the real scan no matter what was in it.
- Likely causes: `--exit-code` was changed or dropped in `scripts/vuln-gate.sh`, or a Trivy upgrade changed `convert`'s exit-code behaviour.
- Do not work around it by skipping the step. A release cut while this is failing has an unverified gate.

### Tag Promotion Failure

Symptoms:

- `Promote Scanned Digest to Release Tags` fails for one or more variants, and the release exists in GHCR only as `sha-<short_sha>-<variant>`.
- `Deploy to Production` is skipped because it depends on promotion.

Check:

- Whether `Verify attestations survived promotion` is the failing step. That means the retag succeeded but the SBOM or provenance manifests did not carry through, which would publish a release whose metadata silently vanished.
- The failing variant's matrix job logs to see which specific suffix (`-aws`, `-gcp`, etc.) failed.
- Re-running the job is safe: `imagetools create` is idempotent for a given digest and tag set. **Re-run `promote-tags` alone** — `deploy` depends on it, so a successful re-run unblocks production without cutting a new release. A promotion failure is not a reason to re-tag the repository.

### Builder Audit Assertion Failure

Symptoms:

- The image build fails in the builder stage at the `rust-audit-info` assertion, or at the `cargo install` layer above it, on a commit that changed nothing relevant.

Check:

- This means the binary no longer carries readable `.dep-v0` audit data, usually because the floating stable toolchain drifted away from the pinned `cargo-auditable` version. Bump `CARGO_AUDITABLE_VERSION` and `RUST_AUDIT_INFO_VERSION` in the `Dockerfile`.
- The assertion is deliberate. Without it the build would succeed and publish an empty SBOM.

## External Dependencies

- **Issue #236**: OIDC IAM role and GitHub environment setup must be completed before first deploy.
- **Issue #239**: Chart hardening (IRSA migration of cert-manager/Route53 credentials) is pending.

## Redis Removal Cleanup (breaking change)

This chart no longer deploys the Redis HA subchart (`redis-ha`), its application
env vars, its NetworkPolicy rules, or its TLS-sync CronJob. If a previous release
was deployed with `redis-ha.enabled=true`, the removal of the subchart **orphans**
Kubernetes resources that Helm does not delete. Clean these up as an ops action
item before/after the first deploy that carries this chart:

1. **`statuslist-haproxy-tls` secret** — this secret holds the TLS key (`redis.pem`)
   for the Redis HAProxy load balancer, including the **production wildcard private
   key**. Because it may contain the production private key, treat it as sensitive
   and verify it is no longer referenced by any live HAProxy before deleting. Delete
   it only after confirming no running Redis HAProxy service depends on it:

   ```bash
   kubectl delete secret statuslist-haproxy-tls -n statuslist-production
   ```

2. **Redis HA persistent volume claims** — the Redis HA subchart provisions PVCs
   (e.g. `status-list-server-redis-ha-pvc-*` / release-scoped claims). These retain
   any persisted Redis data and storage. Delete the claims (and, if you no longer
   need the data, the underlying PVs / storage volumes):

   ```bash
   kubectl get pvc -n statuslist-production | grep redis
   kubectl delete pvc -l release=statuslist,app=redis-ha -n statuslist-production
   ```

   Confirm the backing volumes are released before removing them to avoid data loss.

There is no code change required for this cleanup; it is purely an operational step
that must be performed once when adopting this chart version.
