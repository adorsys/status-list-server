<!-- markdownlint-disable MD013 MD060 -->

# Supply-Chain Attack

**Baseline:** `adbe8fdacae5edb1ce655a14a5f5f2120ea229e3` (`HEAD`).

## Areas

| Area | Finding and Consequences |
|---|---|
| Use Digests for Docker | The Dockerfile uses mutable builder-image tags. Use digest-pinned builder images instead. **PoC:** [Static check 9: Docker builder images](#static-check-9-docker-builder-images). |
| Building immutable image, deploying a mutable tag | Deployment uses a short Git SHA-derived OCI tag. A SHA-derived tag can look immutable, but OCI tags are mutable unless registry immutability is enforced; no such policy is present in this repository. Someone with GHCR package permissions could later repoint that tag. Capture the digest from `docker/build-push-action`, expose it as `image_digest`, and deploy the image using that digest. Tags are for humans; digests are the security identity. **PoC:** [Static checks 4 and 5: image deployment](#static-checks-4-and-5-image-deployment). |
| AWS OIDC is enabled, but not used in the deployment job | The deployment job requests `id-token: write`, but it configures AWS using `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. This creates a large blast radius for supply-chain attacks. Use GitHub OIDC with temporary AWS credentials and a constrained `role-to-assume`. **PoC:** [Static check 3: AWS deployment identity](#static-check-3-aws-deployment-identity). |
| Zizmor scanner does not break deployment | The CI workflow suppresses Zizmor failure with `true`. Every Zizmor finding therefore produces a successful Zizmor job. The deployment workflow also does not depend on the CI workflow. The exact command is shown below. **PoC:** [Static check 7: Zizmor](#static-check-7-zizmor). |

### Use Digests for Docker

The Dockerfile uses:

```dockerfile
FROM --platform=$BUILDPLATFORM blackdex/rust-musl:x86_64-musl AS builder-amd64
FROM --platform=$BUILDPLATFORM blackdex/rust-musl:aarch64-musl AS builder-arm64
```

Use digest-pinned builder images:

```dockerfile
FROM --platform=$BUILDPLATFORM \
  blackdex/rust-musl:x86_64-musl@sha256:<AMD64-BUILDER-DIGEST> \
  AS builder-amd64
FROM --platform=$BUILDPLATFORM \
  blackdex/rust-musl:aarch64-musl@sha256:<ARM64-BUILDER-DIGEST> \
  AS builder-arm64
```

### Building Immutable Image, Deploying A Mutable Tag

Deployment is done using:

```bash
kubectl set image deployment/... \
  status-list-server=ghcr.io/.../status-list-server:sha-${SHORT_SHA}
```

Capture the digest from `docker/build-push-action` as `image_digest` and deploy
using `ghcr.io/.../status-list-server@sha256:<IMAGE-DIGEST>`.

### AWS OIDC Is Enabled, But Not Used In The Deployment Job

The deployment workflow requests:

```yaml
permissions:
  contents: read
  id-token: write
```

But it uses static credentials:

```yaml
with:
  aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
  aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

### Zizmor Scanner Does Not Break Deployment

```yaml
- name: Run Zizmor
  run: zizmor .github/workflows/ || true
```
