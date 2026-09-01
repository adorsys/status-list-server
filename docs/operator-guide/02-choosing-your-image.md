# 02 — Choosing your image

The Status List Server is published as several **image variants**, one per
cryptographic-material backend. Each variant is a build of the same binary with a
different set of Cargo `FEATURES` enabled at compile time, which determines which
cloud/Vault secret backend is available for **Status List Token signing credentials** and
for ACME certificate provisioning. Choose the variant that matches where you already
store secrets and what DNS provider you use.

> [!IMPORTANT]
> The image variant only controls where the server stores/reads its **signing key and
> issuer certificate material** (see [05-token-signing-credentials.md](05-token-signing-credentials.md)).
> It does **not** control where ESO stores your database password or cloud credentials —
> that is governed by the Helm `secretStore.provider`, which is orthogonal and covered in
> [03-helm-installation.md](03-helm-installation.md). You can, for example, run the
> `-fscert` image (filesystem token-signing material) while ESO delivers the database
> password from Vault.

## 1. The five variants

| Image tag suffix | Enabled features                     | Token-signing & cert material backend                                                             | Best when                                                                                                                            |
| ---------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `-aws`           | `postgres,aws-secrets,acme`          | AWS Secrets Manager + Route53 DNS-01 for ACME                                                     | You run EKS and already keep secrets in AWS Secrets Manager                                                                          |
| `-gcp`           | `postgres,gcp-secrets,acme`          | GCP Secret Manager + Google Cloud DNS for ACME                                                    | You run GKE and keep secrets in GCP Secret Manager                                                                                   |
| `-azure`         | `postgres,azure-kv,acme`             | Azure Key Vault + Azure DNS for ACME                                                              | You run AKS and keep secrets in Azure Key Vault                                                                                      |
| `-vault`         | `postgres,vault,acme`                | HashiCorp Vault / OpenBao KV v2 (AppRole or Kubernetes auth)                                      | You operate your own Vault/OpenBao and want no cloud dependency                                                                      |
| `-fscert`        | `postgres` (no cloud secret feature) | Filesystem-mounted signing key and certificate (`PROVISIONING_STRATEGY=store` + filesystem paths) | You deliver the signing key and certificate as files (sealed secrets, mounted CSI, or a key escrow process); smallest attack surface |

> [!NOTE]
> "Feature set" in the table is the **crypto-material/ACME** surface. Every variant still
> supports the full application feature set (status-list operations, JWT/CWT signing,
> observability). The variants differ only in which secret backend the binary links in.

## 2. Reference a variant

Images are tagged `<version>-<suffix>` under `ghcr.io/adorsys/status-list-server`, for
example `0.6.0-aws`, `0.6.0-vault`. Set the image in your values:

```yaml
statuslist:
  image:
    repository: ghcr.io/adorsys/status-list-server
    tag: "0.6.0-aws" # or -gcp, -azure, -vault, -fscert
```

For production, pin by digest (see [03-helm-installation.md](03-helm-installation.md)):

```bash
--set-string statuslist.image.repository=ghcr.io/adorsys/status-list-server \
--set-string statuslist.image.tag=0.6.0-vault \
--set-string statuslist.image.digest=sha256:<digest>
```

### What if I do not see suffix tags for my version?

Multi-variant image publishing is wired into the release pipeline. If a specific suffix
for your target version is missing from the registry, use the closest variant whose
backend matches your environment or build locally from `Dockerfile` with the matching
`FEATURES` build-arg:

```bash
docker build --build-arg FEATURES="postgres,vault,acme" \
  -t status-list-server:vault .
```

## 3. Decision flow

1. **Do you operate your own Vault/OpenBao?** → `-vault`. It is cloud-agnostic and
   recommended when you want the signing material off any single cloud provider.
2. **Otherwise, which cloud already holds your secrets?**
   - AWS → `-aws`
   - GCP → `-gcp`
   - Azure → `-azure`
3. **Do you want the smallest possible binary and will you deliver the key/cert as
   files?** → `-fscert`. Use this when the signing key and issuer certificate are
   provisioned as filesystem paths (e.g. an offline escrow, a sealed-secret injector,
   or a CSI driver that mounts the material) rather than read from a cloud/Vault API.
4. **Local development / the bundled Postgres** → either `-aws` (chart default) or
   `-fscert` with a self-signed key file. See the local install in
   [03-helm-installation.md](03-helm-installation.md).

## 4. Feature-set details by variant

### `-aws` (AWS Secrets Manager + Route53)

- ACME DNS-01 via Route53 (`APP_SERVER__CERT__DNS__PROVIDER=route53`).
- Signing key and certificate stored/read in AWS Secrets Manager.
- Requires AWS credentials (IRSA or ESO-mounted files) with Secrets Manager access
  (and Route53 `ChangeResourceRecordSets` if ACME DNS-01 is used).
- Env: `APP_AWS__REGION`, plus AWS SDK env (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SHARED_CREDENTIALS_FILE`/`AWS_CONFIG_FILE` when mounted files are used).

### `-gcp` (GCP Secret Manager + Google Cloud DNS)

- ACME DNS-01 via Google Cloud DNS.
- Signing key and certificate stored/read in GCP Secret Manager.
- Uses Application Default Credentials (ADC); needs Secret Manager accessor roles.
- Env: `APP_GCP_SECRET_MANAGER__PROJECT_ID`, optional service-account key vars.

### `-azure` (Azure Key Vault + Azure DNS)

- ACME DNS-01 via Azure DNS.
- Signing key and certificate stored/read in Azure Key Vault.
- Uses Azure identity (Workload Identity, managed identity, or service principal).
- Env: `APP_AZURE_KEYVAULT__VAULT_URL`, `APP_AZURE_KEYVAULT__TENANT_ID`,
  `APP_AZURE_KEYVAULT__CLIENT_ID`, `APP_AZURE_KEYVAULT__CLIENT_SECRET`.

### `-vault` (HashiCorp Vault / OpenBao)

- Signing key and certificate stored/read in a KV v2 engine.
- Auth via AppRole or Kubernetes (`APP_VAULT__AUTH_METHOD`).
- Full IAM/Vault policy and auth setup: see
  [docs/secrets-backends.md](../secrets-backends.md).

### `-fscert` (filesystem-mounted)

- **No** cloud or Vault secret SDK is linked in — the smallest possible image.
- Token signing identity is loaded from two files:
  - `APP_SERVER__CERT__STORE__CERTIFICATE_PATH` — PEM/DER issuer certificate chain.
  - `APP_SERVER__CERT__STORE__SIGNING_KEY_PATH` — PKCS#8 PEM/DER private signing key.
- Set `APP_SERVER__CERT__PROVISIONING_STRATEGY=store` (not `acme`).
- You are responsible for provisioning and rotation of the files (see
  [06-secret-rotation.md](06-secret-rotation.md)).

## 5. Backend security notes

- Every variant runs the binary as non-root (UID 65534), on a scratch image, with a
  read-only root filesystem and no shell.
- Prefer short-lived cloud credentials (Workload Identity / IRSA) over mounted static
  files; weigh the trade-offs in
  [docs/secrets-risk-eso-vs-workload-identity.md](../secrets-risk-eso-vs-workload-identity.md).
- The signing key is the crown jewel: it lets an attacker mint valid-looking Status List
  Tokens for lists they do not own. Scope its backend access to least privilege only.
