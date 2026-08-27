# Cryptographic Material Backend Guidance

The server stores lifecycle-coupled cryptographic material in one backend by default: ACME account keys, the server signing key, and the certificate chain associated with that key.

The supported backends include:

- **HashiCorp Vault / OpenBao** (KV v2 engine, feature flag: `vault`)
- **GCP Secret Manager** (feature flag: `gcp-secrets`)
- **Azure Key Vault** (feature flag: `azure-kv`)
- **AWS Secrets Manager** (feature flag: `aws-secrets`)
- **In-Memory** (for development and testing)

Backend selection is controlled by enabled Cargo features. Builds with `vault` use Vault/OpenBao. Builds with `aws-secrets` and without `vault` use AWS Secrets Manager. Builds without either backend feature use in-memory storage for local development and tests.

## HashiCorp Vault & OpenBao (KV v2)

Both HashiCorp Vault and OpenBao share the KV v2 REST API interface and are supported natively when the `vault` feature flag is enabled.

Authentication is supported via **AppRole** or **Kubernetes** auth methods:

- **AppRole**: Standard machine-to-machine authentication mechanism using `role_id` and `secret_id`.
- **Kubernetes**: Native pod authentication using Kubernetes ServiceAccount JWT tokens (`/var/run/secrets/kubernetes.io/serviceaccount/token`), avoiding the need to distribute static credentials.

### Configuration Variables

| Variable                                  | Type              | Default                                               | Description                                                              |
| ----------------------------------------- | ----------------- | ----------------------------------------------------- | ------------------------------------------------------------------------ |
| `APP_VAULT__AUTH_METHOD`                  | String            | `"approle"`                                           | Authentication method: `approle` or `kubernetes`                         |
| `APP_VAULT__ADDR`                         | String            | `http://127.0.0.1:8200`                               | Base URL of the Vault / OpenBao cluster                                  |
| `APP_VAULT__AUTH_MOUNT`                   | String            | `"approle"`                                           | Mount path of the AppRole auth engine (used when `auth_method=approle`)  |
| `APP_VAULT__ROLE_ID`                      | String            | `""`                                                  | AppRole Role ID identifier (required for `approle`)                      |
| `APP_VAULT__SECRET_ID`                    | String (Secret)   | `None`                                                | AppRole Secret ID credential (optional if path is used)                  |
| `APP_VAULT__SECRET_ID_PATH`               | Path              | `None`                                                | File path containing AppRole Secret ID (e.g. volume mount)               |
| `APP_VAULT__K8S_ROLE`                     | String            | `None`                                                | Vault Kubernetes auth role name (required when `auth_method=kubernetes`) |
| `APP_VAULT__K8S_TOKEN_PATH`               | Path              | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Path to projected ServiceAccount JWT token file                          |
| `APP_VAULT__K8S_AUTH_MOUNT`               | String            | `"kubernetes"`                                        | Mount path of the Kubernetes auth engine                                 |
| `APP_VAULT__MOUNT`                        | String            | `"secret"`                                            | KV v2 secrets engine mount point                                         |
| `APP_VAULT__PATH_PREFIX`                  | String            | `""`                                                  | Optional prefix prepended to all secret keys (e.g. `status-list-server`) |
| `APP_VAULT__NAMESPACE`                    | String            | `None`                                                | Optional Enterprise/OpenBao namespace header (`X-Vault-Namespace`)       |
| `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL` | Integer (seconds) | `300` (5 minutes)                                     | In-memory cache TTL in seconds. Set to `0` to disable caching.           |
| `APP_VAULT__TIMEOUT_SECS`                 | Integer (seconds) | `30`                                                  | HTTP request timeout duration in seconds                                 |

### Least-Privilege Vault / OpenBao Policy

Create a dedicated ACL policy for the status-list-server with minimal permissions on the KV v2 mount:

```hcl
# status-list-policy.hcl
# Allow full CRUD on data under the secrets path
path "secret/data/status-list-server/*" {
  capabilities = ["create", "read", "update", "delete"]
}

# Allow reading/deleting metadata for versions and keys
path "secret/metadata/status-list-server/*" {
  capabilities = ["read", "delete", "list"]
}

# Allow proactive token renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

Write the policy to Vault / OpenBao:

```bash
vault policy write status-list-policy status-list-policy.hcl
```

### Provisioning AppRole Credentials

1. **Enable AppRole auth engine**:

   ```bash
   vault auth enable approle
   ```

2. **Create the application role**:

   ```bash
   vault write auth/approle/role/status-list-role \
     token_policies="status-list-policy" \
     token_ttl=1h \
     token_max_ttl=4h \
     secret_id_ttl=0
   ```

3. **Retrieve the `role_id`**:

   ```bash
   vault read -field=role_id auth/approle/role/status-list-role/role-id
   ```

4. **Generate a `secret_id`**:

   ```bash
   vault write -f -field=secret_id auth/approle/role/status-list-role/secret-id
   ```

### Example 1: Local Development with HashiCorp Vault

Start a local Vault dev container:

```bash
docker run -d --name vault -p 8200:8200 -e 'VAULT_DEV_ROOT_TOKEN_ID=root' hashicorp/vault:2.0
```

Configure AppRole:

```bash
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"

vault auth enable approle
vault policy write status-list-policy - <<EOF
path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/token/renew-self" { capabilities = ["update"] }
EOF

vault write auth/approle/role/status-list-role \
  token_policies="status-list-policy" \
  token_ttl=1h

ROLE_ID=$(vault read -field=role_id auth/approle/role/status-list-role/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/status-list-role/secret-id)
```

Configure your `.env` file:

```env
APP_VAULT__ADDR=http://127.0.0.1:8200
APP_VAULT__AUTH_MOUNT=approle
APP_VAULT__ROLE_ID=your-role-id-here
APP_VAULT__SECRET_ID=your-secret-id-here
APP_VAULT__MOUNT=secret
APP_VAULT__PATH_PREFIX=dev/status-list
```

### Example 2: Production Deployment with OpenBao / Vault (AppRole)

In Kubernetes or ECS, inject the `role_id` and `secret_id` via Kubernetes Secrets or IAM-bound orchestration:

```env
APP_VAULT__AUTH_METHOD=approle
APP_VAULT__ADDR=http://openbao-service.openbao.svc.cluster.local:8200
APP_VAULT__AUTH_MOUNT=approle
APP_VAULT__ROLE_ID=ba0a1234-5678-90ab-cdef-1234567890ab
APP_VAULT__SECRET_ID=fe987654-3210-fedc-ba09-876543210fed
APP_VAULT__MOUNT=secret
APP_VAULT__PATH_PREFIX=production/status-list
APP_VAULT__NAMESPACE=my-org-namespace
```

### Example 3: Production Deployment with Kubernetes Authentication

When running inside a Kubernetes cluster, configure the server to authenticate using the pod's projected ServiceAccount token:

1. **Configure Vault Kubernetes Auth Engine**:

   ```bash
   vault auth enable kubernetes
   vault write auth/kubernetes/config \
     kubernetes_host="https://kubernetes.default.svc:443"

   vault write auth/kubernetes/role/status-list-role \
     bound_service_account_names="status-list-server" \
     bound_service_account_namespaces="default" \
     token_policies="status-list-policy" \
     token_ttl=1h
   ```

2. **Configure your pod environment**:

   ```env
   APP_VAULT__AUTH_METHOD=kubernetes
   APP_VAULT__ADDR=http://vault.vault.svc.cluster.local:8200
   APP_VAULT__K8S_ROLE=status-list-role
   APP_VAULT__K8S_TOKEN_PATH=/var/run/secrets/kubernetes.io/serviceaccount/token
   APP_VAULT__K8S_AUTH_MOUNT=kubernetes
   APP_VAULT__MOUNT=secret
   APP_VAULT__PATH_PREFIX=production/status-list
   ```

### Manual Testing with a Local Vault Dev Server (Kubernetes Auth)

To test the Kubernetes authentication workflow against a local Vault dev server:

1. **Start a local Vault dev server**:

   ```bash
   vault server -dev -dev-root-token-id="root" -dev-listen-address="127.0.0.1:8200"
   export VAULT_ADDR="http://127.0.0.1:8200"
   export VAULT_TOKEN="root"
   ```

2. **Enable and configure the Kubernetes auth method**:

   ```bash
   # Enable the Kubernetes auth engine
   vault auth enable kubernetes

   # Configure local/mock verification for dev/test environments
   vault write auth/kubernetes/config \
     kubernetes_host="https://127.0.0.1:6443" \
     disable_issuer_verification=true \
     disable_local_ca_jwt=true

   # Write policy and create a test role
   vault policy write status-list-policy status-list-policy.hcl
   vault write auth/kubernetes/role/status-list-role \
     bound_service_account_names="status-list-server" \
     bound_service_account_namespaces="default" \
     token_policies="status-list-policy" \
     token_ttl=1h
   ```

3. **Run the server with test credentials**:

   ```bash
   # Write your test ServiceAccount JWT token to a file
   echo "$TEST_SA_JWT" > /tmp/k8s-token.jwt

   # Run status-list-server with Vault Kubernetes auth
   APP_VAULT__AUTH_METHOD=kubernetes \
   APP_VAULT__ADDR=http://127.0.0.1:8200 \
   APP_VAULT__K8S_ROLE=status-list-role \
   APP_VAULT__K8S_TOKEN_PATH=/tmp/k8s-token.jwt \
   cargo run --features "vault,postgres,acme"
   ```

### Automated Token Lifecycle & Resilience

The server features an enterprise-grade automated token manager:

- **Initial Login**: Authenticates via `POST /v1/auth/{auth_mount}/login` at application startup (using AppRole credentials or projected Kubernetes SA JWT).
- **Proactive Renewal**: Tokens are automatically renewed via `POST /v1/auth/token/renew-self` when 80% of their lease TTL has elapsed.
- **Re-authentication Fallback**: If renewal fails (e.g. token expired or revoked), the client seamlessly re-authenticates using the configured auth backend (re-reading rotated Kubernetes SA tokens from disk automatically).

### Observability & Metrics

Vault authentication and token operations emit OpenTelemetry counters for successful initial logins, renewals, and re-authentications.

### Cache Behavior

- Certificate material stays cached until provisioning or renewal invalidates it.
- Signing-key material reads are controlled consistently across backends by `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL`.
- To require every private-key read to query the selected material backend, keep `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL=0`.

## GCP Secret Manager

When compiled with the `gcp-secrets` feature flag, secrets are stored in GCP Secret Manager.

### Configuration Variables

| Variable                                              | Type              | Default                          | Description                                                                    |
| ----------------------------------------------------- | ----------------- | -------------------------------- | ------------------------------------------------------------------------------ |
| `APP_GCP_SECRET_MANAGER__PROJECT_ID`                  | String            | _(Required when GCP is enabled)_ | GCP Project ID where secrets are hosted                                        |
| `APP_GCP_SECRET_MANAGER__SERVICE_ACCOUNT_KEY`         | String (JSON)     | `None`                           | Optional inline service account JSON key string                                |
| `APP_GCP_SECRET_MANAGER__SERVICE_ACCOUNT_KEY_PATH`    | String            | `None`                           | Optional filepath to service account JSON key file                             |
| `APP_GCP_SECRET_MANAGER__ENDPOINT`                    | String (URL)      | `None`                           | Optional custom endpoint (for regional endpoints, VPC-SC, or emulator testing) |
| `APP_GCP_SECRET_MANAGER__ALLOW_ANONYMOUS_CREDENTIALS` | Boolean           | `false`                          | Allow anonymous credentials without ADC (for local emulator/testing only)      |
| `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL`             | Integer (seconds) | `300` (5 minutes)                | In-memory cache TTL in seconds. Set to `0` to disable caching.                 |

### Authentication & IAM Permissions

By default, authentication uses **Application Default Credentials (ADC)** (discovering environment credentials via `GOOGLE_APPLICATION_CREDENTIALS`, GKE workload identity, or Compute Engine metadata server).

#### Least-Privilege IAM Roles

Avoid granting broad project-level `roles/secretmanager.admin` (which permits modifying IAM policies on all secrets). Instead, use the combination of built-in least-privilege roles or a custom role:

##### Option 1: Built-in Predefined Roles (Recommended)

- `roles/secretmanager.secretAccessor`: Access secret payload data (`secretmanager.versions.access`).
- `roles/secretmanager.secretVersionManager`: Add new secret versions (`secretmanager.versions.add`).
- `roles/secretmanager.viewer`: Read secret metadata and support readiness health check probes (`secretmanager.secrets.get`).

##### Option 2: Custom Role (Least-Privilege for Full Lifecycle)

If the server manages the creation and deletion of secret containers directly, create a custom IAM role restricted to the following permissions:

```yaml
title: "Status List Server Secrets Operator"
stage: "GA"
includedPermissions:
  - secretmanager.secrets.get
  - secretmanager.secrets.create
  - secretmanager.secrets.delete
  - secretmanager.versions.add
  - secretmanager.versions.access
  - secretmanager.versions.list
```

### Example `.env` Configuration

```env
APP_GCP_SECRET_MANAGER__PROJECT_ID=my-gcp-project-123
APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL=300
GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
```

## Azure Key Vault

When compiled with the `azure-kv` feature flag, secrets are stored in Azure Key Vault.

### Configuration Variables

| Variable                                  | Type              | Default                               | Description                                                    |
| ----------------------------------------- | ----------------- | ------------------------------------- | -------------------------------------------------------------- |
| `APP_AZURE_KEYVAULT__VAULT_URL`           | String            | \_(Required when Azure KV is enabled) | Azure Key Vault URL (e.g. `https://my-vault.vault.azure.net/`) |
| `APP_AZURE_KEYVAULT__TENANT_ID`           | String            | `None`                                | Azure AD Tenant ID (for service principal auth)                |
| `APP_AZURE_KEYVAULT__CLIENT_ID`           | String            | `None`                                | Azure AD Client ID (for service principal auth)                |
| `APP_AZURE_KEYVAULT__CLIENT_SECRET`       | String            | `None`                                | Azure AD Client Secret (for service principal auth)            |
| `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL` | Integer (seconds) | `300` (5 minutes)                     | In-memory cache TTL in seconds. Set to `0` to disable caching. |

### Authentication & RBAC Permissions

The Azure Key Vault must be configured to use the **Azure role-based access control (Azure RBAC)** permission model (recommended) or legacy access policies.

#### Authentication Methods

1. **Explicit Service Principal**: Configure `APP_AZURE_KEYVAULT__TENANT_ID`, `APP_AZURE_KEYVAULT__CLIENT_ID`, and `APP_AZURE_KEYVAULT__CLIENT_SECRET`.
2. **Workload Identity (AKS)**: In Azure Kubernetes Service with Workload Identity enabled, credentials are automatically resolved via `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_CLIENT_ID`, and `AZURE_TENANT_ID`.
3. **Managed Identity**: In Azure VM, App Service, or Container Apps environments, credentials are automatically resolved via the Managed Identity service.
4. **Developer Tools**: In local environments, credentials are automatically resolved from the Azure CLI (`az login`).

#### Required Roles & Permissions

- **Key Vault Secrets Officer** built-in RBAC role (recommended for full CRUD access on secrets).
- Or a custom role with the following data actions:
  - `Microsoft.KeyVault/vaults/secrets/getSecret/action`
  - `Microsoft.KeyVault/vaults/secrets/setSecret/action`
  - `Microsoft.KeyVault/vaults/secrets/deleteSecret/action`
  - `Microsoft.KeyVault/vaults/secrets/purge/action` (optional, to permanently purge soft-deleted secrets so their names can be reused immediately)

> [!NOTE]
> Azure Key Vault has soft-delete enabled by default. When a secret is deleted, the adapter attempts to purge it immediately if the identity has purge permissions and purge protection is not enforced on the vault.

### Example `.env` Configuration

```env
APP_AZURE_KEYVAULT__VAULT_URL=https://prod-vault.vault.azure.net/
APP_AZURE_KEYVAULT__TENANT_ID=00000000-0000-0000-0000-000000000000
APP_AZURE_KEYVAULT__CLIENT_ID=11111111-1111-1111-1111-111111111111
APP_AZURE_KEYVAULT__CLIENT_SECRET=supersecret
APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL=300
```

## AWS Secrets Manager

When compiled with the `aws-secrets` feature flag:

```env
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
APP_AWS__REGION=us-east-1
APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL=0
```
