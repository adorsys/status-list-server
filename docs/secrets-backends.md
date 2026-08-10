# Secrets Storage Backend Guidance

The server supports storing sensitive cryptographic materials (such as ACME account keys and server signing keys) in secure secrets management backends.

The supported secrets backends include:

- **HashiCorp Vault / OpenBao** (KV v2 engine, feature flag: `vault`)
- **GCP Secret Manager** (feature flag: `gcp-secrets`)
- **Azure Key Vault** (feature flag: `azure-kv`)
- **AWS Secrets Manager** (feature flag: `aws`)
- **In-Memory** (for development and testing)

## HashiCorp Vault & OpenBao (KV v2)

Both HashiCorp Vault and OpenBao share the KV v2 REST API interface and are supported natively when the `vault` feature flag is enabled.

### Configuration Variables

| Variable                       | Type              | Default                             | Description                                                              |
| ------------------------------ | ----------------- | ----------------------------------- | ------------------------------------------------------------------------ |
| `APP_VAULT__ADDR`              | String            | `http://127.0.0.1:8200`             | Base URL of the Vault / OpenBao cluster                                  |
| `APP_VAULT__TOKEN`             | String            | _(Mandatory when Vault is enabled)_ | Authentication token (`X-Vault-Token`)                                   |
| `APP_VAULT__MOUNT`             | String            | `"secret"`                          | KV v2 secrets engine mount point                                         |
| `APP_VAULT__PATH_PREFIX`       | String            | `""`                                | Optional prefix prepended to all secret keys (e.g. `status-list-server`) |
| `APP_VAULT__NAMESPACE`         | String            | `None`                              | Optional Enterprise/OpenBao namespace header (`X-Vault-Namespace`)       |
| `APP_VAULT__SECRETS_CACHE_TTL` | Integer (seconds) | `300` (5 minutes)                   | In-memory cache TTL in seconds. Set to `0` to disable caching.           |
| `APP_VAULT__TIMEOUT_SECS`      | Integer (seconds) | `30`                                | HTTP request timeout duration in seconds                                 |

### Example 1: Local Development with HashiCorp Vault

Start a local Vault dev server:

```bash
docker run -d --name vault -p 8200:8200 -e 'VAULT_DEV_ROOT_TOKEN_ID=root' hashicorp/vault:2.0
```

Configure your `.env` file:

```env
APP_VAULT__ADDR=http://127.0.0.1:8200
APP_VAULT__TOKEN=root
APP_VAULT__MOUNT=secret
APP_VAULT__PATH_PREFIX=dev/status-list
APP_VAULT__SECRETS_CACHE_TTL=300
```

### Example 2: Deployment with OpenBao

Start an OpenBao container:

```bash
docker run -d --name openbao -p 8200:8200 -e 'BAO_DEV_ROOT_TOKEN_ID=root' openbao/openbao:2.6
```

Configure environment variables:

```env
APP_VAULT__ADDR=http://openbao-service.openbao.svc.cluster.local:8200
APP_VAULT__TOKEN=s.xxxxxxxxx
APP_VAULT__MOUNT=secret
APP_VAULT__PATH_PREFIX=production/status-list
APP_VAULT__NAMESPACE=my-org-namespace
APP_VAULT__SECRETS_CACHE_TTL=600
```

### Cache Behavior

- Secrets are cached in-memory using TTL semantics to minimize latency and Vault API request volume.
- To disable caching entirely (forcing every read to query Vault directly), set `APP_VAULT__SECRETS_CACHE_TTL=0`.

## GCP Secret Manager

When compiled with the `gcp-secrets` feature flag, secrets are stored in GCP Secret Manager.

### Configuration Variables

| Variable                                           | Type              | Default                          | Description                                                    |
| -------------------------------------------------- | ----------------- | -------------------------------- | -------------------------------------------------------------- |
| `APP_GCP_SECRET_MANAGER__PROJECT_ID`               | String            | _(Required when GCP is enabled)_ | GCP Project ID where secrets are hosted                        |
| `APP_GCP_SECRET_MANAGER__SERVICE_ACCOUNT_KEY`      | String (JSON)     | `None`                           | Optional inline service account JSON key string                |
| `APP_GCP_SECRET_MANAGER__SERVICE_ACCOUNT_KEY_PATH` | String            | `None`                           | Optional filepath to service account JSON key file             |
| `APP_GCP_SECRET_MANAGER__SECRETS_CACHE_TTL`        | Integer (seconds) | `300` (5 minutes)                | In-memory cache TTL in seconds. Set to `0` to disable caching. |

### Authentication & IAM Permissions

By default, authentication uses **Application Default Credentials (ADC)** (discovering environment credentials, GKE workload identity, service account metadata server, etc.).

Required IAM roles (least-privilege):

- `roles/secretmanager.secretAccessor` (read secrets)
- `roles/secretmanager.secretVersionManager` (create/update secret versions)
- `roles/secretmanager.admin` or custom role with `secretmanager.secrets.create` and `secretmanager.secrets.delete` (if automated secret creation/deletion is used)

### Example `.env` Configuration

```env
APP_GCP_SECRET_MANAGER__PROJECT_ID=my-gcp-project-123
APP_GCP_SECRET_MANAGER__SECRETS_CACHE_TTL=300
GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
```

## Azure Key Vault

When compiled with the `azure-kv` feature flag, secrets are stored in Azure Key Vault.

### Configuration Variables

| Variable                                | Type              | Default                               | Description                                                    |
| --------------------------------------- | ----------------- | ------------------------------------- | -------------------------------------------------------------- |
| `APP_AZURE_KEYVAULT__VAULT_URL`         | String            | \_(Required when Azure KV is enabled) | Azure Key Vault URL (e.g. `https://my-vault.vault.azure.net/`) |
| `APP_AZURE_KEYVAULT__TENANT_ID`         | String            | `None`                                | Azure AD Tenant ID (for service principal auth)                |
| `APP_AZURE_KEYVAULT__CLIENT_ID`         | String            | `None`                                | Azure AD Client ID (for service principal auth)                |
| `APP_AZURE_KEYVAULT__CLIENT_SECRET`     | String            | `None`                                | Azure AD Client Secret (for service principal auth)            |
| `APP_AZURE_KEYVAULT__SECRETS_CACHE_TTL` | Integer (seconds) | `300` (5 minutes)                     | In-memory cache TTL in seconds. Set to `0` to disable caching. |

### Authentication & RBAC Permissions

If `tenant_id`, `client_id`, and `client_secret` are provided, the adapter authenticates as a Service Principal. Otherwise, it falls back to Azure developer/workload identity credentials (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, or Azure CLI credentials).

Required RBAC roles (least-privilege):

- **Key Vault Secrets Officer** (full CRUD access to secrets)
- Or custom role with data actions:
  - `Microsoft.KeyVault/vaults/secrets/read`
  - `Microsoft.KeyVault/vaults/secrets/write`
  - `Microsoft.KeyVault/vaults/secrets/delete`

### Example `.env` Configuration

```env
APP_AZURE_KEYVAULT__VAULT_URL=https://prod-vault.vault.azure.net/
APP_AZURE_KEYVAULT__TENANT_ID=00000000-0000-0000-0000-000000000000
APP_AZURE_KEYVAULT__CLIENT_ID=11111111-1111-1111-1111-111111111111
APP_AZURE_KEYVAULT__CLIENT_SECRET=supersecret
APP_AZURE_KEYVAULT__SECRETS_CACHE_TTL=300
```

## AWS Secrets Manager

When compiled with the `aws` feature flag:

```env
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
APP_AWS__REGION=us-east-1
APP_AWS__SECRETS_CACHE_TTL=300
```
