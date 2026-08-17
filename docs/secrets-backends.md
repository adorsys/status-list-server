# Cryptographic Material Backend Guidance

The server stores lifecycle-coupled cryptographic material in one selected backend by default: ACME account keys, the server signing key, and the certificate chain associated with that key.

The supported backends include:

- **HashiCorp Vault / OpenBao** (KV v2 engine)
- **AWS Secrets Manager**
- **In-Memory** (for development and testing)

## Storage Semantics

All supported cryptographic-material backends use the same logical model for certificate chains and private signing keys:

| Backend               | Certificate chain                                     | Private signing key                                   | Behavior                                                                                |
| --------------------- | ----------------------------------------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------- |
| In-memory             | Stored as a string under the certificate material key | Stored as a string under the signing-key material key | Volatile process-local storage for development and tests                                |
| AWS Secrets Manager   | Stored as one secret string                           | Stored as one secret string                           | Same create, update, load, delete, cache, and invalidation path as certificate material |
| Vault / OpenBao KV v2 | Stored as one KV v2 secret value                      | Stored as one KV v2 secret value                      | Same create, update, load, delete, cache, and invalidation path as certificate material |

ACME provisioning writes the issued certificate chain and the signing key through this single abstraction. Store provisioning can seed material either from local files or from existing keys in the selected material backend, but the refreshed server material is persisted back through the same backend and invalidated together.

## HashiCorp Vault & OpenBao (KV v2)

Both HashiCorp Vault and OpenBao share the KV v2 REST API interface and are supported natively when the `vault` feature flag is enabled.

### Configuration Variables

| Variable                                    | Type              | Default    | Description                                                                                                  |
| ------------------------------------------- | ----------------- | ---------- | ------------------------------------------------------------------------------------------------------------ |
| `APP_SERVER__CERT__MATERIAL_BACKEND`        | String            | `memory`   | Primary backend for server cryptographic material: `memory`, `aws_secrets_manager`, or `vault`.              |
| `APP_SERVER__CERT__MATERIAL_CACHE_TTL`      | Integer (seconds) | `300`      | In-memory read-cache TTL for certificate material. Set to `0` to disable this material cache.                |
| `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL`   | Integer (seconds) | `0`        | In-memory read-cache TTL for private signing-key material. Set to `0` to force every read to the backend.    |

Backend-specific settings:

| Variable                       | Type              | Default                             | Description                                                              |
| ------------------------------ | ----------------- | ----------------------------------- | ------------------------------------------------------------------------ |
| `APP_VAULT__ADDR`              | String            | `http://127.0.0.1:8200`             | Base URL of the Vault / OpenBao cluster                                  |
| `APP_VAULT__TOKEN`             | String            | _(Mandatory when Vault is enabled)_ | Authentication token (`X-Vault-Token`)                                   |
| `APP_VAULT__MOUNT`             | String            | `"secret"`                          | KV v2 secrets engine mount point                                         |
| `APP_VAULT__PATH_PREFIX`       | String            | `""`                                | Optional prefix prepended to all secret keys (e.g. `status-list-server`) |
| `APP_VAULT__NAMESPACE`         | String            | `None`                              | Optional Enterprise/OpenBao namespace header (`X-Vault-Namespace`)       |
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
```

### Cache Behavior

- Certificate and signing-key material reads are controlled consistently across backends by `APP_SERVER__CERT__MATERIAL_CACHE_TTL` and `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL`.
- To require every private-key read to query the selected material backend, keep `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL=0`.

## AWS Secrets Manager

When compiled with the `aws-secrets` feature flag:

```env
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
APP_AWS__REGION=us-east-1
APP_SERVER__CERT__MATERIAL_BACKEND=aws_secrets_manager
APP_SERVER__CERT__MATERIAL_CACHE_TTL=300
APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL=0
```
