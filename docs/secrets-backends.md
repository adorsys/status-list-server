# Secrets Storage Backend Guidance

The server supports storing sensitive cryptographic materials (such as ACME account keys and server signing keys) in secure secrets management backends.

The supported secrets backends include:

- **HashiCorp Vault / OpenBao**
- **AWS Secrets Manager**
- **In-Memory** (for development and testing)

## HashiCorp Vault & OpenBao (KV v2)

Both HashiCorp Vault and OpenBao share the KV v2 REST API interface and are supported natively when the `vault` feature flag is enabled.

Authentication is strictly performed via **AppRole**, which is the industry standard machine-to-machine authentication mechanism for production deployments.

### Configuration Variables

| Variable                       | Type              | Default                             | Description                                                              |
| ------------------------------ | ----------------- | ----------------------------------- | ------------------------------------------------------------------------ |
| `APP_VAULT__ADDR`              | String            | `http://127.0.0.1:8200`             | Base URL of the Vault / OpenBao cluster                                  |
| `APP_VAULT__AUTH_MOUNT`        | String            | `"approle"`                         | Mount path of the AppRole auth engine                                    |
| `APP_VAULT__ROLE_ID`           | String            | _(Mandatory when Vault is enabled)_ | AppRole Role ID identifier                                               |
| `APP_VAULT__SECRET_ID`         | String (Secret)   | _(Optional if path is used)_        | AppRole Secret ID credential                                             |
| `APP_VAULT__SECRET_ID_PATH`    | Path              | `None`                              | File path containing AppRole Secret ID (e.g. K8s volume mount)           |
| `APP_VAULT__MOUNT`             | String            | `"secret"`                          | KV v2 secrets engine mount point                                         |
| `APP_VAULT__PATH_PREFIX`       | String            | `""`                                | Optional prefix prepended to all secret keys (e.g. `status-list-server`) |
| `APP_VAULT__NAMESPACE`         | String            | `None`                              | Optional Enterprise/OpenBao namespace header (`X-Vault-Namespace`)       |
| `APP_VAULT__SECRETS_CACHE_TTL` | Integer (seconds) | `300` (5 minutes)                   | In-memory cache TTL in seconds. Set to `0` to disable caching.           |
| `APP_VAULT__TIMEOUT_SECS`      | Integer (seconds) | `30`                                | HTTP request timeout duration in seconds                                 |

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
APP_VAULT__SECRETS_CACHE_TTL=300
```

### Example 2: Production Deployment with OpenBao / Vault

In Kubernetes or ECS, inject the `role_id` and `secret_id` via Kubernetes Secrets or IAM-bound orchestration:

```env
APP_VAULT__ADDR=http://openbao-service.openbao.svc.cluster.local:8200
APP_VAULT__AUTH_MOUNT=approle
APP_VAULT__ROLE_ID=ba0a1234-5678-90ab-cdef-1234567890ab
APP_VAULT__SECRET_ID=fe987654-3210-fedc-ba09-876543210fed
APP_VAULT__MOUNT=secret
APP_VAULT__PATH_PREFIX=production/status-list
APP_VAULT__NAMESPACE=my-org-namespace
APP_VAULT__SECRETS_CACHE_TTL=600
```

### Automated Token Lifecycle & Resilience

The server features an enterprise-grade automated token manager:

- **Initial Login**: Exchanged via `POST /v1/auth/{auth_mount}/login` at application startup.
- **Proactive Renewal**: Tokens are automatically renewed via `POST /v1/auth/token/renew-self` when 80% of their lease TTL has elapsed.
- **Re-authentication Fallback**: If renewal fails (e.g. token expired or revoked), the client seamlessly re-authenticates using the AppRole credentials.

### Observability & Metrics

Vault authentication and token operations emit OpenTelemetry counters for successful initial logins, renewals, and re-authentications.

### Cache Behavior

- Secrets are cached in-memory using TTL semantics to minimize latency and Vault API request volume.
- To disable caching entirely (forcing every read to query Vault directly), set `APP_VAULT__SECRETS_CACHE_TTL=0`.

## AWS Secrets Manager

When compiled with the `aws` feature flag:

```env
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
APP_AWS__REGION=us-east-1
APP_AWS__SECRETS_CACHE_TTL=300
```
