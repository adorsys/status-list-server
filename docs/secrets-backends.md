# Secrets Storage Backend Guidance

The server supports storing sensitive cryptographic materials (such as ACME account keys and server signing keys) in secure secrets management backends.

The supported secrets backends include:

- **HashiCorp Vault / OpenBao**
- **AWS Secrets Manager**
- **In-Memory** (for development and testing)

## HashiCorp Vault & OpenBao (KV v2)

Both HashiCorp Vault and OpenBao share the KV v2 REST API interface and are supported natively when the `vault` feature flag is enabled.

The server supports two authentication methods:

- **AppRole**: Industry-standard machine-to-machine auth using `role_id`/`secret_id` credentials.
- **Kubernetes ServiceAccount**: No static credentials required — uses the projected ServiceAccount token.

### AppRole Authentication

#### Configuration Variables

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

### Example 2: Production Deployment with OpenBao / Vault (AppRole)

In Kubernetes, deliver the `role_id` and `secret_id` via Kubernetes Secrets or the ESO Vault provider:

```env
APP_VAULT__ADDR=http://openbao-service.openbao.svc.cluster.local:8200
APP_VAULT__AUTH_MOUNT=approle
APP_VAULT__ROLE_ID=ba0a1234-5678-90ab-cdef-1234567890ab
APP_VAULT__SECRET_ID_PATH=/var/run/secrets/vault/secret_id
APP_VAULT__MOUNT=secret
APP_VAULT__PATH_PREFIX=production/status-list
APP_VAULT__NAMESPACE=my-org-namespace
APP_VAULT__SECRETS_CACHE_TTL=600
```

### Vault Kubernetes Auth (No Static Credentials)

Use Kubernetes ServiceAccount token projection to authenticate with Vault without AppRole `role_id`/`secret_id` secrets. The service account must be bound to a Vault Kubernetes auth role.

**Key difference from AppRole:** No `APP_VAULT__ROLE_ID` or `APP_VAULT__SECRET_ID` required. The app uses the projected Kubernetes ServiceAccount token automatically mounted at `TOKEN_PATH`.

#### Configuration Variables

| Variable                    | Type   | Default                                  | Description                                              |
|-----------------------------|--------|------------------------------------------|----------------------------------------------------------|
| `APP_VAULT__ADDR`           | String | `http://127.0.0.1:8200`                 | Vault server URL                                          |
| `APP_VAULT__AUTH_MOUNT`     | String | `"kubernetes"`                          | Mount path for Kubernetes auth                            |
| `APP_VAULT__TOKEN_PATH`     | Path   | `/var/run/secrets/tokens/vaulttoken`    | Path to projected ServiceAccount token                   |
| `APP_VAULT__MOUNT`          | String | `"secret"`                              | KV v2 mount                                              |
| `APP_VAULT__PATH_PREFIX`    | String | `""`                                    | Optional prefix for secret paths                         |
| `APP_VAULT__NAMESPACE`      | String | `None`                                  | Optional Vault namespace header                          |
| `APP_VAULT__SECRETS_CACHE_TTL` | Integer | `300`                                 | In-memory cache TTL in seconds                           |

#### Server-Side Vault Setup

1. **Enable Kubernetes auth:**

   ```bash
   vault auth enable kubernetes
   ```

2. **Configure the Kubernetes auth method:**

   ```bash
   vault write auth/kubernetes/config \
     token_reViewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
     kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" \
     kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
   ```

3. **Create the Vault policy** (see [Least-Privilege Vault / OpenBao Policy](#least-privilege-vault--openbao-policy)).

4. **Create the Kubernetes auth role:**

   ```bash
   vault write auth/kubernetes/role/statuslist-role \
     bound_service_account_names=statuslist-sa \
     bound_service_account_namespaces=statuslist \
     policies=statuslist-policy \
     token_ttl=1h \
     token_max_ttl=4h
   ```

   Replace `statuslist-sa` and `statuslist` with your actual ServiceAccount name and namespace.

5. **Create the ServiceAccount** in Kubernetes with your platform's Workload Identity annotations (see [docs/workload-identity.md](workload-identity.md)).

#### Example: Vault K8s Auth Environment Variables

```env
APP_VAULT__ADDR=http://vault.openbao.svc.cluster.local:8200
APP_VAULT__AUTH_MOUNT=kubernetes
APP_VAULT__TOKEN_PATH=/var/run/secrets/tokens/vaulttoken
APP_VAULT__MOUNT=secret
APP_VAULT__PATH_PREFIX=production/status-list
APP_VAULT__SECRETS_CACHE_TTL=300
```

See [docs/workload-identity.md](workload-identity.md#vault-kubernetes-auth) for the full Helm deployment guide using `values-vault-k8s.yaml`.

### Automated Token Lifecycle & Resilience

The server features an enterprise-grade automated token manager:

- **Initial Login**: Exchanged via `POST /v1/auth/{auth_mount}/login` at application startup.
- **Proactive Renewal**: Tokens are automatically renewed via `POST /v1/auth/token/renew-self` when 80% of their lease TTL has elapsed.
- **Re-authentication Fallback**: If renewal fails (e.g. token expired or revoked), the client seamlessly re-authenticates using the configured credentials (AppRole or K8s token).

### Observability & Metrics

Vault authentication and token operations emit OpenTelemetry counters for successful initial logins, renewals, and re-authentications.

### Cache Behavior

- Secrets are cached in-memory using TTL semantics to minimize latency and Vault API request volume.
- To disable caching entirely (forcing every read to query Vault directly), set `APP_VAULT__SECRETS_CACHE_TTL=0`.

## Authentication & Secrets Delivery Decision Tree

Choose the combination of **application authentication** and **secrets delivery** that matches your infrastructure:

```
Start: What is your secrets backend?
│
├─► AWS Secrets Manager
│   │
│   └─► What is your Kubernetes platform?
│       ├─► AWS EKS
│       │   └─► Use: AWS IRSA
│       │         (Workload Identity: no static creds)
│       │         Chart: values-aws-irsa.yaml
│       │         Doc: docs/workload-identity.md
│       │
│       └─► Other EKS-compat (Fargate, etc.)
│           └─► Use: AWS IRSA with Fargate profile
│
├─► HashiCorp Vault / OpenBao
│   │
│   └─► What authentication method?
│       ├─► Kubernetes ServiceAccount (IRSA/GKE WI/Azure WIF available)
│       │   └─► Use: Vault Kubernetes Auth
│       │         (No role_id/secret_id needed)
│       │         Chart: values-vault-k8s.yaml
│       │         Doc: docs/workload-identity.md
│       │
│       └─► AppRole credentials exist in K8s Secrets
│           └─► Use: Vault AppRole + K8s volume mount
│                 (Delivered via ESO or static secret)
│                 Doc: This doc (AppRole section above)
│
├─► GCP Secret Manager
│   └─► Use: GKE Workload Identity
│         Chart: values-gke-wi.yaml
│         Doc: docs/workload-identity.md
│
└─► Azure Key Vault
    └─► Use: AKS Workload Identity Federation
          Chart: values-aks-wif.yaml
          Doc: docs/workload-identity.md
```

### Decision Matrix

| Secrets Backend             | Cloud/Platform      | Auth Method               | ESO Provider | Static Creds? |
|-----------------------------|---------------------|---------------------------|--------------|--------------|
| AWS Secrets Manager         | AWS EKS             | IRSA                      | `aws`        | No           |
| AWS Secrets Manager         | Any K8s             | ESO + mounted credentials  | `aws`        | Yes (legacy) |
| Vault / OpenBao KV          | Any                 | AppRole (file/Vault Agent) | `vault`      | Yes (legacy) |
| Vault / OpenBao KV          | EKS / GKE / AKS     | Vault K8s Auth            | `vault`      | No           |
| GCP Secret Manager          | GKE                 | GKE Workload Identity     | `gcp`        | No           |
| Azure Key Vault             | AKS                 | AKS Workload Identity Fed. | `azure`     | No           |

**Key terminology:**

- **Application Vault auth**: How the *application binary* authenticates to Vault to read/write secrets. Two modes: `approle` (uses `role_id`/`secret_id`) or `kubernetes` (uses projected ServiceAccount token, no static secrets).
- **ESO SecretStore provider**: How the *External Secrets Operator* synchronizes secrets from the external backend into Kubernetes Secrets. Independent of how the app authenticates to Vault.

These are independent concerns:

- You can use Vault K8s auth for the app + ESO `vault` provider for secret sync.
- You can use AWS IRSA for the app + ESO `aws` provider for secret sync.
- The app never needs to know which ESO provider in use.

For the complete Workload Identity setup guide covering AWS IRSA, GKE WI, AKS WIF, and Vault K8s auth, see [docs/workload-identity.md](workload-identity.md).

## AWS Secrets Manager

When compiled with the `aws` feature flag and deployed without Workload Identity:

```env
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
APP_AWS__REGION=us-east-1
APP_AWS__SECRETS_CACHE_TTL=300
```

For Workload Identity deployments (recommended), see [docs/workload-identity.md](workload-identity.md#aws-eks--iam-roles-for-service-accounts-irsa) — no static credentials needed.