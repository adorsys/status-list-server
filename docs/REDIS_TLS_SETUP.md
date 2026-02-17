# Redis TLS Setup with HAProxy Termination

This document explains the Redis TLS configuration for the status-list-server deployment, including the challenges encountered and solutions implemented.

## Quick Start

**For Redis TLS with HAProxy (automated sync):**

1. **Deploy / upgrade the chart (CronJob + RBAC included):**

   ```bash
   helm upgrade statuslist ./helm/status-list-server-chart --namespace statuslist
   ```

   This will:

   - Ensure the wildcard certificate `statuslist-tls` is managed by cert-manager
   - Install a `CronJob` that automatically syncs `statuslist-tls` into `statuslist-haproxy-tls`
   - Only update `statuslist-haproxy-tls` when the certificate actually changes

2. **Verify:**

   ```bash
   kubectl get pods -n statuslist
   kubectl logs statuslist-status-list-server-deployment-<pod-id> -n statuslist
   kubectl logs cronjob/statuslist-status-list-server-redis-cert-sync -n statuslist
   ```

## Why This Setup?

**Problem:** App needs Redis with TLS, but:

- Certificate must match hostname (`*.eudi-adorsys.com`)
- No client certificates wanted (too complex)
- External access required (outside Kubernetes)

**Solution:** HAProxy handles TLS termination, Redis handles data storage

## Architecture

```text
┌─────────────────┐    TLS     ┌──────────────┐    Plain    ┌─────────────┐
│   Application   │ ────────── │   HAProxy    │ ────────── │   Redis     │
│                 │  rediss:// │  (TLS Term)  │            │   Cluster   │
│ redis.eudi-     │  :6379     │              │            │             │
│ adorsys.com     │            │              │            │             │
└─────────────────┘            └──────────────┘            └─────────────┘
```

**Flow:**

1. App connects to `redis.eudi-adorsys.com:6379` (TLS encrypted)
2. HAProxy terminates TLS using wildcard certificate
3. HAProxy forwards plain Redis protocol to Redis cluster
4. Redis handles authentication and data operations

## 🔧 Key Challenges and Solutions

### 1. Redis TLS Configuration

**Challenge**: Redis chart needed explicit TLS configuration to listen on TLS port.

**Solution**: Added explicit TLS configuration in `values.yaml`:

```yaml
redis-ha:
  redis:
    tlsPort: 6380
    authClients: "no"
    config:
      tls-port: 6380
      tls-cert-file: /tls-certs/tls.crt
      tls-key-file: /tls-certs/tls.key
      tls-auth-clients: "no"
  tls:
    secretName: statuslist-tls
    certFile: tls.crt
    keyFile: tls.key
```

### 2. HAProxy TLS Termination

**Challenge**: HAProxy needed TLS termination with proper certificate handling.

**Problem**: HAProxy expects a single PEM file (cert + key), but Kubernetes TLS secrets store them separately.

**Solution**: Automate the combined PEM secret creation for HAProxy via a Kubernetes CronJob (the chart installs an equivalent manifest):

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: statuslist-status-list-server-redis-cert-sync
  namespace: statuslist
spec:
  schedule: "0 0 * * 0" # every Sunday at 00:00 UTC
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: statuslist-status-list-server-redis-cert-sync
          restartPolicy: OnFailure
          containers:
            - name: redis-cert-sync
              image: bitnami/kubectl:latest
              imagePullPolicy: IfNotPresent
              env:
                - name: NAMESPACE
                  valueFrom:
                    fieldRef:
                      fieldPath: metadata.namespace
              command:
                - /bin/bash
                - -c
                - |
                  set -euo pipefail

                  NS="${NAMESPACE:-statuslist}"
                  TMP_DIR="$(mktemp -d)"
                  trap 'rm -rf "$TMP_DIR"' EXIT

                  echo "Fetching base certificate from secret statuslist-tls in namespace ${NS}..."
                  kubectl get secret statuslist-tls -n "${NS}" -o jsonpath='{.data.tls\.crt}' | base64 -d > "${TMP_DIR}/tls.crt"
                  kubectl get secret statuslist-tls -n "${NS}" -o jsonpath='{.data.tls\.key}' | base64 -d > "${TMP_DIR}/tls.key"

                  cat "${TMP_DIR}/tls.crt" "${TMP_DIR}/tls.key" > "${TMP_DIR}/redis.pem"

                  # If the HAProxy secret exists, compare the current redis.pem with the new one.
                  if kubectl get secret statuslist-haproxy-tls -n "${NS}" >/dev/null 2>&1; then
                    echo "Existing statuslist-haproxy-tls secret found, comparing redis.pem..."
                    kubectl get secret statuslist-haproxy-tls -n "${NS}" -o jsonpath='{.data.redis\.pem}' | base64 -d > "${TMP_DIR}/existing-redis.pem" || true

                    if [ -s "${TMP_DIR}/existing-redis.pem" ] && cmp -s "${TMP_DIR}/redis.pem" "${TMP_DIR}/existing-redis.pem"; then
                      echo "Redis HAProxy certificate is already up to date. No changes applied."
                      exit 0
                    fi
                  else
                    echo "statuslist-haproxy-tls secret does not exist yet. It will be created."
                  fi

                  echo "Applying updated statuslist-haproxy-tls secret..."
                  kubectl create secret generic statuslist-haproxy-tls \
                    -n "${NS}" \
                    --from-file=redis.pem="${TMP_DIR}/redis.pem" \
                    --dry-run=client -o yaml | kubectl apply -f -

                  echo "Redis HAProxy TLS secret synced successfully."
```

**HAProxy Configuration**:

```yaml
redis-ha:
  haproxy:
    enabled: true
    replicas: 1 # Reduced from 3 to save resources
    tls:
      enabled: true
      secretName: statuslist-haproxy-tls
      keyName: redis.pem
    service:
      type: LoadBalancer
      annotations:
        service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
        external-dns.alpha.kubernetes.io/hostname: redis.eudi-adorsys.com
```

### 3. DNS Resolution and Certificate Validation

**Challenge**: Application needed to connect to `redis.eudi-adorsys.com` but DNS propagation takes time.

**Problem**: App would fail with "Name has no usable address" if DNS wasn't ready.

**Solution**: Added robust DNS resolution wait in init container:

```yaml
statuslist:
  initContainers:
    - name: wait-for-redis
      image: busybox
      command:
        - "sh"
        - "-c"
        - |
          echo "Waiting for Redis vanity DNS to resolve..."
          until nslookup redis.eudi-adorsys.com >/dev/null 2>&1; do
            echo "redis.eudi-adorsys.com not resolvable yet. Retrying in 2s...";
            sleep 2;
          done
          echo "Vanity DNS resolved. Waiting for HAProxy (TLS) at 6379..."
          until nc -z statuslist-redis-ha-haproxy.statuslist.svc.cluster.local 6379; do
            echo "Redis (haproxy) not ready. Retrying in 2s...";
            sleep 2;
          done
          echo "Redis (haproxy) is up."
```

### 4. Application Configuration

**Challenge**: App needed to connect to Redis with TLS but without client authentication.

**Solution**: Configured app environment variables:

```yaml
env:
  APP_REDIS__REQUIRE_CLIENT_AUTH: "false"
  APP_REDIS__URI: "rediss://:$(REDIS_PASSWORD)@redis.eudi-adorsys.com:6379"
```

**Key Points**:

- `rediss://` scheme enables TLS
- `APP_REDIS__REQUIRE_CLIENT_AUTH: "false"` disables client certificate authentication
- Uses external DNS name that matches certificate CN (`*.eudi-adorsys.com`)

## Why This Architecture?

### 1. HAProxy vs Direct Redis TLS

**Why HAProxy?**

- ✅ Certificate hostname validation: App connects to `redis.eudi-adorsys.com` which matches the certificate CN
- ✅ Load balancing: HAProxy can distribute load across Redis replicas
- ✅ TLS termination: Offloads TLS processing from Redis
- ✅ External access: Provides external LoadBalancer for Redis access

**Why not direct Redis TLS?**

- ❌ Hostname mismatch: In-cluster service names don't match certificate CN
- ❌ Certificate validation would fail with internal DNS names

### 2. Certificate Management

**Certificate Requirements**:

- Must be valid for `*.eudi-adorsys.com` (wildcard certificate)
- HAProxy uses this certificate for TLS termination
- App validates certificate against hostname `redis.eudi-adorsys.com`

We intentionally **derive the Redis/HAProxy certificate from the same wildcard certificate used by the status-list-server ingress** (`statuslist-tls`) so that:

- We only manage **one ACME certificate** for the entire `*.eudi-adorsys.com` namespace.
- cert-manager handles issuance and renewal in a single place.
- Both HTTP (`statuslist.eudi-adorsys.com`) and Redis (`redis.eudi-adorsys.com`) endpoints present certificates that are consistent and valid for their hostnames.
- We avoid self-signed or cluster-internal certificates on the Redis endpoint, which would fail TLS validation in the Rust client unless we shipped and configured custom root CAs.

**Certificate Flow**:

1. App connects to `redis.eudi-adorsys.com:6379`
2. HAProxy terminates TLS using wildcard certificate
3. HAProxy forwards plain Redis protocol to Redis cluster
4. Redis cluster handles authentication and data operations

### 3. DNS Resolution Strategy

**Why wait for DNS?**

- External DNS propagation takes time
- App crashes if hostname doesn't resolve
- Init container ensures DNS is ready before app starts

**Alternative Approaches Considered**:

1. **ELB hostname**: Use AWS ELB hostname directly (temporary solution)
2. **In-cluster service**: Would require certificate with internal DNS name
3. **DNS wait**: Most robust solution for production

## Troubleshooting

### Common Issues

1. **HAProxy crashes**: Check TLS secret format (must be PEM)
2. **DNS resolution fails**: Wait for external-dns propagation
3. **Certificate validation fails**: Ensure certificate CN matches hostname
4. **Redis connection fails**: Check HAProxy logs and Redis cluster status

### Debug Commands

```bash
# Check HAProxy logs
kubectl logs deploy/statuslist-redis-ha-haproxy -n statuslist

# Test DNS resolution
kubectl run test-dns --image=busybox --rm -it --restart=Never -n statuslist -- nslookup redis.eudi-adorsys.com

# Test Redis connection
kubectl run test-redis --image=busybox --rm -it --restart=Never -n statuslist -- nc -z redis.eudi-adorsys.com 6379
```

## Security Considerations

1. **TLS Encryption**: All Redis traffic encrypted in transit
2. **No Client Auth**: Redis doesn't require client certificates (as requested)
3. **Certificate Validation**: App validates server certificate
4. **Network Isolation**: Redis cluster not directly exposed externally

## Performance Considerations

1. **HAProxy Overhead**: Minimal TLS termination overhead
2. **Connection Pooling**: App uses Redis connection manager
3. **Resource Usage**: Reduced HAProxy replicas to 1 for cost optimization
4. **DNS Caching**: Init container ensures DNS resolution before app starts

## Conclusion

This setup provides:

- Redis TLS encryption in production
- No client certificate authentication
- Robust DNS resolution handling
- Certificate hostname validation
- External LoadBalancer access
- Production-ready configuration

The architecture balances security, performance, and operational requirements while handling the complexities of Kubernetes networking and certificate management.
