# Redis TLS Setup with HAProxy Termination

This document explains the Redis TLS configuration for the status-list-server deployment, including the challenges encountered and solutions implemented.

> **Note**: For local testing without TLS, see section 5 below and refer to [LOCAL_DEPLOYMENT.md](./LOCAL_DEPLOYMENT.md) for complete local deployment guide.

## Quick Start

**For Redis TLS with HAProxy:**

1. **Create HAProxy TLS secret:**

   ```bash
   # Extract certificate and key from existing secret for HAProxy
   CRT=$(kubectl get secret statuslist-tls -n statuslist -o jsonpath='{.data.tls\.crt}' | base64 -d)
   KEY=$(kubectl get secret statuslist-tls -n statuslist -o jsonpath='{.data.tls\.key}' | base64 -d)
   # Combine cert and key into single PEM file for HAProxy
   printf "%s\n%s\n" "$CRT" "$KEY" > redis.pem
   # Create new secret for HAProxy with combined PEM
   kubectl create secret generic statuslist-haproxy-tls -n statuslist --from-file=redis.pem=redis.pem
   ```

2. **Deploy:**

   ```bash
   helm upgrade statuslist ./helm/status-list-server-chart --namespace statuslist
   ```

3. **Verify:**
   ```bash
   kubectl get pods -n statuslist
   kubectl logs statuslist-status-list-server-deployment-<pod-id> -n statuslist
   ```

## Why This Setup?

**Problem:** App needs Redis with TLS, but:

- Certificate must match hostname (`*.eudi-adorsys.com`)
- No client certificates wanted (too complex)
- External access required (outside Kubernetes)

**Solution:** HAProxy handles TLS termination, Redis handles data storage

## Architecture

```
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

**Solution**: Created a combined PEM secret for HAProxy:

```bash
# Extract certificate and key from existing secret
CRT=$(kubectl get secret statuslist-tls -n statuslist -o jsonpath='{.data.tls\.crt}' | base64 -d)
KEY=$(kubectl get secret statuslist-tls -n statuslist -o jsonpath='{.data.tls\.key}' | base64 -d)

# Create combined PEM file
printf "%s\n%s\n" "$CRT" "$KEY" > redis.pem

# Create new secret for HAProxy
kubectl create secret generic statuslist-haproxy-tls -n statuslist --from-file=redis.pem=redis.pem
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

### 5. Local Deployment Without TLS

**Challenge**: When adapting the chart for local testing (minikube), Redis pods were crashing even after disabling TLS settings.

**Problem**: The Redis pod was failing with `CrashLoopBackOff` and showing errors:
```
Failed to load certificate: /tls-certs/tls.crt: error:80000002:system library::No such file or directory
Failed to configure TLS. Check logs for more info.
```

**Root Cause Analysis**:

The redis-ha chart's configuration generation logic was still adding TLS directives to `redis.conf` even when TLS was supposedly disabled. The chart checks multiple conditions:
- `redis.tlsPort` value
- `tls.secretName` value  
- Chart's internal defaults and template logic

Even when these were set to `null` (`~`) or empty, the chart's template logic was still generating TLS configuration directives in the generated `redis.conf` file, causing Redis to attempt loading TLS certificates that didn't exist.

**Attempted Solutions (That Didn't Work)**:

1. **Setting `tlsPort: ~` and `tlsReplication: ~`** - Chart still generated TLS config
2. **Removing `tls` section entirely** - Chart still generated TLS config
3. **Setting `tls.secretName: ~` explicitly** - Chart still generated TLS config
4. **Creating dummy TLS secret** - Redis still tried to load invalid certificates

**Final Solution**: Use `redis.customConfig` to completely override the generated configuration.

According to the redis-ha chart documentation, when `customConfig` is provided, it completely replaces the generated `redis.conf`, bypassing the chart's TLS detection logic entirely.

**Local Configuration** (`values-local.yml`):

```yaml
redis-ha:
  redis:
    port: 6379
    tlsPort: ~  # Set to null
    tlsReplication: ~  # Set to null
    authClients: "no"
    # Use customConfig to completely override generated config and avoid TLS
    customConfig: |
      port 6379
      requirepass replace-default-auth
      masterauth replace-default-auth
      dir /data
      save 900 1
      repl-diskless-sync yes
      rdbcompression yes
      rdbchecksum yes
      maxmemory 0
      maxmemory-policy volatile-lru
      min-replicas-to-write 1
      min-replicas-max-lag 5
  haproxy:
    enabled: true
    tls:
      enabled: false  # Disable HAProxy TLS for local
    service:
      type: ClusterIP  # Use ClusterIP instead of LoadBalancer
```

**Key Insights**:

1. **`customConfig` Bypasses Chart Logic**: By providing `customConfig`, we completely bypass the chart's config generation, giving full control over the Redis configuration.

2. **No TLS Directives Needed**: The `customConfig` doesn't include any TLS-related directives (`tls-port`, `tls-cert-file`, etc.), so Redis runs in plain mode.

3. **Sentinel Configuration**: Sentinel uses its own separate `sentinel.conf` file, but when `redis.tlsPort` is null and `customConfig` is used, the chart automatically disables TLS for Sentinel as well.

4. **HAProxy TLS**: Must be explicitly disabled with `haproxy.tls.enabled: false` since HAProxy configuration is separate from Redis configuration.

**Verification**:

After applying the `customConfig` solution:
- ✅ Redis pod starts successfully
- ✅ No TLS certificate errors in logs
- ✅ Redis accepts plain TCP connections on port 6379
- ✅ Sentinel config has no TLS directives
- ✅ No TLS volumes mounted in the pod

**Production vs Local Comparison**:

| Configuration | Production (EKS) | Local (Minikube) |
|--------------|------------------|------------------|
| Redis Config | Generated with TLS | `customConfig` without TLS |
| `tlsPort` | `6380` | `~` (null) |
| `tls.secretName` | `statuslist-tls` | Not set |
| HAProxy TLS | `enabled: true` | `enabled: false` |
| Service Type | `LoadBalancer` | `ClusterIP` |
| Connection URI | `rediss://` (TLS) | `redis://` (plain) |

**Why This Solution Works**:

The `customConfig` approach is the most reliable because:
- It operates at the lowest level (the actual config file)
- It completely bypasses the chart's template logic
- It gives explicit control over every Redis configuration directive
- It prevents any "smart" detection logic from re-enabling TLS

This solution allows the same Helm chart to work in both production (with TLS) and local (without TLS) environments by simply using different values files.

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
5. **Local deployment: Redis pod crashes with TLS errors**: See section 5 above - use `customConfig` to override generated config

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
