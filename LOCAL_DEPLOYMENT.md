# Local Deployment Guide - Status List Server

This document describes the process of adapting the production-ready Helm chart for local testing with minikube, including the issues encountered and their solutions.

## Overview

The status-list-server Helm chart was originally designed for production deployment on AWS EKS with TLS encryption, external secrets, and AWS-specific configurations. This guide documents how we created a local testing version using the same chart with simplified configurations suitable for minikube.

## Goal

Create a local testing environment that:
- Uses the same Helm chart as production
- Disables TLS for Redis (not needed for local testing)
- Removes AWS-specific dependencies (external secrets, secret store)
- Simplifies storage classes and resource requirements
- Works with minikube

## Solution Architecture

### Files Created/Modified

1. **`values-local.yml`** - Local testing values file
2. **Template Updates** - Modified templates to conditionally render AWS/external secret resources
3. **Production `values.yaml`** - Added `enabled` flags for backward compatibility

### Key Changes

- **External Secrets**: Disabled for local, using simple Kubernetes secrets instead
- **Secret Store**: Disabled for local (AWS Secrets Manager not needed)
- **Redis TLS**: Completely disabled using `customConfig` override
- **Ingress**: Disabled for local (using port-forward instead)
- **Storage Classes**: Using default "standard" class for minikube
- **Resources**: Reduced resource requirements for local testing

## Issues Encountered and Solutions

### Issue 1: Redis TLS Configuration Persistence

**Problem:**
The redis-ha chart was generating TLS configuration in `redis.conf` even when `tlsPort` was set to `~` (null). Redis would attempt to load TLS certificates from `/tls-certs/tls.crt` and fail with:
```
Failed to load certificate: /tls-certs/tls.crt: error:80000002:system library::No such file or directory
Failed to configure TLS. Check logs for more info.
```

This caused the Redis pod to crash in a `CrashLoopBackOff` state.

**Root Cause:**
The redis-ha chart's config generation logic was checking for TLS configuration in multiple places:
- `redis.tlsPort` value
- `tls.secretName` value
- Chart's internal defaults

Even when these were set to null/empty, the chart's template logic was still generating TLS configuration directives in the redis.conf file.

**Attempted Solutions:**
1. Set `tlsPort: ~` and `tlsReplication: ~` - **Did not work**
2. Removed `tls` section entirely - **Did not work**
3. Set `tls.secretName: ~` explicitly - **Did not work**
4. Created dummy TLS secret to satisfy volume mount - **Did not work**

**Final Solution:**
Used `redis.customConfig` to completely override the generated configuration. According to the redis-ha chart documentation, when `customConfig` is provided, it completely replaces the generated config, bypassing the chart's TLS detection logic.

```yaml
redis:
  port: 6379
  tlsPort: ~
  tlsReplication: ~
  authClients: "no"
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
```

**Key Insight:**
The `customConfig` approach bypasses the chart's config generation entirely, giving us full control over the Redis configuration without TLS directives.

### Issue 2: Conditional Template Rendering

**Problem:**
The Helm templates were hardcoded to always render AWS-specific resources (external secrets, secret store, AWS credentials volume), which would fail in a local environment without AWS access.

**Solution:**
Added conditional rendering using `enabled` flags:

1. **External Secrets Template** (`templates/external-secretes.yaml`):
```yaml
{{- if .Values.externalSecret.enabled }}
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
...
{{- end }}
```

2. **Secret Store Template** (`templates/secret-store.yaml`):
```yaml
{{- if .Values.secretStore.enabled }}
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
...
{{- end }}
```

3. **Deployment Template** (`templates/deployment.yaml`):
   - Conditionally include AWS credentials volume mount
   - Conditionally set `APP_AWS__REGION` environment variable
   - Use conditional logic for secret names (external secret vs. simple secret)

4. **Ingress Template** (`templates/ingress.yaml`):
   - Conditionally render based on `ingress.enabled`
   - Handle empty `externalDnsHostname` gracefully

### Issue 3: Redis URI Configuration

**Problem:**
The deployment template needed to use different Redis connection URIs:
- Production: `rediss://` (TLS) with external DNS hostname
- Local: `redis://` (no TLS) with internal service name

**Solution:**
Added conditional logic in `templates/deployment.yaml`:
```yaml
- name: APP_REDIS__URI
  {{- if and (index .Values "redis-ha" "haproxy" "tls" "enabled") (index .Values "redis-ha" "externalDnsHostname") }}
  value: "rediss://:$(REDIS_PASSWORD)@{{ index .Values "redis-ha" "externalDnsHostname" }}:6379"
  {{- else }}
  value: "redis://:$(REDIS_PASSWORD)@{{ .Release.Name }}-redis-ha-haproxy.{{ .Release.Namespace }}.svc.cluster.local:6379"
  {{- end }}
```

## Final Configuration

### values-local.yml Structure

```yaml
global:
  storageClass: "standard"  # Minikube default

statuslist:
  # Simplified init containers (no DNS wait needed)
  # Reduced resources
  # Disabled ingress
  # Local environment settings

postgres:
  # Standard configuration with simple secret

externalSecret:
  enabled: false  # Use simple secrets instead

secretStore:
  enabled: false  # No AWS Secrets Manager

redis-ha:
  redis:
    customConfig: |  # Override to avoid TLS
      # Plain Redis config without TLS
  tls:
    secretName: ~  # Explicitly null
  sentinel:
    tlsPort: ~
    tlsReplication: ~
  haproxy:
    tls:
      enabled: false
```

## Deployment Steps

### Prerequisites

1. Minikube running: `minikube status`
2. Helm installed
3. Namespace created: `kubectl create namespace statuslist`

### Step 1: Create Secrets

```bash
kubectl create secret generic statuslist-secret -n statuslist \
  --from-literal=postgres-password=your-postgres-password \
  --from-literal=redis-password=your-redis-password
```

### Step 2: Update Helm Dependencies

```bash
cd helm/chart
helm dependency update
```
### Step 3: Update Helm Dependencies
```bash
cd ../..
helm install statuslist ./helm/chart --namespace statuslist --values ./helm/chart/values-local.yml --create-namespace
```
Or for upgrade:
```bash
helm upgrade statuslist ./helm/chart   
  --namespace statuslist   
  --values ./helm/values-local.yml
```

### Step 4: Verify Deployment

```bash
kubectl get pods -n statuslist
```

All pods should show `Running` status:
- `statuslist-postgres-0`: 1/1 Running
- `statuslist-redis-ha-server-0`: 3/3 Running
- `statuslist-redis-ha-haproxy-*`: 1/1 Running
- `statuslist-status-list-server-deployment-*`: 1/1 Running

### Step 5: Access the Service

```bash
kubectl port-forward -n statuslist svc/statuslist-service 8081:8081
```

Access at: `http://localhost:8081`

## Troubleshooting

### Redis Pod CrashLoopBackOff

**Symptoms:**
- Redis pod shows `CrashLoopBackOff`
- Logs show: "Failed to load certificate: /tls-certs/tls.crt"

**Solution:**
1. Verify `customConfig` is set in `values-local.yml`
2. Check configmap: `kubectl get configmap statuslist-redis-ha-configmap -n statuslist -o yaml`
3. Ensure no TLS directives in the config
4. Delete and recreate the pod: `kubectl delete pod statuslist-redis-ha-server-0 -n statuslist`

### Secret Not Found

**Symptoms:**
- Pods fail with "secret not found" errors

**Solution:**
1. Verify secret exists: `kubectl get secret statuslist-secret -n statuslist`
2. Ensure secret has correct keys: `postgres-password` and `redis-password`
3. Recreate if needed (see Step 1 above)

### Init Container Hanging

**Symptoms:**
- Pods stuck in `Init:0/2` or similar

**Solution:**
1. Check init container logs:
   ```bash
   kubectl logs -n statuslist <pod-name> -c wait-for-postgres
   kubectl logs -n statuslist <pod-name> -c wait-for-redis
   ```
2. Verify dependencies are running: `kubectl get pods -n statuslist`
3. Check service endpoints: `kubectl get endpoints -n statuslist`

## Key Learnings

1. **Chart Override Strategy**: When a chart's config generation logic is problematic, using `customConfig` provides a clean way to bypass it entirely.

2. **Conditional Rendering**: Always use `enabled` flags for optional resources to maintain chart flexibility across environments.

3. **Null vs Empty**: In Helm/YAML, `~` (null) and `""` (empty string) are different. Some charts check for null specifically.

4. **Template Logic**: Complex charts may have multiple code paths that enable features. Overriding at the lowest level (customConfig) is more reliable than trying to disable each path.

5. **Local vs Production**: The same chart can serve both environments with proper value file separation and conditional logic.

## Production vs Local Comparison

| Feature | Production (EKS) | Local (Minikube) |
|--------|------------------|------------------|
| Redis TLS | Enabled (rediss://) | Disabled (redis://) |
| External Secrets | AWS Secrets Manager | Simple K8s secrets |
| Secret Store | Enabled | Disabled |
| Ingress | Enabled with cert-manager | Disabled (port-forward) |
| Storage Class | high-performance | standard |
| Redis Config | Generated with TLS | Custom (no TLS) |
| DNS | External (redis.eudi-adorsys.com) | Internal service name |
| LoadBalancer | AWS NLB | ClusterIP |

## References

- [Redis HA Chart Documentation](https://github.com/dandydeveloper/charts/tree/main/charts/redis-ha)
- [Helm Values Override Guide](https://helm.sh/docs/chart_best_practices/values/)
- [Minikube Getting Started](https://minikube.sigs.k8s.io/docs/start/)

## Maintenance Notes

- When updating the redis-ha chart version, verify that `customConfig` still works as expected
- If adding new production features, ensure they have corresponding `enabled` flags for local testing
- Test local deployment after any chart template changes
- Keep `values-local.yml` in sync with production `values.yaml` structure (where applicable)
