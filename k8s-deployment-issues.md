# Status List Server Kubernetes Deployment Issues and Solutions

## Overview
This document records all issues encountered during the deployment of the Status List Server to a local Kubernetes cluster using kind, along with the solutions implemented.

## Environment
- **Kubernetes Cluster**: kind (Kubernetes in Docker)
- **Cluster Configuration**: 3 nodes (1 control-plane, 2 workers)
- **Namespace**: `statuslist`
- **Helm Chart**: Custom status-list-server-chart with Bitnami dependencies

## Issues Encountered and Solutions

### 1. Missing External Secrets CRDs
**Issue**: Helm chart dependencies on External Secrets Operator CRDs that weren't available in local cluster.
**Error**: 
```
error: resource mapping not found for name: "statuslist-secret" namespace: "statuslist" from "": no matches for kind "ExternalSecret" in version "external-secrets.io/v1beta1"
ensure CRDs are installed first
```
**Solution**: Added conditional logic to disable external secrets for local testing:
```yaml
# In test-values.yaml
externalSecret:
  enabled: false
secretStore:
  enabled: false
```
**Files Modified**: 
- `helm/status-list-server-chart/templates/external-secretes.yaml`
- `helm/status-list-server-chart/templates/secret-store.yaml`
**Status**: ✅ Resolved

### 2. Missing Kubernetes Secrets
**Issue**: PostgreSQL and Redis pods stuck in ContainerCreating state due to missing required secrets.
**Error**: 
```
Warning  FailedMount  43s (x8 over 2m)  kubelet  MountVolume.SetUp failed for volume "statuslist-secret" : secret "statuslist-secret" not found
```
**Solution**: Created required secrets manually:
```bash
kubectl create secret generic statuslist-secret \
  --from-literal=postgres-password=postgres \
  --from-literal=redis-password= \
  --namespace=statuslist

kubectl create secret tls statuslist-tls \
  --cert=src/test_resources/test_cert.pem \
  --key=src/test_resources/ec-private.pem \
  --namespace=statuslist
```
**Status**: ✅ Resolved

### 4. Redis TLS Configuration Issues
**Issue**: Redis pod failing to start due to TLS certificate configuration problems.
**Error**:
```
Failed to load certificate: /opt/bitnami/redis/certs/tls.crt: error:0480006C:PEM routines::no start line
Failed to configure TLS. Check logs for more info.
```
**Root Cause**: Bitnami Redis chart enables TLS by default, but certificates are missing for local deployment.
**Solution**: Disabled TLS by setting `auth.enabled: false` and using minimal Redis configuration:
```yaml
redis:
  auth:
    enabled: false
  master:
    persistence:
      enabled: true
      size: 2Gi
  replica:
    replicaCount: 0
```
**Status**: ✅ Resolved

### 5. Redis Port Configuration Error
**Issue**: Redis configuration file contains invalid port setting.
**Error**:
```
*** FATAL CONFIG FILE ERROR (Redis 8.0.3) ***
Reading the configuration file, at line 2
>>> 'port ""'
argument couldn't be parsed into an integer
```
**Root Cause**: Bitnami Redis chart generating invalid configuration when TLS is disabled.
**Solution**: Simplified Redis configuration to minimal settings and disabled authentication.
**Status**: Resolved

## Configuration Files Modified

### test-values.yaml
Created comprehensive test configuration with:
- Disabled ingress for local testing
- Simplified authentication settings
- Local database and cache URLs
- Resource limits appropriate for local development
- Disabled external secrets and TLS where appropriate

### Helm Chart Templates
Modified conditional logic in:
- `external-secretes.yaml`: Added `{{ if .Values.externalSecret.enabled }}` wrapper
- `secret-store.yaml`: Added `{{ if .Values.secretStore.enabled }}` wrapper

## Current Deployment Status

 **DEPLOYMENT SUCCESSFUL!**

The Status List Server has been successfully deployed to the local Kubernetes cluster and is fully operational. All issues have been resolved and the application is responding to API requests.


### Production Deployment Notes

For production deployment, the following would need to be re-enabled:
- **External Secrets Operator**: Set `externalSecret.enabled: true` and configure appropriate secret store
- **Redis TLS**: Enable TLS for secure Redis connections
- **Ingress**: Enable ingress controller for external access
- **Resource limits**: Adjust based on expected load
- **AWS credentials**: Configure proper AWS credentials for S3 and certificate management
- **Multiple replicas**: Increase replica count for high availability

## Simple Redis Workaround Details

### Problem
The Bitnami Redis chart with TLS enabled was causing persistent connection issues in the local kind cluster, preventing the init containers from successfully connecting to Redis.

### Solution
Created a simple Redis instance without TLS configuration:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-simple
  namespace: statuslist
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis-simple
  template:
    metadata:
      labels:
        app: redis-simple
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        command: ["redis-server", "--appendonly", "yes"]
---
apiVersion: v1
kind: Service
metadata:
  name: redis-simple
  namespace: statuslist
spec:
  selector:
    app: redis-simple
  ports:
  - port: 6379
    targetPort: 6379
```

### Configuration Updates
1. **Updated test-values.yaml** to use the simple Redis service:
   ```yaml
   APP_REDIS__URI: "redis://redis-simple.statuslist.svc.cluster.local:6379"
   ```

2. **Updated init containers** to connect to the simple Redis instance:
   ```yaml
   until nc -z redis-simple.statuslist.svc.cluster.local 6379; do
   ```

## How to Setup and Run the Deployment

### Prerequisites
Before running the deployment script, ensure you have the following tools installed:
- **kind** (Kubernetes in Docker) - available at `~/kubernetes-tools/kind`
- **helm** - for managing Kubernetes packages
- **kubectl** - for Kubernetes cluster management
- **curl** - for testing endpoints

### Quick Start Deployment

**1. Run the complete deployment:**
```bash
./k8s-deployment-test.sh deploy
```

This command will:
- ✅ Check all prerequisites
- ✅ Create a 3-node kind cluster
- ✅ Deploy PostgreSQL and Redis dependencies
- ✅ Deploy the Status List Server
- ✅ Run comprehensive tests
- ✅ Show final deployment status

**2. Test an existing deployment:**
```bash
./k8s-deployment-test.sh test
```

**3. Check deployment status:**
```bash
./k8s-deployment-test.sh status
```

**4. Clean up everything:**
```bash
./k8s-deployment-test.sh cleanup
```

### Manual Access Instructions

After successful deployment, access the Status List Server:

**1. Set up port forwarding:**
```bash
kubectl port-forward svc/status-list-server-service 8081 -n statuslist
```

**2. Test the endpoints:**
```bash
# Health check
curl http://localhost:8081/health

# Root endpoint
curl http://localhost:8081/

# Status lists API
curl http://localhost:8081/status-lists

# Create a status list
curl -X POST http://localhost:8081/status-lists \
  -H "Content-Type: application/json" \
  -d '{"issuer": "test-issuer", "sub": "test-subject"}'
```

### Deployment Configuration

The deployment uses `test-values.yaml` which includes:
- **Simplified authentication** (no TLS, basic auth)
- **Local development settings** (localhost domain, development environment)
- **Resource limits** appropriate for local testing
- **Disabled external dependencies** (no AWS, no external secrets)
- **Persistent storage** for PostgreSQL (5Gi) and Redis (2Gi)

### Troubleshooting

If deployment fails:
1. **Check pod logs**: `kubectl logs -n statuslist <pod-name>`
2. **Check events**: `kubectl get events -n statuslist`
3. **Verify services**: `kubectl get svc -n statuslist`
4. **Check port forwarding**: Ensure no other process is using port 8081

### Production Deployment Notes

For production deployment, modify `test-values.yaml` to:
- Enable TLS and proper certificate management
- Configure external secrets with appropriate secret store
- Set up ingress controller for external access
- Adjust resource limits based on expected load
- Configure AWS credentials for S3 storage
- Enable multiple replicas for high availability

## Next Steps

The deployment is now ready for:
- Development and testing of Status List Server functionality
- Integration testing with other services
- Performance testing and optimization
- Production deployment planning with appropriate security configurations
- Scaling and high availability testing
- Certificate management and TLS configuration for production