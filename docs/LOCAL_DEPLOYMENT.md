# Local Testing Quickstart

Lean checklist for running the status-list-server chart on Minikube.

## 1. Prerequisites

- Minikube ≥ v1.30 (Docker driver recommended)
- Helm ≥ v3.8
- kubectl matching the Minikube cluster

## 2. Start Minikube

```bash
minikube start
kubectl config use-context minikube
```

## 3. Prepare Secrets

Passwords can be any non-empty string; reuse for convenience.

```bash
kubectl create namespace local
kubectl create secret generic statuslist-secret -n local \
  --from-literal=postgres-password=postgres
```

## 4. Deploy

```bash
helm dependency update ./helm/chart
helm install statuslist-local ./helm/chart -n local -f ./helm/chart/values-local.yaml
```

## 5. Verify Pods

```bash
kubectl get pods -n local
```

Expect these components to reach `Running`:

- `statuslist-local-postgres-0`
- `statuslist-local-status-list-server-deployment-*`

## 6. Access the API

```bash
kubectl port-forward -n local svc/statuslist-local-status-list-server-service 8081:8081
curl http://localhost:8081/health/live
curl http://localhost:8081/health/ready
```

## 7. Tear Down

```bash
helm uninstall statuslist-local -n local
kubectl delete namespace local
minikube stop
```

## Notes

- `values-local.yaml` only overrides what differs from production defaults (NodePorts, disabled ingress/secret-store, lighter resources).
- Redis, Redis TLS, and AWS-specific resources remain disabled; no additional setup required.
- If pods fail with `CreateContainerConfigError`, check that `statuslist-secret` exists in the `local` namespace.

## Optional Redis Cache

Redis is only useful here if you want to exercise the distributed certificate-material cache path. Add `--set redis-ha.enabled=true`, add `redis-password` to `statuslist-secret`, and run an application image built with the `redis` feature plus `APP_REDIS__URI` configured. The default local chart intentionally avoids that dependency.
