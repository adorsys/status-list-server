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

## 3. Prepare Namespace

The chart renders the fallback `statuslist-secret` by default. Create the namespace before installing so rendered resources land in the expected place.

```bash
kubectl create namespace local
```

## 4. Deploy

> **Image tag:** the chart's default `appVersion` (`1.0.1-fscert`) is a provider-neutral variant tag.
> The release pipeline publishes only variant-suffixed tags (`latest-aws`, `latest-gcp`,
> `latest-azure`, `latest-vault`, `latest-fscert`, and matching version/sha tags); there is no
> unsuffixed `latest` or `1.0.1`. Override the tag only when you need a specific cloud variant or a
> locally loaded image. See `docs/troubleshooting.md` -> "Image pull errors on variant tags".

```bash
helm dependency update ./helm/chart
helm install statuslist-local ./helm/chart -n local -f ./helm/chart/values-local.yaml
```

> **Certificates:** the default `-fscert` image is provider-neutral and requires certificate and
> signing-key files mounted into the pod. `values-local.yaml` includes disposable local sample
> material and mounts it through `statuslist.secretMounts`. For non-local runs, provide your own
> Secret-backed files or use an image variant tailored to your environment.

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

- `values-local.yaml` only overrides what differs from neutral defaults (NodePorts, disabled ingress/secret-store, lighter resources).
- AWS-specific resources remain disabled; no additional setup required.
- If pods fail with `CreateContainerConfigError`, check that the rendered fallback `statuslist-secret` exists in the `local` namespace.
