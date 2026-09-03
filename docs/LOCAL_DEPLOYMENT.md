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

> **Image tag:** the chart's default `appVersion` (`1.0.1-aws`) is a variant tag. The release
> pipeline publishes only variant-suffixed tags (`latest-aws`, `1.0.1-aws`, `sha-…-aws`, and the
> same suffixes for `gcp`, `azure`, `vault`, `fscert`); there is no unsuffixed `latest` or
> `1.0.1`. Pin a real tag for the variant you need (below: `latest-aws`), or load a locally built
> image and use `pullPolicy: IfNotPresent`. See `docs/troubleshooting.md` → "Image pull errors on variant tags".

```bash
helm dependency update ./helm/chart
helm install statuslist-local ./helm/chart -n local -f ./helm/chart/values-local.yaml \
  --set statuslist.image.tag=latest-aws --set statuslist.image.digest=null
```

> **Certificates:** the image is built with the `acme` feature, so the app tries ACME DNS-01 at
> startup unless disabled. `values-local.yaml` inherits the production cert values
> (`APP_SERVER__CERT__DNS__PROVIDER=route53`, Let's Encrypt URL, adorsys domain) from
> `values.yaml`, which blocks the HTTP server from binding. Where `--set-string` flags can't fully
> express the file mounts, use a values override file (see `docs/troubleshooting.md` → "Pod Running
> but never binds the HTTP port").

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
- AWS-specific resources remain disabled; no additional setup required.
- If pods fail with `CreateContainerConfigError`, check that `statuslist-secret` exists in the `local` namespace.
