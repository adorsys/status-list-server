<!-- markdownlint-disable MD013 MD060 -->

# Multi-POD Operation

In a production setup, especially when running highly critical infrastructure such as an IDP or block lists, it is mandatory to run the service in a multi-pod/high-availability setup.

Multiple pods can connect to one SQL database and shared certificate storage, but the application does not coordinate all state and control-plane work across multiple pods.

## Areas

| Area | Current Behaviour | Multi-Pod Consequences | How to Fix |
|---|---|---|---|
| Status List can become inconsistent | Each process/POD maintains its own status cache. A writer invalidates only its own cache after committing to SQL. | A second pod can freshly sign stale `VALID`, `SUSPENDED`, or `INVALID` data until its local TTL expires. The default TTL is 300 seconds, which means this issue can happen whenever another pod has cached the previous version. | **Quickfix:** On multi-pod deployments, `APP_CACHE__TTL` must be `0`. **Longterm Fix:** Use shared status-list caching with cross-pod invalidation or version-aware reads. Redis can be used for this, but the current Redis integration only caches certificate material and does not fix the status-list cache issue. **PoC:** [`poc_multi_pod_stale_status_cache.py`](poc_multi_pod_stale_status_cache.py) reproduces this issue with two pods. After the PATCH has returned `200 OK`, it must return `INVALID` from both pods. See [Local Reproduction](#local-reproduction) or [Docker Reproduction](#docker-reproduction). |
| Certificate Lifecycle | Every process can provision and renew certificates. There is no leader/follower or distributed coordination for this. | Concurrent pods or an overlapping rollout can create inconsistent keys/certificates and ACME DNS work. | The application should not manage certificate-issuance infrastructure. Certificate material should be provided from outside, for example by Terraform/configuration or one fenced controller. |
| False Positive Readiness -> Routing/Readiness | Liveness and readiness probes call the `/health` endpoint. There is no check whether the SQL database is ready or the service has signing material to use. Loading key material is done only when the key is required, which is too late. | Kubernetes can route requests to a pod that returns 500/503 because underlying dependencies such as SQL or key material do not work. | Add separate liveness, readiness, and startup checks. Readiness must check that infrastructure is ready and that valid, matching signing material is present and working. |
| Rate Limiting | Each pod has its own rate limits and cache. There is no shared queue or cluster-wide limit. | Each pod maintains its own state. | Enforce rate limits through infrastructure such as a Kubernetes ingress or API gateway. Rate limiting should not be done inside the application unless it is really necessary. |
| Parallel startup and migrations | For a reproducible local run, start pod A first, wait for `/health`, then start pod B. Starting both at once can race database migrations and fail before the cache path is exercised. | Starting pods at the same time can fail during database migration and prevent the service from starting. | Run database migrations as an exclusive job in the deployment pipeline before starting or rolling out web pods. |
| Deployment and recovery | Each pod runs migrations, infrastructure changes, and certificate control-plane work. | Each pod runs infrastructure logic. This can cause inconsistencies when deploying new versions. You might need to roll back or have two different versions running concurrently for some time. | Database migrations are usually done using Liquibase inside the pipeline. An S3 bucket should always be provided through configuration and never created inside code. The code should never manage infrastructure components because this is hard to maintain or debug. |

The direct cache failure follows this sequence:

```text
GET -> pod A -> cache V1 (VALID)
PATCH -> pod B -> SQL V2 (INVALID) -> invalidate pod B only -> 200 OK
GET -> pod B -> SQL/cache V2 -> newly signed INVALID
GET -> pod A -> cache V1 -> newly signed VALID
```

Relevant implementation evidence is in `src/outbound/cache.rs:11-48`, `src/domain/service.rs:198-220`, `src/server/handlers/status_list/utils/token.rs:53-118`, `src/startup.rs:74-94`, and `helm/chart/values.yaml:68-99`.

## Proof of Concept: Stale Revocation Across Two Pods

This focused package overlaps with the umbrella `application-functional-bugs` suite. Keep it separate when debugging multi-pod behavior, cache coherence, readiness, or Kubernetes rollout safety.

Run this only in a disposable namespace or local sandbox. It writes one synthetic issuer and one synthetic list. Both processes must use the same SQL database, have `APP_CACHE__TTL` greater than zero, and be able to serve signed JWT responses. Address each pod directly so a Service or ingress cannot change the selected backend.

For a reproducible local run, start pod A first, wait for `/health`, then start pod B. Starting both at once can race database migrations and fail before the cache path is exercised.

### Local Reproduction

Build the server, start a disposable Postgres instance, then launch two app processes with explicit store-mode certificate material:

```bash
cargo build --features postgres
docker run -d --name poc-multi-pod-pg \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=status-list \
  -p 15432:5432 \
  postgres:18.4
docker exec poc-multi-pod-pg pg_isready -U postgres
```

Terminal 1:

```bash
env APP_TELEMETRY__ENABLED=false \
  APP_SERVER__HOST=127.0.0.1 \
  APP_SERVER__PORT=18001 \
  APP_SERVER__CERT__PROVISIONING_STRATEGY=store \
  APP_SERVER__CERT__STORE__SOURCE=filesystem \
  APP_SERVER__CERT__STORE__CERTIFICATE_PATH="$PWD/test_data/test_cert.pem" \
  APP_SERVER__CERT__STORE__SIGNING_KEY_PATH="$PWD/test_data/ec-private.pem" \
  APP_DATABASE__URL=postgres://postgres:postgres@127.0.0.1:15432/status-list \
  APP_DATABASE__BACKEND=postgres \
  APP_CACHE__TTL=300 \
  RUST_LOG=info \
  ./target/debug/status-list-server
```

Terminal 2:

```bash
env APP_TELEMETRY__ENABLED=false \
  APP_SERVER__HOST=127.0.0.1 \
  APP_SERVER__PORT=18002 \
  APP_SERVER__CERT__PROVISIONING_STRATEGY=store \
  APP_SERVER__CERT__STORE__SOURCE=filesystem \
  APP_SERVER__CERT__STORE__CERTIFICATE_PATH="$PWD/test_data/test_cert.pem" \
  APP_SERVER__CERT__STORE__SIGNING_KEY_PATH="$PWD/test_data/ec-private.pem" \
  APP_DATABASE__URL=postgres://postgres:postgres@127.0.0.1:15432/status-list \
  APP_DATABASE__BACKEND=postgres \
  APP_CACHE__TTL=300 \
  RUST_LOG=info \
  ./target/debug/status-list-server
```

### Docker Reproduction

If you prefer containers, use the dedicated compose file in this directory:

```bash
docker compose -p multi-pod-operation \
  -f arc-review/finalReview/multi-pod-operation/docker-compose.yml up -d db app-a

docker compose -p multi-pod-operation \
  -f arc-review/finalReview/multi-pod-operation/docker-compose.yml up -d app-b
```

Then run the PoC from the host against `http://127.0.0.1:18001` and `http://127.0.0.1:18002`.

```bash
python3 arc-review/finalReview/multi-pod-operation/poc_multi_pod_stale_status_cache.py \
  --pod-a-url http://127.0.0.1:18001 \
  --pod-b-url http://127.0.0.1:18002 \
  --confirm-disposable-target
```

Tear down with:

```bash
docker compose -p multi-pod-operation \
  -f arc-review/finalReview/multi-pod-operation/docker-compose.yml down -v
```

If you are reproducing this in Kubernetes, forward each pod's application port:

```bash
kubectl -n "$NS" port-forward "pod/$POD_A" 18001:8000
kubectl -n "$NS" port-forward "pod/$POD_B" 18002:8000
```

In a third terminal, run the bounded PoC (`cryptography` is the only non-standard Python dependency):

```bash
python3 arc-review/finalReview/multi-pod-operation/poc_multi_pod_stale_status_cache.py \
  --pod-a-url http://127.0.0.1:18001 \
  --pod-b-url http://127.0.0.1:18002 \
  --confirm-disposable-target
```

The script publishes index 0 as `VALID` through pod B, reads it through pod A to cache V1, changes it to `INVALID` through pod B, and then reads both pods after the PATCH returned `200 OK`. A vulnerable run has this signature:

```text
Pod A before PATCH: status[0]=VALID(0),   iat=..., ETag="V1"
Pod B after PATCH : status[0]=INVALID(1), iat=..., ETag="V2"
Pod A after PATCH : status[0]=VALID(0),   iat=<newer>, ETag="V1"

RESULT: multi-pod stale-cache issue reproduced
```

The unchanged V1 `ETag` proves pod A returned the old database version. The newer `iat` proves the application created a new signed token after the update was acknowledged; this is not an old HTTP response retained by a client or proxy. If a pod reports healthy but the signed GET returns 500/503, verify the cert/key configuration first; the cache PoC is then inconclusive, but the signing-aware readiness problem is independently demonstrated.
