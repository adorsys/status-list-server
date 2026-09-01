# 07 — Scaling & Availability

This guide covers sizing the database connection pool, configuring the
HorizontalPodAutoscaler (HPA), PodDisruptionBudget (PDB), resource quotas, and the
supporting knobs (initContainer wait, network policy) so the Status List Server stays
up under load and during cluster maintenance.

## 1. Sizing the connection pool

The database pool is configured by `APP_DATABASE__POOL__*` (see
[04-configuration-reference.md](04-configuration-reference.md)). The critical rule from
the template:

> **Size `MAX_CONNECTIONS` as `floor(server_max_connections / replica_count) - headroom`.**

Because **every replica has its own pool**, spreading the same total concurrently over N
replicas multiplies the connection count. If you double the replicas and leave
`MAX_CONNECTIONS` at 5 each, you double the connections the database sees.

```text
Example: Postgres max_connections=100, 2 replicas → 100/2 - 5 = 45 per replica
```

### Guidance

| Setting                                    | Default | Sizing guidance                                                          |
| ------------------------------------------ | ------- | ------------------------------------------------------------------------ |
| `APP_DATABASE__POOL__MAX_CONNECTIONS`      | `5`     | `floor(db_max_connections / replica_count) - headroom` (headroom ~5–10). |
| `APP_DATABASE__POOL__MIN_CONNECTIONS`      | `1`     | Number of connections kept warm; equal to `MAX` for steady workloads.    |
| `APP_DATABASE__POOL__ACQUIRE_TIMEOUT_SECS` | `5`     | Higher = tolerate DB hiccups; lower = fail fast under saturation.        |
| `APP_DATABASE__POOL__CONNECT_TIMEOUT_SECS` | `10`    | Network connect timeout.                                                 |
| `APP_DATABASE__POOL__IDLE_TIMEOUT_SECS`    | `600`   | Reap idle connections.                                                   |
| `APP_DATABASE__POOL__MAX_LIFETIME_SECS`    | `1800`  | Rotate connections before server-side drops.                             |

Recalculate `MAX_CONNECTIONS` **any time you change replica count or enable HPA**, and
put the value in the same values file as your HPA so the two stay in lockstep.

## 2. Replicas & initContainer readiness

The Deployment has an initContainer that waits for the bundled PostgreSQL to accept
connections on the configured DB port before the app starts:

```yaml
statuslist:
  initContainers: # (default wait-for-postgres)
```

The app container also relies on **readiness** probing `/health/ready` before it receives
traffic. Set a sensible `replicaCount` for your availability target:

```yaml
statuslist:
  replicaCount: 2 # ≥2 for HA; matches pool sizing above
```

## 3. HorizontalPodAutoscaler (HPA)

Enable HPA to scale on metrics. When enabled, the Deployment's `replicas` is omitted and
the HPA controls the count. Each scaled pod gets its own short-lived Workload Identity
token automatically (no per-pod cloud registration).

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 8
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 60
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 70
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
```

Validation: the chart fails if `minReplicas > maxReplicas`.

> [!IMPORTANT]
> **Recompute the DB pool whenever HPA can change replica count.** Because connections
> scale with replicas, size `APP_DATABASE__POOL__MAX_CONNECTIONS` for `maxReplicas`, not
> `minReplicas`, or cap the database side accordingly — otherwise a scale-out can exhaust
> the DB connection limit.

## 4. PodDisruptionBudget (PDB)

For voluntary disruptions (node drains, cluster upgrades), a PDB keeps the minimum number
of replicas available. Configure **exactly one** of `minAvailable` or `maxUnavailable`.

```yaml
podDisruptionBudget:
  enabled: true
  maxUnavailable: 1 # SAFE DEFAULT: allows one voluntary eviction regardless of replica count
```

> [!WARNING]
> **Never set `minAvailable >= replicaCount`.** That blocks ALL voluntary evictions
> (node drains, upgrades) indefinitely. Use `maxUnavailable: 1` as the safe default. Only
> use `minAvailable` when you specifically want `N` replicas guaranteed up (and keep it
> `< replicaCount`).
>
> Example: with `replicaCount: 2`, use `maxUnavailable: 1` (safe) — do **not** set
> `minAvailable: 2` (would block evictions forever).

The chart also sets `unhealthyPodEvictionPolicy: AlwaysAllow`, so unhealthy pods never
block voluntary disruption.

## 5. Resource quotas & requests/limits

Set realistic `statuslist.resources` so the scheduler can place pods and the HPA has a
meaningful baseline. The defaults are small:

```yaml
statuslist:
  resources:
    requests:
      memory: "256Mi"
      cpu: "250m"
    limits:
      memory: "512Mi"
      cpu: "500m"
```

For a production multi-replica deployment, raise these per your traffic profile and set a
**namespace ResourceQuota** to bound the whole deployment:

```yaml
# resourcequota.yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: statuslist-quota
  namespace: statuslist
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    count/horizontalpodautoscalers.autoscaling: "2"
    count/poddisruptionbudgets.policy: "2"
```

```bash
kubectl apply -f resourcequota.yaml
```

The bundled PostgreSQL subchart also has its own resource block under `postgres.resources`
and its own `persistence.size` (default `10Gi`, `storageClass: high-performance`). Set
both so DB storage matches your snapshot retention and cache settings.

## 6. Network policy (optional, hardening)

`statuslist.networkPolicy` is **off by default** and enabling it is a hardening step you
must scope yourself:

```yaml
statuslist:
  networkPolicy:
    enabled: true
    # Restrict ingress to your ingress controller only — an empty `ingress`
    # allows ANY source in the cluster.
    ingress:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
    # Extra internal egress destinations beyond the built-in PostgreSQL/OTel pod selectors.
    egressInternal: []
```

> [!WARNING]
> Enabling with an **empty `ingress`** renders a port-only rule with no source restriction —
> equivalent to allowing any source in the cluster. Always restrict it to your ingress
> controller namespace/pods. External egress to ports `443`/`53` is always allowed.

## 7. Availability checklist

- [ ] `replicaCount` ≥ 2 (or HPA with `minReplicas` ≥ 2).
- [ ] DB pool `MAX_CONNECTIONS` computed for the **max** replica count.
- [ ] PDB enabled with `maxUnavailable: 1` (safe default).
- [ ] `resourceQuota` and per-pod resources set.
- [ ] Readiness/liveness probes configured (defaults are sane; adjust periods for your
      DB latency).
- [ ] HPA (if used) has `minReplicas` reflecting your HA floor and re-checked pool sizing.
- [ ] Verify a controlled scale-down of a replica leaves `/health/ready` green and no
      signing errors.

## Related

- [04-configuration-reference.md](04-configuration-reference.md) — full env variable reference.
- [08-observability.md](08-observability.md) — watch HPA/PDB/probe health via metrics.
- [09-upgrading.md](09-upgrading.md) — rolling-upgrade behavior on version bumps.
