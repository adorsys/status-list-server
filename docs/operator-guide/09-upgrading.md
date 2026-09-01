# 09 — Upgrading

This guide covers version migrations, database schema migrations, and Helm upgrade
procedures for the Status List Server, including rollback.

## 1. Version migration checklist

Before upgrading from one release to the next:

1. **Read the release notes / CHANGELOG** for the target version — note any **breaking
   changes** (env var renames, removed features, chart defaults that changed).
2. **Check `.env.template`** deltas for new/renamed `APP_*` variables and their new
   defaults. Map them into your values (see
   [04-configuration-reference.md](04-configuration-reference.md)).
3. **Confirm the image variant** still matches your backend — a version may change the
   default feature set; re-check your `statuslist.image.tag` suffix against
   [02-choosing-your-image.md](02-choosing-your-image.md).
4. **Pin the exact image**: prefer deploying by content **digest**, not a mutable tag.
5. **Validate the new chart** renders cleanly before touching the cluster (see §3).

### Upgrade-safe config rules

- Never put `APP_DATABASE__URL` or a plain `APP_DATABASE__PASSWORD` in `statuslist.env` —
  the chart rejects them (see [04-configuration-reference.md](04-configuration-reference.md)).
- Keep the app Secret named `statuslist-secret`; changing it is rejected.
- If you change `APP_DATABASE__POOL__MAX_CONNECTIONS`, do so together with the
  replica/HPA change in the **same** upgrade to avoid a transient connection spike (see
  [07-scaling-and-availability.md](07-scaling-and-availability.md)).

## 2. Database schema migrations

Schema migrations are applied by the application at startup (SeaORM-based migrations for
the `postgres`/`mysql`/`sqlite` backends). The server runs pending migrations before it
becomes ready, so:

- **Rolling upgrades handle migrations**: with `replicaCount>1`, the new pod applies
  migrations, then passes readiness; the other replicas roll over. Use `--wait --atomic`.
- **Back up the database first** for major-version migrations:

  ```bash
  # Postgres example (bundled or external)
  kubectl exec -n statuslist deployment/statuslist-postgres -- \
    pg_dump -U postgres status-list > backup-$(date +%F).sql
  ```

- Migration failure stops the new pod from becoming ready; the `--atomic` upgrade rolls
  back automatically.

## 3. Helm upgrade procedure

Always render/validate first, then upgrade with the atomic/wait flags:

```bash
# 1. Validate
helm template statuslist helm/chart \
  --namespace statuslist --values my-values.yaml > /tmp/rendered.yaml

# 2. Upgrade (atomic + wait → automatic rollback on failure)
helm upgrade --install statuslist helm/chart \
  --namespace statuslist \
  --values my-values.yaml \
  --atomic --wait --timeout 10m

# 3. Verify
helm status statuslist -n statuslist
helm history statuslist -n statuslist
kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist
kubectl logs -l app.kubernetes.io/name=status-list-server -n statuslist --tail=100
```

### Pinning the image by digest

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist \
  --set-string statuslist.image.repository=ghcr.io/adorsys/status-list-server \
  --set-string statuslist.image.tag=0.6.0-aws \
  --set-string statuslist.image.digest=sha256:<digest> \
  --atomic --wait --timeout 10m
```

> [!WARNING]
> **Do not use `--reuse-values` with only a changed tag.** The stored `digest` (if any)
> takes precedence over the tag, so the upgrade reports success while the running image
> is unchanged. Pass both the new tag **and** the new digest, or clear the digest with
> `--set statuslist.image.digest=null` when intentionally moving to tag-only deployment.

### Using a values file vs `--set`

Keep environment-specific configuration in committed values files; use `--set` only for
ephemeral overrides (image tag/digest). This avoids drift between what you tested and
what you deployed.

## 4. Rollback

Two paths:

- **Automatic** (failed upgrade): because deploys use `--atomic --wait`, Helm rolls back
  during the pipeline when readiness fails or the timeout elapses.
- **Manual** (successful-but-bad upgrade): choose a previous revision and roll back.

```bash
helm history statuslist -n statuslist

helm rollback statuslist <revision> -n statuslist --wait --timeout 10m
kubectl rollout status deployment/statuslist-status-list-server-deployment -n statuslist
```

After a rollback, confirm the signing key/cert used by the reverted image still matches
the backend/filesystem (a version that changed key material could leave the reverted
pods unable to sign — see [05-token-signing-credentials.md](05-token-signing-credentials.md)).

## 5. Redis-removal / breaking-change cleanup

Some chart versions removed components (e.g. the Redis HA subchart). An upgrade to such a
version **orphans** resources Helm does not delete. Before adopting, clean up former
resources as documented in [docs/deployment-runbook.md](../deployment-runbook.md)
(remove the orphaned HAProxy TLS secret and Redis PVCs). Treat any leftover production
private-key-containing Secret as sensitive.

## 6. Post-upgrade smoke test

```bash
curl -s https://<your-host>/health/live
curl -s https://<your-host>/health/ready
curl -s https://<your-host>/metrics | head            # metrics endpoint (if enabled)
helm status statuslist -n statuslist
```

Confirm issued tokens still verify and that `/health/ready` is green before closing the
upgrade.

## Related

- [03-helm-installation.md](03-helm-installation.md) — initial installs and values layout.
- [06-secret-rotation.md](06-secret-rotation.md) — rotating material after an upgrade.
- [04-configuration-reference.md](04-configuration-reference.md) — env var reference for migration mapping.
- [docs/deployment-runbook.md](../deployment-runbook.md) — the release-pipeline deploy equivalent.
