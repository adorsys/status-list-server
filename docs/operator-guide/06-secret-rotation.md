# 06 — Secret & Credential Rotation

This guide covers rotating the credentials the Status List Server holds, with zero
downtime. There are three rotation domains, each with different mechanics:

1. **Token signing identity** (the crown jewel — key + issuer certificate).
2. **Cloud/Vault access credentials** (the backend identity that reads the signing key).
3. **Database password** (delivered via the `statuslist-secret` Secret).

None of these should cause downtime if done correctly. This page explains the
in-place **file re-read** behavior, the ACME **renewal cron**, **Vault lease renewal**, the
role of the **signing-key cache TTL**, and the rollback/failure handling for each.

## 0. The two rotation primitives

The server rotates material two ways, and it is important not to confuse them:

| Primitive            | What happens                                                                                                                                  | Downtime                                            | When                                                    |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------- |
| **In-place re-read** | The pod keeps running and the next signing action reads the **new** key/cert from the file or backend (subject to the signing-key cache TTL). | None                                                | `store` keys/certs, backend material                    |
| **Rolling restart**  | A new ReplicaSet is rolled out (new pod), which re-reads material at startup.                                                                 | Zero (with `replicaCount>1` + rolling update / HPA) | ACME key material, or when a file **path/name** changes |

For the **token signing identity**, prefer **in-place re-read** so verifiers see a
smooth transition and you never mint a token with the wrong key between restarts.

## 1. Filesystem (`-fscert`) token signing key rotation

The filesystem store provider **re-reads the file on each signing-key read**. There is
**no inotify/file-watch**; rotation is picked up on the next read, gated by
`APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL`.

### Recommended: atomic in-place replacement (no restart)

Overwrite the mounted files with new material **atomically** so a reader never sees a
half-written file:

```bash
# 1. Create the new key + cert
openssl genpkey -algorithm ED25519 -out new-signing-key.pem
openssl req -new -x509 -key new-signing-key.pem -out new-issuer-cert.pem \
  -days 365 -subj "/CN=statuslist.example.com"

# 2. Update the Kubernetes Secret
kubectl -n statuslist create secret generic signing-credentials \
  --from-file=certificate=new-issuer-cert.pem \
  --from-file=signing-key=new-signing-key.pem \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Force the mounted Secret/projected volume to update (K8s < 1.27 needs a restart
#    of the pod to re-project projected Secrets; see note below).
```

> [!NOTE]
> **Projected/secret volumes** are updated by kubelet, but the application only re-reads
> the file at its moment of use. To guarantee the pod observes the new bytes **without a
> custom reload**, either:
>
> - Set `APP_SERVER__CERT__SIGNING_KEY_CACHE_TTL=0` so every signing key read goes to the
>   file (maximum freshness, no restart), **and**
> - Ensure the file path is unchanged (atomic rename onto the same path). If you change
>   the **path/name**, the pod must be restarted to mount the new one.

The `SIGNING_KEY_CACHE_TTL` interplay:

- `0` (default): every signing-key read hits the file/backend. Rotation visible on the
  next signed token. **Recommended for rotation-critical environments.**
- `>0`: reads are served from an in-memory cache for that many seconds; a rotated file
  is only observed after the cache expires or a certificate event invalidates the
  certificate chain cache. Use for latency-sensitive, rarely-rotated keys.

### Alternative: rolling restart

If your provisioning tool writes to a **new path/name** (e.g. rotation creates
`signing-key.v2.pem`), you must apply a new config that points
`APP_SERVER__CERT__STORE__SIGNING_KEY_PATH` at the new file. That changes the Deployment
pod template and triggers a rolling restart — zero downtime with multiple replicas:

```bash
helm upgrade --install statuslist helm/chart \
  --namespace statuslist \
  --set statuslist.env.APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=/etc/status-list-signing/signing-key.v2.pem \
  --set statuslist.env.APP_SERVER__CERT__STORE__CERTIFICATE_PATH=/etc/status-list-signing/certificate.v2.pem \
  --wait --timeout 10m
```

Then delete the old files/secret entries once every replica has rolled.

## 2. ACME signing identity renewal (`acme` strategy)

With `PROVISIONING_STRATEGY=acme`, the server renews its own identity:

- Runs on `APP_SERVER__CERT__RENEWAL_CRON_SCHEDULE` (6-field cron, default `0 0 0 * * *` =
  daily at 00:00). On each tick it calls `renew_cert_if_needed()`.
- Renewal triggers when the current certificate is near expiry (see `RenewalStrategy`:
  days-before-expiry, percentage-of-lifetime, or fixed interval).
- On success the parsed **certificate chain cache is invalidated/replaced** and stays hot
  — non-provisioning replicas pick up the renewed chain from the cache without restart.
- The **signing key** is written back to the backend and read per `SIGNING_KEY_CACHE_TTL`.

There is a small window between the old key being retired in the backend and the cache
expiry on other replicas; with `SIGNING_KEY_CACHE_TTL>0`, replicas may still sign with the
old key briefly. Set it to `0` to make ACME-rotated keys visible everywhere immediately.

## 3. Vault / OpenBao auth token renewal

When the application authenticates to Vault/OpenBao (the `-vault` image) it uses the
built-in token manager:

- **Initial login** at startup (AppRole or Kubernetes SA JWT).
- **Proactive renewal** via `POST /v1/auth/token/renew-self` when **80% of the lease TTL**
  has elapsed.
- **Re-authentication fallback**: if renewal fails (expired/revoked token), it
  re-authenticates with the configured backend, automatically re-reading rotated
  Kubernetes SA tokens from disk.
- Renewal is **serialized** (double-checked locking) to prevent concurrent
  renew/login stampedes.

### Rotating a Vault login credential without downtime

Because the app re-authenticates automatically on renewal failure, rotating the
underlying `role_id`/`secret_id` (AppRole) or the Kubernetes SA role does **not** require
a pod restart. Replace the secret at the source, and the next renewal failure triggers a
clean re-login with the new credential:

| Credential          | Where to rotate                                                                        | Effect                                        |
| ------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------- |
| AppRole `secret_id` | Vault `vault write -f auth/approle/role/<role>/secret-id` + update the injected secret | Next renewal/re-login uses it                 |
| Kubernetes SA token | Let Vault's K8s auth rotate the projected token                                        | Auto re-read from `APP_VAULT__K8S_TOKEN_PATH` |

Failure telemetry is emitted as OpenTelemetry counters (`vault_auth_renewals_total`,
re-authentication and failure counters) — see [08-observability.md](08-observability.md).

## 4. Database password rotation

The DB password reaches the pod as `APP_DATABASE__PASSWORD` from the `statuslist-secret`
Secret (key `postgres-password`), and PostgreSQL also references that same Secret. To
rotate the DB password:

1. Update the **secret source**:
   - ESO mode: update the value in the cloud/Vault provider; ESO re-syncs to
     `statuslist-secret` after `refreshInterval`.
   - Fallback mode: `kubectl edit secret statuslist-secret -n statuslist` and update
     `postgres-password`.
2. **Rotate the database-side password** to match (the bundled Postgres:
   `kubectl exec ... -- psql -c "ALTER USER ... PASSWORD ..."`).
3. Restart pods so the new env value is picked up (env values are read at process start):

   ```bash
   kubectl -n statuslist rollout restart deployment/statuslist-status-list-server-deployment
   kubectl -n statuslist rollout status deployment/statuslist-status-list-server-deployment
   ```

> [!TIP]
> Because `APP_DATABASE__PASSWORD` comes from `secretKeyRef` (not an env literal), you
> update only the Secret — the chart forbids setting it as a plain env value. Keep ESO's
> `refreshInterval` aligned with your password rotation cadence.

## 5. Ingress TLS certificate rotation

Rotating the ingress TLS certificate (cert-manager) has **no effect** on issued status
tokens — it only re-provisions the ingress Secret. This is handled by your normal
cert-manager/ingress flow and is unrelated to the signing identity. See
[05-token-signing-credentials.md](05-token-signing-credentials.md) for the distinction.

## 6. Failure handling & rollback

| Failure                   | Detection                                                                                     | Response                                                                 |
| ------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Signing-key read fails    | Application logs + `cert_renewal_failures` metric; pod may fail readiness on `store` failures | Restore/rotate the file/backend value; re-check `/health/ready`          |
| ACME renewal fails        | `cert_renewal_attempts` / `cert_renewal_failures` counters + logs                             | Investigate DNS/ACME provider; existing cert stays valid until expiry    |
| Vault token renewal fails | `vault_auth_renewals_total`, re-auth & failure counters                                       | Auto re-login; if it persists, check Vault reachability and role binding |
| Half-rolled keys          | Verify signed tokens with the _new_ issuer key; verifiers must see the new key                | Complete rotation; never use a partially-applied file                    |

Always validate after any rotation that newly-minted tokens verify with the intended
issuer key, and that `/health/ready` stays green.
