# Hosted sandbox deployment

The hosted sandbox is a test-only trust domain. Its tokens must never be accepted
as production status assertions. See the [trust model](trust-model.md).

## Scope and prerequisites

`deploy/helm/chart/values-hosted.yaml` configures the existing three listeners,
PostgreSQL, ingress, network policies, and alerts. It does not deploy the portal,
an ingress controller, a VPN, or a mutual-TLS gateway.

Use a dedicated namespace and PostgreSQL storage, an independent issuer registry,
and independent signing keys. Do not layer `values-production.yaml` or
`values-aws.yaml` onto this overlay. These reference the current production
configuration. The hosted overlay uses the filesystem certificate image variant.

Before installation, provide:

- An ingress-nginx controller and a NetworkPolicy-enforcing CNI.
- Prometheus Operator CRDs, with discovery labels matching `serviceMonitor.labels`
  and `prometheusRule.labels` in your monitoring installation.
- A sandbox-only issuer registry ConfigMap, default name `sandbox-issuers`, with
  the registry file `issuers.yaml`. Add the portal backend under `admins` with
  public keys and `issuers:read` and `issuers:write` scopes. Registry loading
  remains mandatory in hosted mode.
- A sandbox-only signing Secret, default name `sandbox-signing`, with `tls.crt`
  (the PEM signing chain) and `tls.key` (the matching private key). Override the
  signing entry in `statuslist.secretMounts` to change its name or paths; lists
  are replaced when overlaying values, so retain the database mount too.
- A separate ingress TLS Secret covering the chosen hostname(s). Transport TLS
  and status-token signing have different trust roles.

Hostnames, TLS Secret names, management and admin audiences, trusted proxy
addresses, release namespace, and network selectors are site-specific values.
No deployed ADORSYS hostname is supplied.

## Edge configuration

Apply `deploy/helm/ingress-nginx-hosted.yaml` to a **dedicated ingress-nginx
controller**. It is not an application chart values file. The profile uses
IngressClass `hosted-sandbox`; install the controller as release
`hosted-sandbox-ingress` in namespace `ingress-nginx-hosted` to match the
application NetworkPolicy selectors, or override those selectors for your
deployment. The controller values set a distinct controller class and leader
election ID so the shared nginx controller does not claim these Ingresses.
For the supported direct-edge topology, the profile disables
incoming forwarded-header trust and full-chain appending, so nginx overwrites
`X-Forwarded-For` with its connection-derived client address. It also configures
rate-limit rejections as HTTP 429 and preserves source addresses with
`externalTrafficPolicy: Local`.

Do not apply this to a shared controller without assessing its other users.
A CDN or HTTP proxy in front of nginx needs a separately reviewed trusted-proxy
configuration; do not enable forwarded-header trust for arbitrary peers. See the
[ingress-nginx configuration reference](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/).

For a chart-based controller installation, use the matching release and namespace:

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm upgrade --install hosted-sandbox-ingress ingress-nginx/ingress-nginx \
  --namespace ingress-nginx-hosted --create-namespace \
  -f deploy/helm/ingress-nginx-hosted.yaml
```

The overlay supplies initial, operator-tunable per-IP edge budgets:

- Public ingress: 100 requests/second, burst multiplier 5.
- Management ingress: 10 requests/second, burst multiplier 5.

These are starting values to tune for the deployment.
Override the `nginx.ingress.kubernetes.io/limit-rps` and
`nginx.ingress.kubernetes.io/limit-burst-multiplier` annotations on each ingress.
Ingress limits are per controller replica and multiply when controllers scale;
they are not a distributed cluster-wide quota. A shared global budget requires
an upstream gateway with shared state. The overlay sets
`APP_RATE_LIMIT__CLIENT_IP_SOURCE=rightmost_x_forwarded_for`, so the server's
limits key on the client address from the controller's overwritten
`X-Forwarded-For`. That needs `APP_RATE_LIMIT__TRUSTED_PROXIES` to list the
controller pods' addresses or CIDR; without it, the chart refuses to render
and production refuses to start. The server's public-read and admin budgets, a
burst of 1,000 then one request every 5 ms per client, sit above the edge's
per-client 100 requests/second, so the edge limit is the one clients hit.
See the
[ingress-nginx rate-limit semantics](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#rate-limiting).

## Installation

For example, create a site values file using your own non-production names:

```yaml
statuslist:
  ingress:
    externalDnsHostname: sandbox.example.org
    tls:
      secretName: sandbox-edge-tls
  env:
    APP_MANAGEMENT_AUTH__AUDIENCES: https://sandbox.example.org/api/v1
    APP_ADMIN_AUTH__AUDIENCES: https://sandbox.example.org/admin
    APP_RATE_LIMIT__TRUSTED_PROXIES: 10.244.0.0/16
```

Replace the trusted-proxy example with the addresses or CIDR of the dedicated
controller pods in your cluster. Keep it narrow and ensure other pods cannot
reach the management listener under another NetworkPolicy. The admin audience
must differ from the management audience; production startup rejects an empty
admin audience when the registry lists admins.

Then install into the chosen isolated namespace:

```bash
helm dependency build deploy/helm/chart
helm upgrade --install sandbox deploy/helm/chart \
  --namespace YOUR_SANDBOX_NAMESPACE --create-namespace \
  -f deploy/helm/chart/values-hosted.yaml -f sandbox-site.yaml \
  --wait --timeout 5m
```

Keep the runtime environment `production`: the sandbox still needs production
security validation, including a nonempty management audience. `server.profile`
selects `hosted`; the environment does not select the trust domain.

By default both ingress resources use one hostname and IngressClass
`hosted-sandbox`. Management paths for
`statuses`, `allocations`, and `credentials` route to the management Service port;
public reads route to the public Service. To use a separate management origin,
set `statuslist.ingress.management.hostname` and its `tls.secretName` to a Secret
covering that hostname. Neither ingress routes to admin. NetworkPolicy applies
to pod target ports, not Service port numbers.

## Admin access and readiness

The overlay allows admin connections only from these peers:

- Portal backend: namespace `sandbox-portal` **and** pod label
  `app.kubernetes.io/name: sandbox-portal-backend`, in the same peer entry under
  `statuslist.networkPolicy.adminIngress`.
- Prometheus: namespace `monitoring` **and** pod label
  `app.kubernetes.io/name: prometheus`, under
  `statuslist.networkPolicy.prometheusIngress`. This list is admitted only when
  `serviceMonitor.enabled` is true.

Override both selectors for the actual deployments. Keep the portal frontend out
of the permitted backend selector. Public and management ports admit only the
selected `hosted-sandbox-ingress` controller pods in `ingress-nginx-hosted`.
NetworkPolicy permissions are additive: audit
other policies selecting these pods for broader grants. Enabling policy without
a CNI that enforces it does not establish isolation.

There is no admin ingress or public admin LoadBalancer. If operators need remote
admin access, add a peer for their VPN or mutual-TLS gateway to `adminIngress`,
with both its namespace and pod selector. Do not admit the public ingress
controller to the admin port. Gateway network authentication does not replace
admin JWT authentication for admin API requests.

Readiness remains `GET /health/ready` on the admin container port. Kubernetes
allows traffic from the pod's node, so kubelet HTTP probes do not require a
public admin rule; see [NetworkPolicy behavior](https://kubernetes.io/docs/concepts/services-networking/network-policies/).
On the first cluster deployment, confirm readiness with the policy enabled:

```bash
kubectl -n YOUR_SANDBOX_NAMESPACE wait --for=condition=Ready pod \
  -l app.kubernetes.io/instance=sandbox --timeout=120s
```

Also verify Prometheus scraping, a connection from a selected portal backend pod,
and denial from an unrelated namespace. Render tests verify the policy and probe
wiring; only a deployment on the actual CNI verifies its enforcement.

## Alerts

With `prometheusRule.enabled`, the existing rule resource also includes:

- `IssuerRegistryReloadFailures`: a failed reload state lasting 1 minute. The
  alert stays active until a reload succeeds on every affected replica. The
  last valid registry remains active; fix the mounted document and verify reload.
- `ListQuotaRejectionsSpike`: more than 10 quota rejections in 5 minutes,
  sustained for 5 minutes. Inspect issuer usage and abuse before raising limits.
  `list_quota_rejections_total` counts HTTP `list_quota_exceeded` responses;
  quota exhaustion is HTTP 400, not rate-limit HTTP 429.
- `ManagementAuthFailuresSpike`: more than 50 missing-token or rejected-token
  requests in 5 minutes, sustained for 5 minutes. Check token audience, key IDs,
  registry changes, and abusive clients. Successful requests and trust-backend
  outages do not count toward this alert.

The management authentication instrument already ends in `_total`, and the
in-process Prometheus exporter appends another suffix. Its alert reads
`management_auth_requests_total_total`. The registry reload alert reads the
persistent `issuer_registry_reload_failed` gauge; the new quota instrument
exports `list_quota_rejections_total`.

Tune the latter two thresholds with `slo.listQuotaRejections` and
`slo.managementAuthFailures`. Alerts aggregate replicas within the release
namespace. Connect the existing alert-routing configuration to your monitoring
installation; rule creation alone does not deliver notifications.

## External acceptance check

After the first deployment, run the Python 3 check against every published
origin using HTTPS:

```bash
python3 scripts/check-hosted-sandbox.py sandbox.example.org
python3 scripts/check-hosted-sandbox.py sandbox.example.org \
  --management-hostname management.sandbox.example.org
```

The check validates TLS, refuses redirects, requires admin paths to return 404,
and requires management operations without a token to return the application's
401 `missing_token` response. With separate hosts, the public host must return
404 for management operations. Retired credential registration must reject the
request. Connection errors, generic login pages, missing management routes, and
successful anonymous operations fail the check. Requests use an invalid empty
write body and no credentials; the script never prints response bodies.

This is an HTTP surface check, not a port scanner or proof of internal policy
isolation. Separately inspect published Services/load balancers and confirm that
no admin port is exposed. Verify an authenticated issuer write as well; anonymous
rejection alone does not prove that valid credentials can write.
