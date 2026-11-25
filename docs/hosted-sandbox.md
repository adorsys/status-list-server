# Hosted sandbox deployment

The hosted sandbox is a test-only trust domain. Its tokens must never be accepted
as production status assertions. See the [trust model](trust-model.md).

## Scope and prerequisites

The hosted profile runs either as a dedicated release or on an existing one.

- A dedicated release uses `deploy/helm/chart/values-hosted.yaml`, which
  configures the existing three listeners, PostgreSQL, ingress, network
  policies, and alerts. It does not deploy the portal, an ingress controller, a
  VPN, or a mutual-TLS gateway. Use a dedicated namespace and PostgreSQL storage,
  an independent issuer registry, and independent signing keys. Do not layer
  `values-production.yaml` or `values-aws.yaml` onto this overlay. These
  reference the current production configuration. The hosted overlay uses the
  filesystem certificate image variant.
- An existing release keeps its own overlays, hostname, registry, signing keys,
  and database, and adds the hosted settings to its site overlay. See
  [hosted profile on an existing release](#hosted-profile-on-an-existing-release).

The rest of this section, [edge configuration](#edge-configuration), and
[installation](#installation) describe a dedicated release.

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
and production refuses to start. The server's public-read budget, a burst of
1,000 then one request every 5 ms per client, sits above the edge's per-client
100 requests/second, so the edge limit is the one clients hit. The admin
listener has its own per-client budget, configured with
`APP_RATE_LIMIT__ADMIN_*`. The NetworkPolicy and admin authentication also
bound that listener.
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

## Hosted profile on an existing release

A running release can switch to the hosted profile in place. Its hostname,
signing identity, issuer registry, and database stay, and from then on they are
shared with the issuers the portal registers. Switch only a release whose
signing identity no production relying party trusts; see the
[trust model](trust-model.md#hosted-profile-on-an-existing-release).

Add these to the release's last site overlay, as
`deploy/helm/chart/values-datev-staging.yaml` does for the `statuslist` release:

- `APP_SERVER__PROFILE: hosted`. The server refuses to start on the memory
  database backend, and on PostgreSQL or MySQL with
  `APP_DATABASE__POOL__MAX_CONNECTIONS` below 2.
- `statuslist.ingress.externalDnsHostname` set to the hostname the release
  already serves. The hosted profile refuses to render without it, and the same
  value keeps `APP_SERVER__DOMAIN` and the published URLs unchanged.
- `APP_RATE_LIMIT__CLIENT_IP_SOURCE=rightmost_x_forwarded_for` and
  `APP_RATE_LIMIT__TRUSTED_PROXIES` set to the edge pods' address range. The
  hosted profile refuses to render behind an ingress with `connect_info`, and
  with the management ingress or gateway on, without trusted proxies. The edge
  must replace `X-Forwarded-For` rather than append to it: ingress-nginx does
  with `use-forwarded-headers` and `compute-full-forwarded-for` off, its
  defaults. Over `values-production.yaml`, also restore the default
  `APP_RATE_LIMIT__PERMISSIVE_*` values, which that overlay lifts for
  `connect_info`. For Envoy Gateway, `values-envoy-gateway.yaml` sets all three
  and admits only the Envoy proxies to the public and management ports.
- Distinct management and admin audiences. A release that already has both
  keeps them.
- `statuslist.networkPolicy.enabled: true` with `ingress` and
  `managementIngress` for the edge pods, `adminIngress` for the portal, and
  `prometheusIngress` for Prometheus. The hosted profile refuses to render
  with either edge list empty: an empty `ingress` admits every pod in the
  cluster to the public port, and an empty `managementIngress` denies every
  management request. The portal's server and its reminders
  CronJob call the admin API; its migration job does not. Database egress
  follows the chart default for the bundled PostgreSQL; set `databaseEgress`
  for an external database.
- `APP_RATE_LIMIT__ADMIN_BURST_SIZE` sized for the portal. The admin budget is
  per client address and per replica, and each portal pod is one client. The
  period is whole seconds, so a pod can sustain at most one admin request per
  second and replica; the burst absorbs page views and registrations above that.
- A CNI that enforces NetworkPolicy. On EKS, the VPC CNI enforces it only with
  network policy turned on in the add-on; otherwise the policy is accepted and
  ignored.

Before the upgrade that switches the profile, add the portal backend under
`admins` in the release's existing registry, with its public key and the
`issuers:read` and `issuers:write` scopes, and keep every issuer already listed.
Validate the file with `status-list-server issuer-registry` and confirm the
reload as the
[deployment runbook](deployment-runbook.md#rotate-or-revoke-issuer-keys)
describes. The admin audience must be configured before the registry lists
admins. Admins are accepted in the private profile too, so this step can come
first.

Registry issuers keep authenticating after the switch: the server resolves
registry keys first and rejects any portal registration that collides with
them. Switching back to the private profile stops trusting the issuers the
portal registered. Their lists stay public.

After the switch, verify:

- `python3 scripts/check-hosted-sandbox.py <hostname>` passes. The release-tag
  deployment runs it for `statuslist.eudi-adorsys.com`.
- A portal server pod reaches the admin port, and a pod in another namespace
  is refused. The portal image has no shell, so the first probe runs in a debug
  container that shares a portal server pod's network:

  ```bash
  ADMIN=http://statuslist-status-list-server-internal-service.statuslist:8002/health/ready
  PORTAL_POD=$(kubectl -n status-list-portal get pod -o name \
    -l app.kubernetes.io/name=status-list-portal,app.kubernetes.io/component=server | head -n 1)
  kubectl -n status-list-portal debug -i "$PORTAL_POD" --image=busybox:1.37 -- \
    wget -qO- -T 5 "$ADMIN"
  kubectl -n default run admin-probe --rm -i --restart=Never \
    --image=busybox:1.37 -- wget -qO- -T 5 "$ADMIN"
  ```

  The first prints the readiness answer; the second must time out.
- A registry issuer publishes with an authenticated write, and Prometheus still
  scrapes the release.

## Admin access and readiness

The overlay allows admin connections only from these peers:

- Portal: namespace `status-list-portal` **and** pod label
  `app.kubernetes.io/name: status-list-portal` **and**
  `app.kubernetes.io/component` `server` or `reminders`, in the same peer entry
  under `statuslist.networkPolicy.adminIngress`. The portal's migration job
  calls no admin route, so keep its component label out of that list.
- Prometheus: namespace `monitoring` **and** pod label
  `app.kubernetes.io/name: prometheus`, under
  `statuslist.networkPolicy.prometheusIngress`. This list is admitted only when
  `serviceMonitor.enabled` is true.

Override both selectors when the portal or Prometheus run elsewhere or under
other labels. Keep any portal workload that does not call the admin API out of
the selector. Public and management ports admit only the
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
origin using HTTPS. The release-tag deployment runs it against
`statuslist.eudi-adorsys.com` after every upgrade and fails the job when three
attempts, 20 seconds apart, do not pass; it does not roll the release back.

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
