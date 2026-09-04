# Changelog

All notable changes to this project will be documented in this file.
<!-- markdownlint-disable line-length no-bare-urls ul-style emphasis-style -->

## [1.2.0] - 2026-09-04

### Features

- [b062645](
https://github.com/adorsys/status-list-server/commit/b0626456eacea1bf9065fb672e09ad4d2cd82e4c) *(ci)* Add container image scanning by @martcpp in [#438](
https://github.com/adorsys/status-list-server/pull/438)

  > * feat(ci): add container image scanning
  >
  > * chore: fix cli issue
  >
  > * docs: correct release feature set rationale after redis removal
  >
  > * fix: restore trailing newline in .trivyignore.yaml
  >
  > * fix: drop skip_tags from cliff.toml, an empty regex skips every tag
  >
  > * fix(ci): scan every published architecture and trim the scan job summary
  >
  > * chore(ci): install PyYAML from apt instead of an unpinned pip
  >
  > * docs: lead the supply-chain guide with operator steps and cut narrative
  >
  > * refactor(ci): extract image reference verification into a script
  >
  > * fix(ci): build image_ref in a step rather than the job outputs block
  >
  > * fix(ci): drop the duplicated FEATURES build-arg from the docker smoke build

- [31b6177](
https://github.com/adorsys/status-list-server/commit/31b61773da84f00dbf5a9fbb2266b039e614eb62) *(external-secrets)* Implement ClusterSecretStore support and enhance secret management by @Ngha-Boris in [#462](
https://github.com/adorsys/status-list-server/pull/462)

  > * feat(external-secrets): implement ClusterSecretStore support and enhance secret management
  >
  > * feat(watcher): add configuration for credential rotation detection and polling interval
  >
  > * feat: enhance Helm chart with file-based secret mounts and rotation support
  >
  > * fix: update digest and generated timestamp in Chart.lock for opentelemetry-collector
  >
  > * fix: update apiVersion from v1beta1 to v1 in external-secrets and secret-store templates
  >
  > * feat: enhance Helm chart with validation for secret mounts and fileEnv paths
  >
  > * fix: update README and templates for External Secrets Operator compatibility and env validation

- [22f09dd](
https://github.com/adorsys/status-list-server/commit/22f09dda90d442734fd538ac81487a2f6ca8d155) *(helm)* Enable Workload Identity and provider-neutral SecretStore by @Christiantyemele in [#397](
https://github.com/adorsys/status-list-server/pull/397)

  > * feat(helm): enable Workload Identity and provider-neutral SecretStore
  >
  > Make the Helm chart ready for Kubernetes Workload Identity and
  > provider-neutral secret delivery:
  > - Configurable ServiceAccount with role annotations (EKS IRSA / GCP /
  >   Azure WI) and templated pod labels (azure.workload.identity/use)
  > - Static AWS credential-file mount is opt-in
  >   (statuslist.aws.mountCredentials); Workload Identity is the default
  > - Provider-neutral SecretStore (aws | vault | gcp | azure | raw) with
  >   values.schema.json and fail-closed validation
  > - Fallback Kubernetes Secret for clusters without External Secrets
  >   Operator; SecretStore only rendered in ESO mode
  > - Centralized effective app-secret-name and app-region helpers
  > - Opt-in autoscaling/v2 HPA and PodDisruptionBudget; Deployment replicas
  >   omitted when HPA is enabled
  > - CI render/negative/upgrade tests for all identity modes
  >
  > * ci: extract duplicate Helm render step into reusable composite action
  >
  > Consolidate the duplicated 'Render Helm templates' step from the
  > trivy-config and kube-linter jobs in CI.yml into a single composite
  > action (.github/actions/render-helm-templates/action.yml) referenced
  > by both jobs. Reduces CI.yml from 539 to 419 lines.
  >
  > * ci: pin kube-linter binary to v0.8.3 for reproducible lint results
  >
  > * ci: fix kube-linter version pin to use release tag v0.8.3
  >
  > * fix(helm): set unhealthyPodEvictionPolicy to AlwaysAllow in PDB to satisfy kube-linter
  >
  > * fix(helm): tighten scaling validation and secret-name propagation
  >
  > - hpa.yaml: fail when autoscaling.minReplicas > maxReplicas
  > - pdb.yaml: fail unless exactly one of minAvailable / maxUnavailable is set
  > - fallbackSecret: remove independently configurable name; always render
  >   'statuslist-secret' (single supported name referenced by Deployment,
  >   postgres.auth.existingSecret, redis-ha.existingSecret)
  > - render-helm-templates: assert primary workload-identity path (non-default
  >   app SA + IRSA binding; Azure pod label + ESO SA distinct from app KSA),
  >   add negative scaling tests, and assert POSTGRES_PASSWORD secretKeyRef
  >   instead of a loose global grep
  >
  > * fix(helm): fail-closed provider fields and single-secret invariant
  >
  > - secret-store.yaml: reject empty mandatory provider fields (vault server,
  >   gcp projectID, azure tenantId/vaultUrl/identity) at render time
  > - enforce the single-secret invariant in ESO mode: externalSecret.spec.target.name
  >   must equal statuslist-secret (shared by Deployment, PostgreSQL, Redis); the
  >   appSecretName helper now always resolves to statuslist-secret and the ExternalSecret
  >   renders that name, with a schema const reinforcing it
  > - render-helm-templates: use valid positive config for vault/gcp/azure renders, add
  >   negative tests for incomplete provider branches and the ESO one-name invariant
  >
  > * ci: assert Azure WI client-id annotation in render test
  >
  > The Azure direct-workload-identity render now sets
  > serviceAccount.annotations.azure.workload.identity/client-id and asserts it on the
  > rendered ServiceAccount, so the test proves AKS can federate the application pod.
  >
  > * ci: move render-helm-templates action to .github/workflows
  >
  > * fix(helm): address PR #397 review comments
  >
  > - pdb: treat maxUnavailable/minAvailable null as unset but preserve 0
  > - secret-store raw: hold provider body directly under spec.provider
  > - secret-store azure: align with ESO AzureKVProvider CRD (authType enum,
  >   authSecretRef/identityId, drop invalid clientId/auth)
  > - secret fallback: fail closed when postgres-password is empty
  > - render action: assert Azure WI label as string (--set-string), string podLabels
  >   in schema, raw provider shape, prod values render
  > - add values-production.yaml wiring app SA IRSA annotation; use it in deploy.yml
  > - docs: update helm/README.md for azure/raw/prod-WI
  >
  > * ci: fix trivy KSV-0014 ignore for nested postgres chart renders
  >
  > * feat(helm): remove unused ESO fallback Secret mode
  >
  > * Revert "feat(helm): remove unused ESO fallback Secret mode"
  >
  > This reverts commit 6bf4624730e07ca12b612963d36060a0642fe035.
  >
  > * fix(helm): address review feedback (azure serviceAccountRef, fail-closed ESO, assertions)
  >
  > * fix(helm): default secret provisioning to ESO-mounted credentials
  >
  > Flip statuslist.aws.mountCredentials default to true so the application
  > mounts the ESO-provisioned aws-credentials-secret instead of relying on
  > ambient Workload Identity. Workload Identity/IRSA becomes opt-in. Update
  > values-production.yaml to keep the ESO default, set local mode to opt out,
  > reflect the new default in helm/README.md, and adjust the CI render
  > assertions for the production path.
  >
  > * fix(helm): address PR #397 review — secure SA defaults, region gating, azure coverage, chart bump
  >
  > * fix(ci): fix trivy ignore glob path for nested templates
  >
  > * fix(helm): restore Redis HA provisioning and add Redis secret-name CI assertion
  >
  > Per PR #397 review feedback: Redis stays in the chart (do not remove it) and
  > the CI render test now asserts the Redis password secretKeyRef references the
  > single application-secret name so a future refactor cannot silently point Redis
  > at a different secret.
  >
  > - Re-add redis-ha subchart dependency and values block (disabled by default)
  > - Restore REDIS_PASSWORD (secretKeyRef -> statuslist-secret) and credential-free
  >   APP_REDIS__URI env, gated on redis-ha.enabled
  > - Restore redis egress ports in the NetworkPolicy and the redis-cert-sync CronJob
  >   (least-privilege RBAC: read-only on the source wildcard secret, read/write only
  >   on the HAProxy TLS secret)
  > - Add redis-password to the externalSecret data and fallbackSecret stringData
  > - Add Redis password secretKeyRef assertions to render-helm-templates/action.yml
  > - Document Redis HA provisioning in helm/README.md
  > - Regenerate Chart.lock / charts (helm dependency update)
  >
  > * fix(helm): address PR #397 re-review — safe PDB default, opt-in APP_AWS__REGION, SA note, dangling-secretStoreRef test
  >
  > * fix(helm): address PR #397 review — templatize redis-ha cert-sync, validate fallback redis-password
  >
  > - redis-ha-cert-sync: source/target TLS secret names, pem key, and kubectl image
  >   are now driven by redis-ha.tls.secretName / haproxy.tls.secretName /
  >   haproxy.tls.keyName / redis-ha.certSync.image (customizable) instead of
  >   hardcoded literals; jsonpath dot-escape preserved for the pem key.
  > - secret.yaml: fail closed in fallback mode when redis-ha.enabled=true but
  >   redis-password is empty (mirrors the existing postgres-password check).
  > - values.schema.json: correct stale 'raw' description to the actual
  >   direct-body-under-spec.provider contract (no nested 'provider' key).
  >
  > * ci(helm): assert PDB explicit-0 and fallback redis-password fail-closed (PR #397 review)
  >
  > - Render action now asserts minAvailable: 0 and maxUnavailable: 0 render as
  >   integer zero (not treated as unset) in the PDB.
  > - The fallback + redis-ha render must set redis-password; the negative test
  >   asserts an empty redis-password fails at render time.
  >
  > * ci(helm): register dandydeveloper redis-ha repo before helm dependency build
  >
  > The chart depends on redis-ha from https://dandydeveloper.github.io/charts,
  > but the Build Helm dependencies steps only added the open-telemetry repo, so
  > helm dependency build failed and skipped every downstream render/scan step.
  > Add the missing repo add in all four call sites (trivy-config, kube-linter,
  > otel-config-validation in CI.yml, and deploy.yml) to unblock the checks.
  >
  > * fix(helm): harden redis-cert-sync — daily schedule, pinned image digest, emptyDir /tmp (PR #397 review)
  >
  > - Schedule defaults to daily 02:00 UTC (redis-ha.certSync.schedule) instead of
  >   weekly, so the synced HAProxy TLS secret never lags more than ~24h behind a
  >   cert-manager renewal (weekly could leave the old cert for up to 6 days).
  > - redis-ha.certSync.image supports an optional immutable  (renders
  >   repo:tag@sha256:...) and README/values document pinning a patch version.
  > - Mount an explicit emptyDir at /tmp so mktemp -d works with
  >   readOnlyRootFilesystem: true on hardened runtimes (gVisor/Kata/containerd).
  > - Update the template's top-of-file comment to reflect the daily schedule.
  >
  > * fix(helm): networkPolicy opt-in and scoped internal egress (PR #397 review)
  >
  > - Default statuslist.networkPolicy.enabled to false (opt-in) with a loud WARNING:
  >   an empty ingress renders a port-only rule with no from, equivalent to no ingress
  >   restriction. README/values document restricting ingress to the ingress controller.
  > - Scope internal egress to target pods instead of any pod in the cluster:
  >   PostgreSQL (app.kubernetes.io/name: postgres), Redis (app: redis-ha, when enabled),
  >   and OTel (app.kubernetes.io/name: opentelemetry-collector) each get a to: podSelector.
  >   Extra destinations can be appended via statuslist.networkPolicy.egressInternal.
  > - Render action now asserts the default emits no NetworkPolicy and that enabled + redis-ha
  >   scopes PostgreSQL egress to its pods.
  >
  > * ci(helm): fix flaky render checks from grep -q SIGPIPE under pipefail
  >
  > grep -q closes the pipe as soon as it matches, so helm template writing the
  > rest of the manifests receives SIGPIPE (141); with set -o pipefail the
  > pipeline returns non-zero and inverts the 'if !' guards into false failures
  > that are timing-dependent (reproduced in CI, not locally). Drop -q and read
  > the full stream via grep ... >/dev/null.
  >
  > * fix(helm): remove redis-ha from chart to match #404 redis removal (PR #397 review)
  >
  > * fix(helm): provision aws-credentials-secret via ExternalSecret to complete mounted-creds path (PR #397 review)

- [a2ba6df](
https://github.com/adorsys/status-list-server/commit/a2ba6dfd3554defe31088b81e22c291e304cf6f4) *(observability)* Define SL dashboards and alerts for production by @ndefokou in [#445](
https://github.com/adorsys/status-list-server/pull/445)

  > * feat: defining sl dashboards and alert for production observability
  >
  > * feat: defining sl dashboards and alert for production observability
  >
  > * feat: defining sl dashboards and alert for production observability
  >
  > * feat: defining sl dashboards and alert for production observability
  >
  > * feat: defining sl dashboards and alert for production observability
  >
  > * feat: defining sl dashboards and alert for production observability
  >
  > * feat: defining sl dashboards and alert for production observability
  >
  > * feat: defining sl dashboards and alert for production observability
  >
  > * fix: promethus observability
  >
  > * fix(pipeline): formatting
  >
  > * chore: refactor Redis and database configuration to enhance security by using split credentials
  >
  > * chore: refactor Redis and database configuration to enhance security by using split credentials
  >
  > * chore: update deployment template to use dynamic database port and enhance Redis error handling
  >
  > * refactor: enhance database configuration handling and reject assembled URLs
  >
  > * refactor: update database configuration to use split fields and require database port
  >
  > * refactor: update Helm templates to use APP_DATABASE_PORT environment variable
  >
  > * refactor: update database configuration to enforce split fields and validate query parameters
  >
  > * refactor: enhance database configuration handling for IPv6 and validate APP_DATABASE_PORT
  >
  > * refactor: standardize database port configuration and validation across Helm templates
  >
  > * refactor: enhance security context for test Pod and add temporary volume
  >
  > * refactor: update test to verify default database port usage in Helm chart
  >
  > * refactor: update database port helper to require APP_DATABASE__PORT and clean up tests for Redis credentials
  >
  > * refactor: update database port helper to require APP_DATABASE__PORT and clean up tests for Redis credentials
  >
  > * refactor: update commitlint configuration to allow longer headers and disable body line length check
  >
  > * docs: clarify external database configuration in README
  >
  > * fix(pipeline): fix formatting
  >
  > * fix(pipeline): fix formatting
  >
  > * fix(pipeline): fix formatting
  >
  > * refactor: remove webhook alert notifications from observability branch
  >
  > Move the Alertmanager webhook/Discord notification implementation to the
  > 446-add-webhook-based-alert-notifications branch. The observability branch now
  > keeps only the SLO dashboards and Prometheus alert rules.
  >
  > * fix(observability): align alert table column pipes in LIVE_TESTING.md
  >
  > * feat(observability): add error-budget alert, 30d SLO rules, and review hardening
  >
  > Address review comments:
  > - Add ErrorBudgetCritical page alert on 30d budget < 10% + runbook
  > - Add 30d recording rules for token-gen and cert-renewal failure rates
  > - Add current-value description to CacheHitRatioLow
  > - Require GRAFANA_ADMIN_PASSWORD (remove insecure admin default)
  > - Add CI dashboard-drift check and compose-config placeholder
  > - Document datasource UID and hardcoded-threshold consistency
  > - Add no-data / 30d edge-case rule tests
  >
  > * fix(observability): address review comments for cache test and live testing docs
  >
  > * fix(observability): address production-readiness and operator review comments
  >
  > - enable server metrics by default in values.yaml and values-production.yaml
  > - add ServiceMonitor and PrometheusRule templates for kube-prometheus-stack
  > - document production OpenTelemetry exporter configuration examples
  > - add production Prometheus config (prometheus.production.yml) with 15s scrape interval
  > - enforce 31-day TSDB retention in docker-compose.yml
  > - set disableDeletion: true in Grafana dashboards provisioning config
  > - create Alertmanager example configuration with severity routing
  > - centralize SLO thresholds in thresholds.json with CI drift linter
  > - use absolute GitHub URLs for runbook_url in alerting rules
  >
  > * fix(helm): escape prometheusrule value variable and fix values formatting
  >
  > * feat(observability): address code review feedback on SLO rules and Helm templates
  >
  > - Add 30d error budget alerting and recording rule for token generation
  > - Add 30d cert renewal budget exhaustion critical alert
  > - Fix window documentation in SLO README and add Quarterly SLO Review Process section
  > - Make Grafana dashboard UID configurable via process.env.GRAFANA_DASHBOARD_UID
  > - Move Helm PrometheusRule thresholds to configurable values.yaml slo section
  > - Add SLI-based routing example to Alertmanager configuration
  >
  > * fix(helm): remove redundant blank line in values.yaml
  >
  > * fix(observability): address follow-up PR review feedback
  >
  > - Revert hardcoded postgres host/port in init container wait command back
  >   to Helm templating ({{ .Release.Name }}-postgres.{{ .Release.Namespace }}
  >   and {{ include "status-list-server-chart.dbPort" . }}) in values.yaml
  >   and values-local.yaml
  > - Add missing 7d recording rules: sli:cache_hit_ratio:7d and
  >   sli:cert_renewal_failure_rate:7d in recording.rules.yml and
  >   prometheusrule.yaml to match documentation
  > - Add promtool test cases for new 7d recording rules in recording.test.yml
  > - Update lint-thresholds.mjs to dynamically verify HTTP and token-gen error
  >   budget denominators match thresholds.json (previously only checked /0.005)
  > - Add Token-gen error budget (30d) stat panel for sli:token_gen_error_budget:30d
  >   to the Grafana dashboard generator and regenerate status-list-slo.json
  >
  > * fix(helm): use mulf and fix alertmanager formatting
  >
  > - Replace Sprig mul with mulf + printf "%.3f" on all four burn-rate
  >   alert exprs (ErrorRateFastBurn, ErrorRateSlowBurn, TokenGenerationFastBurn,
  >   TokenGenerationSlowBurn) in prometheusrule.yaml. Sprig mul performs integer
  >   arithmetic: int(0.005) * int(14.4) = 0, causing all four alerts to render
  >   as '>= 0' and fire permanently on any traffic
  > - Remove duplicate blank line in alertmanager.example.yml to fix the
  >   yamlfmt CI lint check
  >
  > * chore(ci): exclude helm values files from yamlfmt
  >
  > values.yaml and values-local.yaml contain Helm template syntax ({{ }})
  > inside YAML block scalars (initContainers wait command). yamlfmt cannot
  > parse these correctly and reports spurious formatting differences.
  > Extend the exclude list to match the existing helm/chart/templates/ rule.
  >
  > * chore(ci): apply yamlfmt formatting to alertmanager.example.yml
  >
  > Collapse >- block scalar in slack_configs.text to a single line as
  > required by yamlfmt. Fixes the yamlfmt --lint CI check.
  >
  > * fix(observability): address operator review on SLIs, alerts, dashboards, and panic metrics
  >
  > - dashboards: fix colour-inversion so higher-is-better metrics (cache hit
  >   ratio, error-budget stats) render green when healthy instead of permanently
  >   red; regenerate status-list-slo.json
  > - alertmanager.example.yml: remove undefined receivers, fix invalid
  >   placeholder URL so the config loads, and route severity=page to PagerDuty
  >   with precedence
  > - alerting: add service=status-list-server label to every alert so Alertmanager
  >   can group/route on identity
  > - cert alerts: CertRenewalFailures now evaluates a 7d window (5m rate vs a
  >   discrete daily renewal loop could never fire with for:15m); the 30d critical
  >   page now requires >=50% failures so a single transient failure warns instead
  >   of paging; align helm PrometheusRule copy and update runbook/tests
  > - startup: layer track_http_metrics outside CatchPanicLayer so panic-induced
  >   500s are recorded as 5xx; add regression test proving the ordering matters
  >
  > * fix(observability): realign SLI table to satisfy markdownlint MD060
  >
  > The cert-renewal row edited in the SLO review fix made the last column wider
  > than the aligned column width, failing markdownlint MD060/table-column-style.
  > Realign every row of the per-SLI table to consistent column widths.
  >
  > * fix(observability): add watchdog/absent alerts, validate Helm rule, and fix metrics test lock
  >
  > Address review feedback on the SLO ruleset:
  >
  > - Drop dead :route/:operation recording rules that no panel or alert consumes;
  >   this also removes the direct source of the Helm/standalone divergence.
  > - Add an always-firing Watchdog and a StatusListMetricsAbsent absent() target-down
  >   guard so a scrape loss or deleted deployment pages instead of failing silent.
  >   Mirror both in the Helm PrometheusRule and update the promtool alerting tests.
  > - Hoist the hardcoded budget-critical gates into slo.errorBudgetCriticalThreshold
  >   and slo.certRenewalErrorBudgetCriticalThreshold in the Helm chart.
  > - Validate the rendered Helm PrometheusRule in CI (helm template + promtool check
  >   rules) instead of only the raw observability YAML.
  > - Extend lint-thresholds.mjs to assert helm/chart/values.yaml slo.* matches
  >   thresholds.json, and add the budget-critical gates to thresholds.json.
  > - Document the non-stock pagerduty.default.instances template in the Alertmanager
  >   example so operators know it must be defined or inlined.
  > - Hold METRICS_TEST_LOCK across the router awaits in the two metrics middleware
  >   tests (drop(_metrics_guard) before the assertions caused a deterministic
  >   parallel-test race on the 5xx counter).
  >
  > Verified:cargo test --lib (156 passed), clippy --all-targets -D warnings,
  > promtool check/test rules for standalone and rendered rules, lint-thresholds.mjs,
  > yamlfmt.
  >
  > * fix(ci): build helm deps for rendered PrometheusRule check and appease typos
  >
  > - Run `helm dependency build helm/chart` before rendering in the
  >   prometheus-rules-validation job: the postgres/opentelemetry-collector
  >   subchart tarballs are gitignored, so a plain `helm template` failed with
  >   "You may need to run 'helm dependency build'".
  > - Reword the StatusListMetricsAbsent comment to avoid the `mis` token that
  >   the typos lint flagged.
  >
  > * fix(observability): preserve namespace identity across SLI series and alerts
  >
  > The sli:* recording rules aggregated with sum(...) by (le) / plain sum(...),
  > which dropped the namespace/job labels a ServiceMonitor injects, and the
  > alerts carried only a static service label. Under a shared/aggregated
  > Prometheus scraping this app from more than one namespace, the series collide
  > and alerts cannot identify which deployment is burning.
  >
  > - Recording rules now group by namespace (histograms by (namespace, le),
  >   ratios by sum by (namespace)), keeping per-deployment identity; the budget
  >   gauges inherit it from sli:error_rate:30d / sli:token_gen_failure_rate:30d.
  > - Helm PrometheusRule mirrors the same grouping and stamps
  >   namespace: <release namespace> on every alert, including Watchdog and
  >   StatusListMetricsAbsent.
  > - promtool alerting tests carry a namespace label on inputs and assert it in
  >   expected labels so namespace propagation is regression-guarded.
  >
  > * fix(observability): correct burn-rate model, make cert alerts fire, and unit-test deployed rules
  >
  > Address review on PR #445: the multi-window multi-burn-rate alerts were
  > misimplemented (fast-burn pages waited on the slow 6h trailing average, so they
  > fired hours late and after their own warns), the certificate alerts could not
  > fire (rate() over a fixed window is 0/0=NaN between sparse renewals), the
  > deployed PrometheusRule copy was never behaviorally tested, and the Watchdog
  > fell through to the default Slack receiver.
  >
  > - Alerting: fast-burn page now pairs the 1h window with a 5m confirmation at
  >   14.4x; slow-burn warn pairs the 6h window with a 30m confirmation at 6x
  >   (short window = 1/12 of long, per Google SRE), for error, token-gen, request
  >   latency and DB latency, so pages fire promptly and before warns.
  > - Recording: add the :30m short-confirmation windows (error_rate, token_gen,
  >   request_latency:p95, db_query_latency:p95).
  > - Cert: replace the NaN-prone failure-rate ratio alerts with expiry-driven
  >   alerts on the continuous cert_time_to_expiry_seconds gauge (warn <=14d, page
  >   <=7d), which fire deterministically when renewal stops keeping the cert fresh.
  > - Deployed copy: CI now renders the Helm PrometheusRule, asserts it matches the
  >   tested standalone rule names (drift guard), and runs the full promtool
  >   'test rules' alerting suite against it so the deployed rules are unit-tested.
  > - Alertmanager: route severity=none (Watchdog) to a dead-man's-switch and make
  >   the default receiver a no-op so the always-firing Watchdog no longer spams
  >   Slack; switch to matchers syntax.
  > - Sync slo/README, thresholds.json, lint-thresholds.mjs, and cert/latency
  >   runbooks; update recording/alerting test suites (new windows + cert
  >   boundary/positive cases). Dashboard JSON regenerated with no drift.
  >
  > * fix: fix burn-rate and certificate alerting
  >
  > ---------

- [b1c5768](
https://github.com/adorsys/status-list-server/commit/b1c57686127b70f0509f518e4f9f840914edaf52) *(uncategorized)* Update Helm chart for provider-neutral deployment and enhance configuration options by @Ngha-Boris in [#473](
https://github.com/adorsys/status-list-server/pull/473)

  > * feat: update Helm chart for provider-neutral deployment and enhance configuration options
  >
  > * feat: enhance Helm template rendering for provider-neutral secret management
  >
  > * fix: update image tag references to ensure provider-neutral deployment
  >
  > * fix: update global domain handling to support null values in schema
  >
  > * feat: refactor Helm chart for provider-neutral deployment and enhance fallback secret management
  >
  > * test: simplify assertion for database URL in default config
  >
  > * feat: enhance Helm chart for provider-neutral deployment and external secrets management
  >
  > * feat: update Helm chart for provider-neutral image variant handling and improve deployment configurations
  >
  > * feat: enhance Helm chart for provider-neutral deployment with local signing material and TLS support

- [6240800](
https://github.com/adorsys/status-list-server/commit/6240800dd94f8424806cc52da39ba1ec23df9bd2) *(uncategorized)* Ci scheduled re scan by @martcpp in [#470](
https://github.com/adorsys/status-list-server/pull/470)

  > * refactor(ci): extract manifest resolution, report derivation and gate self-test into shared scripts
  >
  > * feat(scripts): surface trivyignore exceptions approaching expiry before they lapse
  >
  > * feat(ci): add scheduled re-scan of released images with SARIF and issue tracking
  >
  > * docs(supply-chain): restore the post-merge advisory claim and document the nightly re-scan
  >
  > * fix(ci): stop the scheduled re-scan reading absent coverage as a clean run
  >
  > * feat(scripts): assert the image variant lists agree across deploy and the re-scan
  >
  > * fix(ci): fail the deploy when IMAGE_VARIANT is invisible to the scheduled re-scan
  >
  > * fix(ci): correct the nightly's expiry notice and scope its red to production
  >
  > * docs(supply-chain): document the tiered verdict, expiry notice and variant parity
  >
  > * fix(scripts): reject a malformed arch manifest digest before it reaches GITHUB_ENV
  >
  > * feat(scripts): constrain ignore-file ids to the character set their consumers assume
  >
  > * refactor(ci): keep the nightly's severity floor and summary schema in one place
  >
  > * docs(supply-chain): correct the aggregation gating claim and the SARIF derivation
  >
  > ---------

- [8b92259](
https://github.com/adorsys/status-list-server/commit/8b922592a54735e1ed54755166c7570eeafb93dd) *(uncategorized)* Add support for reloading database credentials from a password file by @Ngha-Boris in [#465](
https://github.com/adorsys/status-list-server/pull/465)

  > * feat: add support for reloading database credentials from a password file
  >
  > * refactor: replace SeaOrmStore::new with SeaOrmStore::from_handle for better clarity
  >
  > * feat: update dependencies and add new exemptions for improved compatibility
  >
  > * feat(secrets): enhance database password management with file-based credentials and update Helm chart configuration
  >
  > * fix(dependencies): update arc-swap to version 1.9
  >
  > * feat(watcher): prevent duplication of watcher poll interval in rendered Helm chart
  >
  > * fix(tests): correct database connection string by removing unnecessary encoding
  >
  > * feat(cert-manager): refactor certificate provider interface to use SigningMaterial struct
  >
  > * fix(tests): add ConnectionTrait import for PostgreSQL password file rotation test

- [718b2ec](
https://github.com/adorsys/status-list-server/commit/718b2ec1bfec9317d0899a885efd593c85de51ea) *(uncategorized)* Add multi-variant support for Docker images in CI and deploy workflows by @Ngha-Boris in [#460](
https://github.com/adorsys/status-list-server/pull/460)

  > * feat: add multi-variant support for Docker images in CI and deploy workflows
  >
  > * docs: update deployment runbook to clarify multi-arch image variant details
  >
  > * docs: update deployment runbook to format multi-arch image variant details consistently
  >
  > * docs: update deployment runbook to improve clarity and formatting of multi-arch image variant details
  >
  > * docs: update deployment runbook to clarify image tag application for multi-arch variants
  >
  > * docs: update deployment runbook to improve formatting of multi-arch image variant details
  >
  > * docs: remove cargo build variants and update docker build steps for clarity
  >
  > * docs: remove unnecessary blank line before domain layer purity verification step
  >
  > * docs: update variant matrix in deploy workflow to include GCP, Azure, and Vault support
  >
  > * refactor: simplify job names in deploy workflow by removing variant suffix
  >
  > * refactor: remove variant suffix from promote-tags job name in deploy workflow
  >
  > * refactor: update deployment runbook to clarify variant selection process
  >
  > * refactor: update deployment workflow to use IMAGE_VARIANT and improve rollback handling
  >
  > * docs: clarify IMAGE_VARIANT note in deployment runbook
  >
  > * refactor: enhance deployment workflows with multi-variant support and improve documentation
  >
  > * docs: update deployment runbook to improve clarity on variant selection and infrastructure requirements
  >
  > * fix: add permissions for cargo-build job in CI workflow
  >
  > ---------

- [ff4b071](
https://github.com/adorsys/status-list-server/commit/ff4b071be8f0d8a4c5828099351aa0d9f04268fc) *(uncategorized)* Add Helm template check with local values and update values-local.yaml by @Ngha-Boris in [#447](
https://github.com/adorsys/status-list-server/pull/447)

  > * feat: add Helm template check with local values and update values-local.yaml
  >
  > * fix: update busybox image version in values-local.yaml and add permissions to helm-template-local job
  >
  > * feat(ci): enhance Helm template validation for local values and verify environment settings
  >
  > * fix(ci): improve APP_ENV verification in Helm template check for local values

- [7a36909](
https://github.com/adorsys/status-list-server/commit/7a369091e3e967cd109bf2aeea7d456bd2944cd4) *(uncategorized)* Add vault kubernetes authentication by @Hermann-Core in [#408](
https://github.com/adorsys/status-list-server/pull/408)

  > * feat(vault): add Kubernetes authentication method support
  >
  > * docs: add Kubernetes auth support
  >
  > * fix(vault): add method label to renewal metric
  >
  > * fix(setup): validate role_id for Vault AppRole auth method
  >
  > * docs(vault): restore cache TTL in config table and document manual dev server testing

### Bug Fixes

- [74e6b86](
https://github.com/adorsys/status-list-server/commit/74e6b86ccc26daf1cb7ea48d839b99b97f774433) *(cert)* Streamline static cert provider, mutual exclusion with acme, and rename cloud features by @Hermann-Core in [#472](
https://github.com/adorsys/status-list-server/pull/472)

  > * fix(cert): fix filesystem certificate and key provider and support mixed sources
  >
  > * fix(setup): avoid unused assignment warning for db_arc
  >
  > * refactor(cert): simplify static cert store configuration and mutual exclusion with acme
  >
  > * feat(cloud): rename cloud provider features to aws, gcp, azure with transitive acme
  >
  > * chore(deploy): align ci matrix, helm, docker, and docs with renamed cloud features
  >
  > * docs: normalize markdown formatting in docs and README
  >
  > * chore: reformat code and simplify cfg conditions
  >
  > * docs: correct feature flag names and clean up backend documentation

- [5af701a](
https://github.com/adorsys/status-list-server/commit/5af701a3bbc53bed5d6769ae75c7e9f8aac33f62) *(deploy)* Remove --create-namespace from helm deploy step by @Christiantyemele in [#444](
https://github.com/adorsys/status-list-server/pull/444)

  > * fix(deploy): remove --create-namespace from helm deploy step
  >
  > * fix(deploy): replace deprecated --atomic with --rollback-on-failure
  >
  > * fix(deploy): pin Helm 4 in setup step to use --rollback-on-failure

- [b7cca4b](
https://github.com/adorsys/status-list-server/commit/b7cca4b8ba335973b0d1cd7eb72a9dd4496d1c6c) *(uncategorized)* Unset CARGO_BUILD_TARGET when installing cargo tools in Dockerfile by @Hermann-Core in [#490](
https://github.com/adorsys/status-list-server/pull/490)

### Refactor

- [68e4e96](
https://github.com/adorsys/status-list-server/commit/68e4e9641c94786a382d4c06f88614763e7d7398) *(uncategorized)* Remove redis and all its references by @Blindspot22 in [#404](
https://github.com/adorsys/status-list-server/pull/404)

  > * refactor: remove redis application code
  >
  > * chore: regenerate cargo lock without redis
  >
  > * refactor: remove redis docker config
  >
  > * refactor: remove redis helm chart
  >
  > * docs: remove redis documentation references
  >
  > * ci: remove redis from ci config
  >
  > * ci: fix helm chart lock
  >
  > * style: fix markdown lint blank lines
  >
  > * ci: add docker build smoke job and fix features
  >
  > * refactor: remove dead AWS S3 path
  >
  > * chore: drop aws s3 config and vet exemptions
  >
  > * docs: add redis helm cleanup runbook
  >
  > * chore: remove dangling-service exclusion
  >
  > * chore: format cargo-vet imports lock
  >
  > * docs: fix markdown fence blank lines
  >
  > * chore: fix vet and machete
  >
  > * docs: fix runbook typo and prune vet exemptions
  >
  > ---------

### Documentation

- [a3d0772](
https://github.com/adorsys/status-list-server/commit/a3d077275e29d10a08384be44409a33910e87708) *(uncategorized)* Add operator deployment and operations guide by @Christiantyemele in [#467](
https://github.com/adorsys/status-list-server/pull/467)

  > * docs: generalize deployment runbook and document ESO vs Workload Identity risk trade-offs
  >
  > * docs: restore deployment-runbook reference in operator guide and fix related links
  >
  > * docs(helm): rewrite deployment guide for clarity and cover workload identity
  >
  > * docs: remove out-of-scope architecture documents and revert README change
  >
  > * docs: restore operator troubleshooting reference and link it from the helm guide
  >
  > * docs(helm): link External Secrets Operator in prerequisites
  >
  > * docs: adopt generalized deployment runbook from PR 463
  >
  > * docs(helm): update deployment guide per review feedback

### Performance

- [f69c1d9](
https://github.com/adorsys/status-list-server/commit/f69c1d96d4fca4bef4818f2825d2002cea7e58e3) *(deploy)* Optimize multi-variant caching, digest resolution, and rollout verification by @Hermann-Core in [#475](
https://github.com/adorsys/status-list-server/pull/475)

  > * feat(deploy): optimize multi-variant caching, digest resolution, and rollout verification
  >
  > * docs(deploy): document fail-closed release transaction and cache scoping
  >
  > * fix(deploy): eliminate TOCTOU by reading scanned digest from run artifact and validating promoted tag
  >
  > * docs(deploy): clarify release atomicity and warn against environment-scoped IMAGE_VARIANT
  >
  > * fix(deploy): restore promoted multi-arch index digest resolution in deploy job
  >
  > * docs(deploy): document BuildKit cache isolation and update supply chain guide for variants

### Miscellaneous Tasks

- [b0843f1](
https://github.com/adorsys/status-list-server/commit/b0843f12ed2387f81da677762986b4e197b4e0a2) *(uncategorized)* Sync develop into main by @Hermann-Core in [#491](
https://github.com/adorsys/status-list-server/pull/491)

- [efd4bbb](
https://github.com/adorsys/status-list-server/commit/efd4bbb97b6b53d54e429bb00fadca488e8acbf3) *(uncategorized)* Refactor Redis and database configuration to enhance security by using split credentials by @Ngha-Boris in [#440](
https://github.com/adorsys/status-list-server/pull/440)

  > * chore: refactor Redis and database configuration to enhance security by using split credentials
  >
  > * chore: update deployment template to use dynamic database port and enhance Redis error handling
  >
  > * refactor: enhance database configuration handling and reject assembled URLs
  >
  > * refactor: update database configuration to use split fields and require database port
  >
  > * refactor: update Helm templates to use APP_DATABASE_PORT environment variable
  >
  > * refactor: update database configuration to enforce split fields and validate query parameters
  >
  > * refactor: enhance database configuration handling for IPv6 and validate APP_DATABASE_PORT
  >
  > * refactor: standardize database port configuration and validation across Helm templates
  >
  > * refactor: enhance security context for test Pod and add temporary volume
  >
  > * refactor: update test to verify default database port usage in Helm chart
  >
  > * refactor: update database port helper to require APP_DATABASE__PORT and clean up tests for Redis credentials
  >
  > * refactor: update database port helper to require APP_DATABASE__PORT and clean up tests for Redis credentials
  >
  > * refactor: update commitlint configuration to allow longer headers and disable body line length check
  >
  > * docs: clarify external database configuration in README

- [592660f](
https://github.com/adorsys/status-list-server/commit/592660ff6064b1d6315b9a10e51defdb282c7527) *(uncategorized)* Stage by @martcpp in [#437](
https://github.com/adorsys/status-list-server/pull/437)

  > * chore: initialize project baseline for release automation
  >
  > * chore: create release v1.0.0
  >
  > * feat: fix the valute issue
  >
  > ---------

- [55834e6](
https://github.com/adorsys/status-list-server/commit/55834e6151ef0e894004924ab96b99a871bdb579) *(uncategorized)* Sync main to develop by @martcpp in [#435](
https://github.com/adorsys/status-list-server/pull/435)

  > * chore: initialize project baseline for release automation
  >
  > * chore: create release v1.0.0
  >
  > ---------

### Continuous Integration

- [06b39ef](
https://github.com/adorsys/status-list-server/commit/06b39ef3108d7111f253fc818fa3407d5f6bdd52) *(uncategorized)* Make the zizmor gate fail closed and gate merges on a single required check by @martcpp in [#452](
https://github.com/adorsys/status-list-server/pull/452)

  > * ci: harden workflow permissions and make the zizmor gate fail closed
  >
  > * ci: pin the zizmor version, self-test the gate, and restrict dependabot auto-merge
  >
  > * docs(ci): cut workflow comments to the reason, two lines at most
  >
  > * docs(ci): trim remaining workflow comments to the reason only
  >
  > * ci: test the gate through the action, drop the actor guard and the PR approval
  >
  > * ci: assert the self-test names its finding and close two silent-skip paths
  >
  > * ci: warn instead of failing when auto-merge is disabled repository-wide
  >
  > * ci: gate helm-template-local behind ci-success
  >
  > * ci: address review on zizmor self-test, ci-success skips, and auto-merge detection
  >
  > * ci: gate prometheus-rules-validation behind ci-success
  >
  > * ci: fix zizmor findings from the multi-variant merge (artipacked, stale pin comments)
  >
  > * docs(ci): explain why artifact upload needs no actions scope
  >
  > * docs(ci): drop the artifact permissions note from build-and-push

**Full Changelog**: https://github.com/adorsys/status-list-server/compare/v1.1.0...v1.2.0



## [1.1.0] - 2026-09-04

### Features

- *(ci)* Add container image scanning by @martcpp

- *(external-secrets)* Implement ClusterSecretStore support and enhance secret management by @Ngha-Boris

- *(helm)* Enable Workload Identity and provider-neutral SecretStore by @Christiantyemele

- *(observability)* Define SL dashboards and alerts for production by @ndefokou

- *(feat)* Update Helm chart for provider-neutral deployment and enhance configuration options by @Ngha-Boris

- *(ci)* Ci scheduled re scan by @martcpp

- *(feat)* Add support for reloading database credentials from a password file by @Ngha-Boris

- *(feat)* Add multi-variant support for Docker images in CI and deploy workflows by @Ngha-Boris

- *(ci)* Add Helm template check with local values and update values-local.yaml by @Ngha-Boris

- *(vault)* Add vault kubernetes authentication by @Hermann-Core

### Bug Fixes

- *(cert)* Streamline static cert provider, mutual exclusion with acme, and rename cloud features by @Hermann-Core

- *(deploy)* Remove --create-namespace from helm deploy step by @Christiantyemele

### Refactor

- *(refactor)* Remove redis and all its references by @Blindspot22

### Documentation

- *(docs)* Add operator deployment and operations guide by @Christiantyemele

### Performance

- *(deploy)* Optimize multi-variant caching, digest resolution, and rollout verification by @Hermann-Core

### Miscellaneous Tasks

- *(uncategorized)* Refactor Redis and database configuration to enhance security by using split credentials by @Ngha-Boris

### Continuous Integration

- *(ci)* Make the zizmor gate fail closed and gate merges on a single required check by @martcpp


## [1.0.0] - 2026-08-20

### Miscellaneous Tasks

- [f4ea335](https://github.com/adorsys/status-list-server/commit/f4ea335c21bc5b85aa9f39b2cc4ebc74c096471b) *(uncategorized)* Initialize project baseline for release automation by @Hermann-Core

