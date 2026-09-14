# Changelog

All notable changes to this project will be documented in this file.
<!-- markdownlint-disable line-length no-bare-urls ul-style emphasis-style -->

## [1.2.0] - 2026-09-14

### Features

- [299dab7](
https://github.com/adorsys/status-list-server/commit/299dab7b7bbdb601cbdb7ccb46e73fb43496ece8) *(auth)* Enhance JWT management claims validation and configuration by @Ngha-Boris in [#513](
https://github.com/adorsys/status-list-server/pull/513)

  > * feat(auth): enhance JWT management claims validation and configuration
  >
  > * feat(auth): enhance management JWT claims validation and configuration
  >
  > * docs: remove outdated validation and security sections from README
  >
  > * docs: remove redundant example commands from README
  >
  > * docs: add example for building with PostgreSQL support and filesystem key loading

- [c8d1f46](
https://github.com/adorsys/status-list-server/commit/c8d1f4660a1deecb0918cecf2bca1f2d7409d20c) *(auth)* Introduce AuthenticatedIssuer struct for better issuer management by @Ngha-Boris in [#510](
https://github.com/adorsys/status-list-server/pull/510)

  > * feat(auth): introduce AuthenticatedIssuer struct for better issuer management
  >
  > * refactor(auth): streamline AuthenticatedIssuer usage and improve request handling

- [1a10920](
https://github.com/adorsys/status-list-server/commit/1a1092056cc5cfc6db0e9f4212a4570a4981b08f) *(uncategorized)* Refresh readme to match current implementation and configuration by @Blindspot22 in [#448](
https://github.com/adorsys/status-list-server/pull/448)

  > * docs: fix architecture link
  >
  > * docs: update documentation index
  >
  > * docs: remove stale redis references
  >
  > * docs: add pebble dns provider
  >
  > * docs: add rate limit limits
  >
  > * docs: add nextest prerequisite note
  >
  > * docs: update README.md
  >
  > * docs: overhaul README to highlight features and simplify overview
  >
  > * fix(env): increase status cache max capacity to 1000

- [3d9354d](
https://github.com/adorsys/status-list-server/commit/3d9354d6f3c3611debd67bd2b1b2dc4ad829997a) *(uncategorized)* Add support for GKE and AKS Workload Identity in DNS provider configuration by @Ngha-Boris in [#471](
https://github.com/adorsys/status-list-server/pull/471)

  > * feat: add support for GKE and AKS Workload Identity in DNS provider configuration
  >
  > * fix: streamline ClientSecretCredential initialization in DefaultAzureCredential
  >
  > * refactor: azure and gcp dns providers to use defaultazurecredential and application default credential
  >
  > * refactor: simplify project_id assignment and update token module condition
  >
  > * refactor: streamline acme dependencies and clean up test configurations in GoogleCloudDnsProvider
  >
  > * refactor: remove test-specific from_token_provider implementation in AzureDnsProvider

- [2e6ba0a](
https://github.com/adorsys/status-list-server/commit/2e6ba0ad259dff8f1a726081f0c150bb0ad3ad5b) *(uncategorized)* Add webhook based alert notifications for observability alerts by @ndefokou in [#451](
https://github.com/adorsys/status-list-server/pull/451)

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
  > * feat(observability): wire alertmanager webhook notifications for all platforms
  >
  > Forward observability alerts to external notification systems through
  > Alertmanager webhooks . Prometheus now sends fired/resolved
  > alerts to Alertmanager, which renders a native receiver config from env-only
  > credentials so no webhook URL is committed.
  >
  > - Add Alertmanager service to docker-compose and alerting.alertmanagers to
  >   dev + production Prometheus configs
  > - Fix Teams/Mattermost receivers to use generic webhook_configs (no native
  >   receiver exists in the pinned alertmanager image); validate discord,
  >   slack, email, teams, mattermost, webhook all generate amtool-valid configs
  > - Add webhook delivery test (firing + resolved) against a mock endpoint and
  >   wire it into CI
  > - Document webhook/Discord setup in observability/runbooks/webhook-notifications.md
  >   and update .env.template with required vars prior to docker compose up
  >
  > * style(observability): fix yamlfmt and markdownlint warnings
  >
  > - yamlfmt: dedent commented-out alternative receivers in alertmanager.example.yml
  > - markdownlint (runbook): add code-fence language, wrap bare URLs, align tables
  > - markdownlint (README): remove multiple consecutive blank lines
  >
  > * fix: adding webhook based alert notification for observability
  >
  > * docs(helm): fix markdownlint issues in README
  >
  > * fix(observability): address code review feedback for webhook alert notifications
  >
  > - Harden config generator by validating required ALERTMANAGER_SMTP_FROM for email platform
  > - Add explicit dmsEnabled flag to Helm values, schema, and AlertmanagerConfig template
  > - Add dashboard_url annotation pointing to SLO Grafana dashboard in alerting rules and tests
  > - Document JSON alert payload schema and retry/failure behavior in runbooks and README
  > - Add portability notes and SMTP_FROM test variable to alertmanager test script
  >
  > * docs(observability): fix markdownlint formatting errors in webhook runbook
  >
  > - Align table column pipes and headers for MD060 compliance
  > - Add blank line before fenced code block in list item for MD031 compliance
  > - Remove consecutive trailing blank lines for MD012 compliance
  >
  > * fix(observability): resolve alerting feedback on Slack, SMTP, dashboard URLs, and CI tests
  >
  > - Parametrize Slack channels and Grafana dashboard URLs in Alertmanager & Helm templates
  > - Enforce host:port format and required sender validation for email platform
  > - Fix process lifecycle management in integration test harness
  > - Add fail-closed Helm template validation for alerting configurations in CI
  > - Update documentation and comments to reflect enduring invariants
  >
  > * fix(docs): align table columns in helm/README.md to satisfy MD060
  >
  > * docs(helm): fix ordered list item prefix in helm README
  >
  > * fix(alerting): address webhook notification review comments
  >
  > - bump AlertmanagerConfig API to v1beta1 (v1alpha1 is deprecated)
  > - add service label to route groupBy so alerts from different services
  >   are not merged under the same alert name
  > - expose configurable webhook timeout (alerting.webhookTimeout) for
  >   webhook/teams/mattermost and dead-man's-switch receivers
  > - expose retry backoff via alerting.retry (minBackoff/maxBackoff/maxRetries)
  > - add SMTP tlsConfig passthrough for the email receiver
  > - document Teams generic-JSON rendering limitation and secret rotation
  > - document Linux-only --network host requirement of the observability test
  > - document existingSecret and dead-man's-switch key validation requirements
  >
  > * fix(markdown): resolve MD012 multiple-blank-line lint errors
  >
  > * fix(alerting): align AlertmanagerConfig with Prometheus Operator CRD schema
  >
  > Rework the chart's AlertmanagerConfig to use fields valid against the
  > monitoring.coreos.com/v1beta1 CRD, which previously produced manifests the
  > Kubernetes API server would reject on apply:
  >
  > - webhook receivers: use urlSecret (direct name/key) instead of url.secretKeyRef
  > - discord/slack: use apiURL with direct name/key (drop secretKeyRef wrapper)
  > - email: render to/smarthost/from as plain string values; optional SMTP AUTH
  >   password via authPassword from the smtp-password secret key
  > - remove invalid httpConfig minBackoff/maxBackoff/maxRetries and the
  >   alerting.retry values (not part of the CRD or Alertmanager receivers)
  >
  > Other consistency fixes:
  > - add dashboardUrl/slack/webhookTimeout/email.tlsConfig/smtpPassword to
  >   values.schema.json
  > - add 'service' to group_by in generate-alertmanager-config.sh and
  >   alertmanager.example.yml to match the chart groupBy
  > - document v1beta1 API version and the new email credential model in helm README
  > - fix MD060 table alignment in helm README
  >
  > * test(helm): update render test for email plain-string SMTP fields
  >
  > The AlertmanagerConfig EmailConfig CRD renders to/from/smarthost as plain
  > strings, not Secret selectors, so the email SMTP fields are no longer stored
  > in the alerting Secret. Update the render-helm-templates action to assert that
  > smarthost/to render as plain values in the AlertmanagerConfig and that the
  > Secret no longer contains email-to/smtp-host/smtp-from keys.
  >
  > * fix(alerting): skip empty alerting Secret for email without SMTP password
  >
  > When platform=email and neither smtpPassword nor dmsWebhookUrl is set, the
  > alerting Secret had an empty stringData. Guard the Secret template so it only
  > renders when there is at least one credential key to store, while keeping the
  > fail-closed platform/credential validation active.
  >
  > Update the render-helm-templates action to assert the SMTP password (when set)
  > is stored in the Secret and that an email without smtpPassword/dmsWebhookUrl
  > does not render an empty Secret.
  >
  > * docs(alerting): address webhook notification review comments
  >
  > * test(containers): retry MySQL and Postgres container boot on transient pull failures
  >
  > * style(containers): apply rustfmt to container boot retry
  >
  > ---------

### Bug Fixes

- [9476030](
https://github.com/adorsys/status-list-server/commit/94760306663621ccf556c8f579f6e9557053743c) *(docs)* Update error response formats to use JSON instead of plain text by @Ngha-Boris in [#509](
https://github.com/adorsys/status-list-server/pull/509)

- [fe43572](
https://github.com/adorsys/status-list-server/commit/fe43572c95b44440cabb6747a72bc35da1572c79) *(watcher)* Only rotate on real content changes, not read/open events by @Christiantyemele in [#532](
https://github.com/adorsys/status-list-server/pull/532)

  > * fix(watcher): only rotate on real content changes, not read/open events
  >
  > * refactor(watcher): harden fingerprinting and logging per review

### Performance

- [172738a](
https://github.com/adorsys/status-list-server/commit/172738a248a1ce0e8b9098be7f83b323cdb86f5f) *(ci)* Optimize cargo build caching and eliminate cold starts by @Hermann-Core in [#497](
https://github.com/adorsys/status-list-server/pull/497)

  > * perf(ci): optimize cargo build caching and eliminate cold starts
  >
  > * docs(ci): update docker build caching rationale in CI workflow

### Miscellaneous Tasks

- [8f63825](
https://github.com/adorsys/status-list-server/commit/8f63825b0e701e209f140782a020349008bb683a) *(uncategorized)* Sync develop into main by @Hermann-Core in [#538](
https://github.com/adorsys/status-list-server/pull/538)

**Full Changelog**: https://github.com/adorsys/status-list-server/compare/v1.1.2...v1.2.0



## [1.1.2] - 2026-09-04

### Bug Fixes

- *(ci)* Fetch repo and pass repository flag for digest artifact download by @Hermann-Core


## [1.1.1] - 2026-09-04

### Bug Fixes

- *(fix)* Unset CARGO_BUILD_TARGET when installing cargo tools in Dockerfile by @Hermann-Core


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

