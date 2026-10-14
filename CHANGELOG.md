# Changelog

All notable changes to this project will be documented in this file.
<!-- markdownlint-disable line-length no-bare-urls ul-style emphasis-style -->

## [Unreleased]

### Upgrade notes

- Fixed-size status-list metadata is stored inside the status-list document. Do not run this release side by side with older pods: an older pod that updates a fixed-size list can write the document back without `size` and `default_status`, turning that list into a caller-managed list. Complete the rollout before sending fixed-size publish or allocation traffic.
- `limits.max_lists_per_issuer` is new and enforced. Fresh installs enforce it from the first start. When upgrading an existing SQL database, pods refuse to start until it is enabled: deploy with `APP_LIMITS__LIST_QUOTA_TRANSITION=true`, then, once no pod of the previous release is left, run `status-list-server list-quota recount` and `status-list-server list-quota enable`, and remove the setting. See `docs/troubleshooting.md`, "Upgrading to the list quota".

### Changed

- Bump the Helm chart to `0.5.0` for render-time validation changes.
- Helm MySQL deployments are external-only and now require `statuslist.env.APP_DATABASE__HOST` plus an explicit `statuslist.image.tag` or `statuslist.image.digest`; when NetworkPolicy is enabled they also require `statuslist.networkPolicy.databaseEgress`.
- The Helm chart intentionally accepts only `postgres` and `mysql` backends. Use non-Helm local/custom deployment paths for `sqlite` or `memory`.
- `mysql.enabled=true` remains unsupported, while `mysql.enabled=false` is accepted for overlays that explicitly disable unused components.

## [1.2.0] - 2026-09-14

### Features

- *(auth)* Enhance JWT management claims validation and configuration by @Ngha-Boris

- *(auth)* Introduce AuthenticatedIssuer struct for better issuer management by @Ngha-Boris

- *(docs)* Refresh readme to match current implementation and configuration by @Blindspot22

- *(dns)* Add support for GKE and AKS Workload Identity in DNS provider configuration by @Ngha-Boris

- *(observability)* Add webhook based alert notifications for observability alerts by @ndefokou

### Bug Fixes

- *(docs)* Update error response formats to use JSON instead of plain text by @Ngha-Boris

- *(watcher)* Only rotate on real content changes, not read/open events by @Christiantyemele

### Performance

- *(ci)* Optimize cargo build caching and eliminate cold starts by @Hermann-Core


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

