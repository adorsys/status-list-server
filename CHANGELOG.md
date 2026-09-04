# Changelog

All notable changes to this project will be documented in this file.
<!-- markdownlint-disable line-length no-bare-urls ul-style emphasis-style -->

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

