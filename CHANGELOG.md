# Changelog

All notable changes to this project will be documented in this file.
<!-- markdownlint-disable line-length no-bare-urls ul-style emphasis-style -->

## [2.0.0] - 2026-10-30

### Features

- *(aggregation)* Scope status list aggregation to one issuer [**breaking**]

- *(cache)* Implement Redis cache support and update configuration options

- *(compose)* Split optional services into profiles

- *(crypto)* Support multi-curve keys with PEM-only provisioning [**breaking**]

- *(compose)* Fix docker compose configuration conflict when both env and envtemplate exist

- *(tests)* Add postman assets and Microcks contract testing support

- *(xtask)* Adopt cargo xtask workflow

- *(compose)* Replace LocalStack with Floci for AWS emulation and update related configurations

- *(cache)* Cache signed status-list tokens per validity window and use weak identity-derived ETags

- *(ci)* Rewrite local CI script for improved functionality and clarity

- *(auth)* Make the status list sub URI one authoritative value that issuers can read

- *(statuslist)* Add allocation and recording of indices for status lists

- *(docs)* Consolidate license badges and restore dependencies and release tag badges in readme

- *(statuslist)* Status list aggregation endpoint

- *(statuslist)* Enforce 8-bit capacity for application-specific status values and update related validations

- *(openapi)* Align openapi status contract dual stringinteger deserialization

- *(db)* Update database password handling and support MySQL

- *(ci)* Image provenance self asserted

### Bug Fixes

- *(ci)* Give each Trivy SARIF run a distinct category and move codeql-action to v4

- *(demo)* Replace Jupyter notebooks with plain workflow scripts

- *(demo)* Move demo environment to uv and align notebooks

- *(deploy)* Point release at datev-wallet ClusterSecretStore

- *(deps)* Update quinn-proto

- *(docker)* Pin builder base images to immutable sha256 digests

- *(helm)* Align chart monitoring with shared kube-prometheus-stack

- *(migrations)* Make rollbacks across migrations recoverable

- *(tests)* Clean up scoped database fixture containers

- *(http)* Negotiate Accept per RFC 9110 for status list retrieval

- *(auth)* Reject token lifetime values the spec forbids

- *(db)* Reject empty PATCH and validate duplicate indices

- *(auth)* Prevent 304 Not Modified when client JWT has expired

### Refactor

- *(deploy)* Consolidate helm and observability assets under deploy/

- *(acme)* Consolidate Azure modules under outbound::azure

- *(database)* Split store.rs tests into concern-based modules

### Documentation

- *(adr)* Add an ADR template and record the issuer trust decision

- *(helm)* Expand chart value and template documentation

### Performance

- *(perf)* Make the performance-test workspace discoverable and harness-agnostic

- *(perf)* Cache pre-parsed CWT x5chain and eliminate token clone allocations



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

