# Dependency maintenance audit — issue #618

Baseline: `5db173e1`. Audit date: 2026-10-09. Tracker: [#618](https://github.com/adorsys/status-list-server/issues/618).

This document is the reviewable PR description/inventory for the compatible maintenance batch. It does not close the tracker: the linked migration and security deferrals below remain outstanding. Versions are resolved lockfile versions, not the lower bound in a Cargo requirement. No direct runtime dependency was removed and no security exception was added. The Cargo lockfile refresh is deferred because its new versions do not pass the existing cargo-vet policy.

## Reproduce the inventory and refresh

```bash
python3 scripts/dependency-inventory.py
# After the new versions have audit coverage: cargo update && cargo vet --locked
(cd perf && npm update --package-lock-only && npm ci)
(cd scripts/local-ci/node && npm install --package-lock-only && npm ci)
(cd demo && uv lock --upgrade && uv export --locked --format requirements-txt -o requirements.txt)
uv pip compile scripts/local-ci/requirements.in --upgrade --generate-hashes --no-header --output-file scripts/local-ci/requirements.txt
```

Use Node >=22.18 for the performance harness. Audit resolution used Rust/Cargo 1.96.1 and uv 0.12.15; CI export verification uses uv 0.12.24. `rust-toolchain.toml` tracks `stable`, while Docker pins its compiler through the builder digest. A proposed Cargo refresh resolved with the installed compiler but failed `cargo vet --locked`: 121 new crate versions lacked required audit coverage even after updating imported audits. The compatible Cargo versions are therefore retained until the affected releases are audited or covered by trusted upstream audits. Do not add blanket exemptions to make the refresh pass.

## Cargo direct dependencies

The root and xtask are members of one workspace and share `Cargo.lock`. Rows include optional, target-specific, and test dependencies. The release links identify upstream release metadata. The proposed compatible Cargo updates are deferred under [the cargo-vet blocker](#cargo-vet-blocker); Cargo deny/audit results are separate checks.

| Manifest / dependency | Before | Target in this batch | Latest stable | Rationale / result |
| --- | --- | --- | --- | --- |
| Cargo.toml: `tokio` | 1.53.1 | 1.53.1 | [1.53.2](https://crates.io/crates/tokio/1.53.2) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `async-trait` | 0.1.92 | 0.1.92 | [0.1.92](https://crates.io/crates/async-trait/0.1.92) | Current supported release; retained |
| Cargo.toml: `arc-swap` | 1.9.2 | 1.9.2 | [1.9.2](https://crates.io/crates/arc-swap/1.9.2) | Current supported release; retained |
| Cargo.toml: `notify` | 8.2.0 | 8.2.0 | [8.2.0](https://crates.io/crates/notify/8.2.0) | Current supported release; retained |
| Cargo.toml: `hyper` | 1.11.0 | 1.11.0 | [1.12.0](https://crates.io/crates/hyper/1.12.0) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `hyper-util` | 0.1.20 | 0.1.20 | [0.1.21](https://crates.io/crates/hyper-util/0.1.21) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `reqwest` | 0.13.4 | 0.13.4 | [0.13.5](https://crates.io/crates/reqwest/0.13.5) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `tower` | 0.5.3 | 0.5.3 | [0.5.3](https://crates.io/crates/tower/0.5.3) | Current supported release; retained |
| Cargo.toml: `hyper-rustls` | 0.27.9 | 0.27.9 | [0.27.10](https://crates.io/crates/hyper-rustls/0.27.10) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `axum` | 0.8.9 | 0.8.9 | [0.8.9](https://crates.io/crates/axum/0.8.9) | Current supported release; retained |
| Cargo.toml: `tower-http` | 0.7.0 | 0.7.0 | [0.7.1](https://crates.io/crates/tower-http/0.7.1) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `tower_governor` | 0.8.0 | 0.8.0 | [0.8.0](https://crates.io/crates/tower_governor/0.8.0) | Current supported release; retained |
| Cargo.toml: `governor` | 0.10.4 | 0.10.4 | [0.10.4](https://crates.io/crates/governor/0.10.4) | Current supported release; retained |
| Cargo.toml: `moka` | 0.12.16 | 0.12.16 | [0.12.16](https://crates.io/crates/moka/0.12.16) | Current supported release; retained |
| Cargo.toml: `aws-lc-rs` | 1.18.0 | 1.18.0 | [1.18.1](https://crates.io/crates/aws-lc-rs/1.18.1) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `pem` | 3.0.6 | 3.0.6 | [4.0.0](https://crates.io/crates/pem/4.0.0) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `pkcs8` | 0.11.0 | 0.11.0 | [0.11.0](https://crates.io/crates/pkcs8/0.11.0) | Current supported release; retained |
| Cargo.toml: `sec1` | 0.8.1 | 0.8.1 | [0.8.1](https://crates.io/crates/sec1/0.8.1) | Current supported release; retained |
| Cargo.toml: `der` | 0.8.2 | 0.8.2 | [0.8.2](https://crates.io/crates/der/0.8.2) | Current supported release; retained |
| Cargo.toml: `coset` | 0.4.2 | 0.4.2 | [0.4.2](https://crates.io/crates/coset/0.4.2) | Current supported release; retained |
| Cargo.toml: `instant-acme` | 0.8.5 | 0.8.5 | [0.8.5](https://crates.io/crates/instant-acme/0.8.5) | Current supported release; retained |
| Cargo.toml: `rustls` | 0.23.45 | 0.23.45 | [0.23.45](https://crates.io/crates/rustls/0.23.45) | Current supported release; retained |
| Cargo.toml: `webpki-roots` | 1.0.9 | 1.0.9 | [1.0.9](https://crates.io/crates/webpki-roots/1.0.9) | Current supported release; retained |
| Cargo.toml: `rustls-pki-types` | 1.15.1 | 1.15.1 | [1.15.1](https://crates.io/crates/rustls-pki-types/1.15.1) | Current supported release; retained |
| Cargo.toml: `secrecy` | 0.10.3 | 0.10.3 | [0.10.3](https://crates.io/crates/secrecy/0.10.3) | Current supported release; retained |
| Cargo.toml: `rcgen` | 0.14.9 | 0.14.9 | [0.14.10](https://crates.io/crates/rcgen/0.14.10) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `jsonwebtoken` | 11.1.0 | 11.1.0 | [11.1.0](https://crates.io/crates/jsonwebtoken/11.1.0) | Current supported release; retained |
| Cargo.toml: `sha2` | 0.10.9 | 0.10.9 | [0.11.0](https://crates.io/crates/sha2/0.11.0) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `hex` | 0.4.3 | 0.4.3 | [0.4.3](https://crates.io/crates/hex/0.4.3) | Current supported release; retained |
| Cargo.toml: `serde_json` | 1.0.151 | 1.0.151 | [1.0.151](https://crates.io/crates/serde_json/1.0.151) | Current supported release; retained |
| Cargo.toml: `serde-aux` | 4.7.0 | 4.7.0 | [4.7.0](https://crates.io/crates/serde-aux/4.7.0) | Current supported release; retained |
| Cargo.toml: `serde` | 1.0.229 | 1.0.229 | [1.0.229](https://crates.io/crates/serde/1.0.229) | Current supported release; retained |
| Cargo.toml: `config` | 0.15.25 | 0.15.25 | [0.15.27](https://crates.io/crates/config/0.15.27) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `dotenvy` | 0.15.7 | 0.15.7 | [0.15.7](https://crates.io/crates/dotenvy/0.15.7) | Current supported release; retained |
| Cargo.toml: `tracing` | 0.1.44 | 0.1.44 | [0.1.44](https://crates.io/crates/tracing/0.1.44) | Current supported release; retained |
| Cargo.toml: `tracing-subscriber` | 0.3.23 | 0.3.23 | [0.3.23](https://crates.io/crates/tracing-subscriber/0.3.23) | Current supported release; retained |
| Cargo.toml: `opentelemetry` | 0.32.0 | 0.32.0 | [0.33.0](https://crates.io/crates/opentelemetry/0.33.0) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `opentelemetry_sdk` | 0.32.1 | 0.32.1 | [0.33.0](https://crates.io/crates/opentelemetry_sdk/0.33.0) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `opentelemetry-otlp` | 0.32.0 | 0.32.0 | [0.33.0](https://crates.io/crates/opentelemetry-otlp/0.33.0) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `opentelemetry-appender-tracing` | 0.32.0 | 0.32.0 | [0.33.0](https://crates.io/crates/opentelemetry-appender-tracing/0.33.0) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `tracing-opentelemetry` | 0.33.0 | 0.33.0 | [0.34.0](https://crates.io/crates/tracing-opentelemetry/0.34.0) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `opentelemetry-prometheus` | 0.32.0 | 0.32.0 | [0.33.0](https://crates.io/crates/opentelemetry-prometheus/0.33.0) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `prometheus` | 0.14.0 | 0.14.0 | [0.14.0](https://crates.io/crates/prometheus/0.14.0) | Current supported release; retained |
| Cargo.toml: `metrics-process` | 2.4.3 | 2.4.3 | [2.4.3](https://crates.io/crates/metrics-process/2.4.3) | Current supported release; retained |
| Cargo.toml: `thiserror` | 2.0.20 | 2.0.20 | [2.0.21](https://crates.io/crates/thiserror/2.0.21) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `color-eyre` | 0.6.5 | 0.6.5 | [0.6.5](https://crates.io/crates/color-eyre/0.6.5) | Current supported release; retained |
| Cargo.toml: `uuid` | 1.24.1 | 1.24.1 | [1.27.0](https://crates.io/crates/uuid/1.27.0) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `base64` | 0.22.1 | 0.22.1 | [0.23.1](https://crates.io/crates/base64/0.23.1) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `time` | 0.3.55 | 0.3.55 | [0.3.55](https://crates.io/crates/time/0.3.55) | Current supported release; retained |
| Cargo.toml: `base64url` | 0.1.0 | 0.1.0 | [0.1.0](https://crates.io/crates/base64url/0.1.0) | Current supported release; retained |
| Cargo.toml: `flate2` | 1.1.9 | 1.1.9 | [1.1.10](https://crates.io/crates/flate2/1.1.10) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `x509-parser` | 0.18.1 | 0.18.1 | [0.18.1](https://crates.io/crates/x509-parser/0.18.1) | Current supported release; retained |
| Cargo.toml: `public-suffix` | 0.1.3 | 0.1.3 | [0.1.3](https://crates.io/crates/public-suffix/0.1.3) | Current supported release; retained |
| Cargo.toml: `tokio-cron-scheduler` | 0.15.1 | 0.15.1 | [0.15.1](https://crates.io/crates/tokio-cron-scheduler/0.15.1) | Current supported release; retained |
| Cargo.toml: `url` | 2.5.8 | 2.5.8 | [2.5.8](https://crates.io/crates/url/2.5.8) | Current supported release; retained |
| Cargo.toml: `dashmap` | 6.2.1 | 6.2.1 | [6.2.1](https://crates.io/crates/dashmap/6.2.1) | Current supported release; retained |
| Cargo.toml: `sea-orm` | 1.1.20 | 1.1.20 | [2.0.4](https://crates.io/crates/sea-orm/2.0.4) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `sea-orm-migration` | 1.1.20 | 1.1.20 | [2.0.4](https://crates.io/crates/sea-orm-migration/2.0.4) | Compatible version retained; [breaking migration deferred](#rust-migrations) |
| Cargo.toml: `aws-config` | 1.10.1 | 1.10.1 | [1.12.0](https://crates.io/crates/aws-config/1.12.0) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `aws-sdk-route53` | 1.119.0 | 1.119.0 | [1.127.0](https://crates.io/crates/aws-sdk-route53/1.127.0) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `aws-sdk-secretsmanager` | 1.112.0 | 1.112.0 | [1.120.0](https://crates.io/crates/aws-sdk-secretsmanager/1.120.0) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `google-cloud-secretmanager-v1` | 1.12.0 | 1.12.0 | [1.14.0](https://crates.io/crates/google-cloud-secretmanager-v1/1.14.0) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `google-cloud-auth` | 1.15.0 | 1.15.0 | [1.17.0](https://crates.io/crates/google-cloud-auth/1.17.0) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `azure_security_keyvault_secrets` | 1.0.0 | 1.0.0 | [1.0.1](https://crates.io/crates/azure_security_keyvault_secrets/1.0.1) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `azure_identity` | 1.0.0 | 1.0.0 | [1.0.0](https://crates.io/crates/azure_identity/1.0.0) | Current supported release; retained |
| Cargo.toml: `azure_core` | 1.1.0 | 1.1.0 | [1.1.0](https://crates.io/crates/azure_core/1.1.0) | Current supported release; retained |
| Cargo.toml: `redis` | 1.7.0 | 1.7.0 | [1.7.1](https://crates.io/crates/redis/1.7.1) | Deferred under [cargo-vet blocker](#cargo-vet-blocker) |
| Cargo.toml: `wiremock` | 0.6.5 | 0.6.5 | [0.6.5](https://crates.io/crates/wiremock/0.6.5) | Current supported release; retained |
| Cargo.toml: `tempfile` | 3.27.0 | 3.27.0 | [3.27.0](https://crates.io/crates/tempfile/3.27.0) | Current supported release; retained |
| Cargo.toml: `testcontainers-modules` | 0.15.0 | 0.15.0 | [0.15.0](https://crates.io/crates/testcontainers-modules/0.15.0) | Current supported release; retained |
| Cargo.toml: `tikv-jemallocator` | 0.7.0 | 0.7.0 | [0.7.0](https://crates.io/crates/tikv-jemallocator/0.7.0) | Current supported release; retained |
| xtask/Cargo.toml: `color-eyre` | 0.6.5 | 0.6.5 | [0.6.5](https://crates.io/crates/color-eyre/0.6.5) | Current supported release; retained |
| xtask/Cargo.toml: `clap` | 4.6.7 | 4.6.7 | [4.6.7](https://crates.io/crates/clap/4.6.7) | Current supported release; retained |

## npm and Python direct dependencies

| Manifest / dependency | Before | Target | Latest | Rationale / result |
| --- | --- | --- | --- | --- |
| perf/package.json: `jsonwebtoken` | 9.0.3 | 9.0.3 | [9.0.3](https://www.npmjs.com/package/jsonwebtoken/v/9.0.3) | Compatible refresh; [security blockers](#npm-security) |
| perf/package.json: `artillery` | 2.0.34 | 2.0.34 | [2.0.34](https://www.npmjs.com/package/artillery/v/2.0.34) | Compatible refresh; [security blockers](#npm-security) |
| scripts/local-ci/node/package.json: `markdownlint-cli2` | 0.23.1 | 0.23.3 | [0.23.3](https://www.npmjs.com/package/markdownlint-cli2/v/0.23.3) | Compatible refresh; [security blockers](#npm-security) |
| scripts/local-ci/node/package.json: `tombi` | 1.2.4 | 1.7.3 | [1.7.3](https://www.npmjs.com/package/tombi/v/1.7.3) | Compatible refresh; [security blockers](#npm-security) |
| demo: `cbor2` | 6.1.4 | 6.1.5 | [6.1.5](https://cbor2.readthedocs.io/en/latest/versionhistory.html) | Compatible maintenance; hashes exported |
| demo: `cryptography` | 50.0.1 | 50.0.2 | [50.0.2](https://pypi.org/project/cryptography/50.0.2/) | Compatible maintenance; hashes exported |
| demo: `pyjwt` | 2.14.0 | 2.15.1 | [2.15.1](https://pypi.org/project/pyjwt/2.15.1/) | Compatible maintenance; hashes exported |
| demo: `python-dotenv` | 1.2.3 | 1.2.4 | [1.2.4](https://github.com/theskumar/python-dotenv) | Compatible maintenance; hashes exported |
| demo: `requests` | 2.34.2 | 2.34.2 | [2.34.2](https://github.com/psf/requests) | Current release; retained |
| local CI: `jsonschema` | 4.26.0 | 4.26.0 | [4.26.0](https://pypi.org/project/jsonschema/) | Current; explicit requirements.in preserves direct ownership and hashed transitive refresh |
| local CI: `pyyaml` | 6.0.3 | 6.0.3 | [6.0.3](https://pypi.org/project/pyyaml/) | Current; explicit requirements.in preserves direct ownership and hashed transitive refresh |

## GitHub Actions

All external actions remain pinned to full commit SHAs. Subactions (cache restore/save, CodeQL init/analyze/upload) use the same repository release. Compatible bumps carry upstream maintenance/security fixes; major/runtime migrations remain separate.

| Action | Before | Target | Latest / release rationale | Result |
| --- | --- | --- | --- | --- |
| `DavidAnson/markdownlint-cli2-action` | v24.1.0 | Removed | [v24.2.0](https://github.com/DavidAnson/markdownlint-cli2-action/releases/tag/v24.2.0) | Its latest wrapper bundles vulnerable 0.23.2; CI now runs the same locked 0.23.3 CLI as local CI |
| `actions/setup-node` | — | v7.1.0 | [v7.1.0](https://github.com/actions/setup-node/releases/tag/v7.1.0) | Added SHA-pinned Node 22 setup for the shared lint lockfile |
| `EmbarkStudios/cargo-deny-action` | v2.1.1 | v2.1.1 | [v2.1.1](https://github.com/EmbarkStudios/cargo-deny-action/releases/tag/v2.1.1) | Current; retained |
| `actions-rust-lang/setup-rust-toolchain` | v1.17.0 | v1.17.0 | [v2.0.0](https://github.com/actions-rust-lang/setup-rust-toolchain/releases/tag/v2.0.0) | [Deferred](#ci-and-build-tool-migrations) |
| `actions/attest-build-provenance` | v4.2.2 | v4.2.2 | [v4.2.2](https://github.com/actions/attest-build-provenance/releases/tag/v4.2.2) | Current; retained |
| `actions/cache` | v5.0.5 | v5.0.5 | [v6.1.0](https://github.com/actions/cache/releases/tag/v6.1.0) | [Deferred](#ci-and-build-tool-migrations) |
| `actions/checkout` | v7.0.1 | v7.0.1 | [v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) | Current; retained |
| `actions/create-github-app-token` | v3.2.0 | v3.2.0 | [v3.2.0](https://github.com/actions/create-github-app-token/releases/tag/v3.2.0) | Current; retained |
| `actions/setup-go` | v6.5.0 | v6.5.0 | [v7.0.0](https://github.com/actions/setup-go/releases/tag/v7.0.0) | [Deferred](#ci-and-build-tool-migrations) |
| `actions/upload-artifact` | v7.0.1 | v7.0.2 | [v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) | Refreshed SHA |
| `amannn/action-semantic-pull-request` | v6.1.1 | v6.1.1 | [v6.1.1](https://github.com/amannn/action-semantic-pull-request/releases/tag/v6.1.1) | Current; retained |
| `aquasecurity/setup-trivy` | v0.2.6 | v0.2.6 | [v0.3.1](https://github.com/aquasecurity/setup-trivy/releases/tag/v0.3.1) | [Deferred](#ci-and-build-tool-migrations) |
| `aquasecurity/trivy-action` | v0.36.0 | v0.36.0 | [v0.36.0](https://github.com/aquasecurity/trivy-action/releases/tag/v0.36.0) | Current; retained |
| `aws-actions/configure-aws-credentials` | v6.2.3 | v6.3.0 | [v6.3.0](https://github.com/aws-actions/configure-aws-credentials/releases/tag/v6.3.0) | Refreshed SHA |
| `azure/setup-helm` | v5.0.1 | v5.0.1 | [v5.0.1](https://github.com/Azure/setup-helm/releases/tag/v5.0.1) | Current; retained |
| `azure/setup-kubectl` | v5.1.0 | v5.2.0 | [v5.2.0](https://github.com/Azure/setup-kubectl/releases/tag/v5.2.0) | Refreshed SHA |
| `dependabot/fetch-metadata` | v3.1.0 | v3.1.0 | [v3.1.0](https://github.com/dependabot/fetch-metadata/releases/tag/v3.1.0) | Current; retained |
| `docker/build-push-action` | v7.3.0 | v7.4.0 | [v7.4.0](https://github.com/docker/build-push-action/releases/tag/v7.4.0) | Refreshed SHA |
| `docker/login-action` | v4.4.0 | v4.6.0 | [v4.6.0](https://github.com/docker/login-action/releases/tag/v4.6.0) | Refreshed SHA |
| `docker/metadata-action` | v6.2.0 | v6.2.0 | [v6.2.0](https://github.com/docker/metadata-action/releases/tag/v6.2.0) | Current; retained |
| `docker/setup-buildx-action` | v4.2.0 | v4.4.1 | [v4.4.1](https://github.com/docker/setup-buildx-action/releases/tag/v4.4.1) | Refreshed SHA |
| `dorny/paths-filter` | v4.0.3 | v4.0.3 | [v4.0.3](https://github.com/dorny/paths-filter/releases/tag/v4.0.3) | Current; retained |
| `github/codeql-action` | v4.37.9 | v4.38.3 | [v4.38.3](https://github.com/github/codeql-action/releases/tag/v4.38.3) | Refreshed SHA |
| `release-plz/action` | v0.5.131 | v0.5.140 | [v0.5.140](https://github.com/release-plz/action/releases/tag/v0.5.140) | Refreshed SHA |
| `taiki-e/install-action` | v2.84.1 | v2.87.26 | [v2.87.26](https://github.com/taiki-e/install-action/releases/tag/v2.87.26) | Refreshed SHA |
| `tombi-toml/setup-tombi` | v1.2.4 | v1.7.3 | [v1.7.3](https://github.com/tombi-toml/setup-tombi/releases/tag/v1.7.3) | Refreshed SHA |
| `wagoid/commitlint-github-action` | v6.2.1 | v6.2.1 | [v6.2.1](https://github.com/wagoid/commitlint-github-action/releases/tag/v6.2.1) | Current; retained |
| `zizmorcore/zizmor-action` | v0.6.2 | v0.6.4 | [v0.6.4](https://github.com/zizmorcore/zizmor-action/releases/tag/v0.6.4) | Refreshed SHA |
| `astral-sh/setup-uv` | — | v10.2.0 | [v10.2.0](https://github.com/astral-sh/setup-uv/releases/tag/v10.2.0) | Added SHA-pinned export consistency gate |

## Developer tools

These pins also occur in `local-ci.sh`, workflow inputs, or Docker build arguments; Dependabot does not parse arbitrary shell install commands. Keep corresponding CI/local pins together.

| Tool | Before | Target | Latest / release notes | Result |
| --- | --- | --- | --- | --- |
| `cargo-nextest` | 0.9.101 | 0.9.101 | [0.9.148](https://github.com/nextest-rs/nextest/releases/tag/cargo-nextest-0.9.148) | [Deferred](#ci-and-build-tool-migrations) |
| `cargo-machete` | 0.9.2 | 0.9.2 | [0.9.2](https://github.com/bnjbvr/cargo-machete/releases) | Current; retained |
| `cargo-vet` | 0.10.2 | 0.10.2 | [0.10.2](https://crates.io/crates/cargo-vet/0.10.2) | Current; retained |
| `cargo-audit` | 0.22.2 | 0.22.2 | [0.22.2](https://crates.io/crates/cargo-audit/0.22.2) | Current; retained |
| `cargo-deny` | 0.20.2 | 0.20.2 | [0.20.2](https://github.com/EmbarkStudios/cargo-deny/releases) | Current; retained |
| `cargo-llvm-cov` | 0.6.16 | 0.6.16 | [0.9.1](https://github.com/taiki-e/cargo-llvm-cov/releases/tag/v0.9.1) | [Deferred](#ci-and-build-tool-migrations) |
| `typos-cli` | 1.49.0 | 1.49.0 | [1.51.1](https://github.com/crate-ci/typos/releases/tag/v1.51.1) | [Deferred](#ci-and-build-tool-migrations) |
| `yamlfmt` | 0.21.0 | 0.21.0 | [0.21.0](https://github.com/google/yamlfmt/releases/tag/v0.21.0) | Current; retained |
| `helm` | 4.2.4 | 4.2.4 | [4.3.0](https://github.com/helm/helm/releases/tag/v4.3.0) | [Deferred](#ci-and-build-tool-migrations) |
| `kube-linter` | 0.8.3 | 0.8.3 | [0.8.3](https://github.com/stackrox/kube-linter/releases/tag/v0.8.3) | Current; retained |
| `zizmor` | 1.28.0 | 1.28.0 | [1.30.1](https://github.com/zizmorcore/zizmor/releases/tag/v1.30.1) | [Deferred](#ci-and-build-tool-migrations) |
| `trivy` | 0.70.0 | 0.70.0 | [0.75.0](https://github.com/aquasecurity/trivy/releases/tag/v0.75.0) | [Deferred](#ci-and-build-tool-migrations) |
| `cargo-auditable` | 0.7.5 | 0.7.5 | [0.7.7](https://github.com/rust-secure-code/cargo-auditable/releases/tag/v0.7.7) | [Deferred](#ci-and-build-tool-migrations) |
| `rust-audit-info` | 0.5.4 | 0.5.4 | [0.5.4](https://crates.io/crates/rust-audit-info/0.5.4) | Current; retained |
| `uv (new CI pin)` | — | 0.12.24 | [0.12.24](https://github.com/astral-sh/uv/releases/tag/0.12.24) | Added export gate |

## Container and build images

`python3 scripts/dependency-inventory.py` now records image references and source lines from the application Dockerfile, Compose, CI workflows, local scripts, and Helm chart YAML. Repeated references are retained because a pinned digest can drift between the local and CI copy. This table groups equivalent references and records the review result; mutable tags and user-supplied chart images are called out separately.

| Current reference(s) | Source | Target in this batch | Latest / release rationale | Result |
| --- | --- | --- | --- | --- |
| `blackdex/rust-musl:x86_64-musl@sha256:875ccf23…` and `blackdex/rust-musl:aarch64-musl@sha256:9f1f5a00…` | Dockerfile | Same pinned digests | Builder/compiler pair is coupled to the two-architecture musl build and SBOM checks; see [cargo-auditable deferral](#ci-and-build-tool-migrations). | Retained; no digest change |
| `ghcr.io/zizmorcore/zizmor:1.28.0@sha256:8e6b3e4f…` | CI, local CI | Same pinned digest | Scanner version is pinned in the workflow and tool config; policy changes require its negative fixture to be reviewed. See [lint-policy deferral](#ci-and-build-tool-migrations). | Retained; no digest change |
| `aquasec/trivy:0.70.0@sha256:be1190af…` | Local CI and CI inputs | Same pinned digest | Scanner upgrade is coupled to installer, database cache, report schema, and release gate; see [Trivy deferral](#ci-and-build-tool-migrations). | Retained; no digest change |
| `otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78…`, `prom/prometheus:v3.11.3@sha256:e4254400…`, `jaegertracing/jaeger:2.20.0@sha256:46a88626…` | Compose, Helm CI, local checks | Same tags and digests | Images validate the collector configuration, Prometheus rules, and rendered chart. A refresh must keep the local/CI pins aligned and rerun those config checks. | Retained; exact pins agree where shared |
| `postgres:18.4` → `postgres:18.6`, `mysql:9.2`, `redis:8.10-alpine` | Compose | `postgres:18.6`; other tags retained | These images define the local provider/database test environment. PostgreSQL 18.6 is available ([official image tags](https://hub.docker.com/_/postgres)); updated within the same major, with the PostgreSQL profile checks still required. MySQL 9.2 is behind the 9.7.2 tag ([official image listing](https://hub.docker.com/_/mysql)); defer its innovation-release migration until the MySQL test profile is validated across supported behavior. Redis 8.10 is a series tag whose current patch is 8.10.2 ([official image tags](https://hub.docker.com/_/redis)). | PostgreSQL patched; MySQL migration deferred; Redis series tag retained |
| `floci/floci:2.2.0` | Compose | Same tag | [Upstream 2.2.0](https://github.com/floci-io/floci/releases/tag/2.2.0) is the current stable release. | Current; retained |
| `ghcr.io/letsencrypt/pebble:2.10` and `pebble-challtestsrv:2.10` | Compose | Same tags | Upstream released [v2.10.1](https://github.com/letsencrypt/pebble/releases/tag/v2.10.1) with ACME behavior and dependency fixes. Verify the matching GHCR tags, then upgrade both images together and run certificate issuance/renewal tests against the committed Pebble configuration. | Patch release deferred under [ACME image validation](#container-image-follow-ups) |
| `alpine:3.24` | Compose | Same series tag | The official image maps `3.24` to the current [3.24.2 patch](https://hub.docker.com/_/alpine); this helper only copies the sample certificate and key in the `fscert` profile. | Current stable series; retained |
| `prom/alertmanager:v0.28.1` | Compose | Same tag | [v0.34.1](https://github.com/prometheus/alertmanager/releases/tag/v0.34.1) is current and includes alert-inhibition fixes. The intervening pre-1.0 releases can change receiver/config behavior; validate generated configurations with the matching `amtool` and exercise all notification routes before updating. | Migration deferred under [observability image validation](#container-image-follow-ups) |
| `grafana/grafana:12.0.0` | Compose | Same tag | [v13.2.3](https://github.com/grafana/grafana/releases/tag/v13.2.3) is current; [v12.4.12](https://github.com/grafana/grafana/releases/tag/v12.4.12) is a newer release on the 12.x line. Validate dashboard JSON, provisioning, datasource configuration, and the 12-to-13 migration separately. | Migration deferred under [observability image validation](#container-image-follow-ups) |
| `prom/pushgateway:v1.11.2` | Compose | Same tag | [v1.11.3](https://github.com/prometheus/pushgateway/releases/tag/v1.11.3) is the current patch and is published as an [official image tag](https://hub.docker.com/r/prom/pushgateway/tags). Its release updates Go dependencies. Verify the metrics push/scrape path and related dashboards before changing the Compose tag. | Patch release deferred under [observability image validation](#container-image-follow-ups) |
| `busybox:1.37` (chart default/test) and `busybox:1.37.0` (local values) | Helm | Local fixture switched from `1.38` to `1.37.0` | [BusyBox 1.38.0 is marked unstable upstream](https://busybox.net/); the [official image lists both stable 1.37.0 and unstable 1.38.0 tags](https://hub.docker.com/_/busybox). The local values still exercise an explicit image override while staying on the stable release. | Stable image selected; rendered chart checks updated |
| `postman/newman@sha256:02dc4a28…` | API collection validation script | Same pinned digest | API collection runner is digest-pinned so the test tool cannot move independently of its validation contract. | Retained; no digest change |
| `ghcr.io/adorsys/status-list-server` | Helm values/template | User-supplied release tag or digest | This is the service image selected by deployment values, rather than a build/test tool pin. The chart validates explicit tags/digests and does not set a mutable default release. | No fixed image version to upgrade |

The inventory script records references and locations, not registry freshness. The release and tag comparisons above were checked against upstream release pages and official image listings on 2026-10-12. Docker Hub's [PostgreSQL tags](https://hub.docker.com/_/postgres), [MySQL listing](https://hub.docker.com/_/mysql), and [Redis tags](https://hub.docker.com/_/redis) were used for the database image observations above. The newer image releases left pinned here have explicit validation work below; their current tags are not claimed to be the latest.

### Container image follow-ups

- **ACME image validation:** move Pebble and challtestsrv together to the upstream 2.10.1 patch after confirming both GHCR tags exist. Run the `acme` Compose profile and the certificate issuance/renewal integration tests with the pinned configuration. This is deferred under [#618](https://github.com/adorsys/status-list-server/issues/618) because a release comparison alone does not prove the two image tags or the test contract.
- **Observability image validation:** update Pushgateway 1.11.3 in a patch batch and Alertmanager ([#645](https://github.com/adorsys/status-list-server/issues/645))/Grafana ([#644](https://github.com/adorsys/status-list-server/issues/644)) in separate migration PRs. Run the `observability` Compose profile, generated Alertmanager config tests with the target `amtool`, Prometheus scrape and Pushgateway metrics checks, and Grafana dashboard/provisioning smoke checks. The current releases are listed above; these images stay pinned until the profile is validated. Track the PRs under [#618](https://github.com/adorsys/status-list-server/issues/618).

## Cargo-vet blocker

The proposed full Cargo lockfile refresh failed `cargo vet --locked` with 121 unvetted crate versions after the available imported audits were refreshed. The existing `supply-chain/config.toml` criteria and exemptions were not broadened. The current committed `Cargo.lock` and `supply-chain/imports.lock` remain aligned; `cargo vet --locked --frozen` passes with 71 fully audited, 3 partially audited, and 610 previously exempted crates. Refresh the lockfile only in reviewable groups with matching trusted audits or completed crate reviews, and rerun the full CI security checks. This remains a blocker under [#646](https://github.com/adorsys/status-list-server/issues/646).

## Deferrals and review boundaries

These are explicit follow-ups under [#618](https://github.com/adorsys/status-list-server/issues/618), not completed migrations. Each breaking boundary below needs its own reviewable PR linked from the tracker. The [migration follow-up index](dependency-migration-follow-ups-618.md) records the linked issues. The tracker's major-migration acceptance criterion remains open until those PRs land.

### Rust migrations

- **SeaORM 2.0.4 ([#640](https://github.com/adorsys/status-list-server/issues/640)):** keep both ORM and migration crates on 1.1.20 together. The 2.x move changes the database/SQL dependency boundary and must prove existing-schema upgrade, migrations, transactions, and all three SQL backends separately. Do not remove the mock-enabled dev dependency: it contributes test features to the optional runtime dependency. [Upstream release](https://crates.io/crates/sea-orm/2.0.4).
- **OpenTelemetry 0.33 / tracing-opentelemetry 0.34 ([#641](https://github.com/adorsys/status-list-server/issues/641)):** migrate the API, SDK, OTLP exporter, tracing bridge, and Prometheus exporter together. Pre-1.0 minor versions are incompatible Cargo requirements; mixed provider/exporter types are not interchangeable. Verify emitted metrics and collector/dashboard compatibility in that PR. The updated Google SDK brings its own telemetry versions transitively; this does not authorize replacing the application's telemetry API.
- **pem 4, base64 0.23, sha2 0.11 ([#642](https://github.com/adorsys/status-list-server/issues/642)):** separate crypto/encoding API migration. Preserve certificate loading, PEM/DER round trips, JWT/COSE signatures, ETags, and encoded status-list bytes. The presence of another version transitively is not evidence that the application's direct import can be removed or bumped safely.

### CI and build-tool migrations

- **setup-rust-toolchain 2, cache 6, setup-go 7 ([#643](https://github.com/adorsys/status-list-server/issues/643)):** separate Actions runtime/cache migration. Check runner compatibility, permissions, cache keys, and behavior on reusable workflows before replacing these majors. They remain SHA-pinned.
- **setup-trivy 0.3 / Trivy 0.75 ([#648](https://github.com/adorsys/status-list-server/issues/648)):** move the installer, native version, container digest, and scan/report fixtures together. The release pipeline depends on exit codes, JSON/SARIF fields, database caching, and fail-closed advisory handling. Keep the validated 0.70 scanner contract for this batch.
- **nextest 0.9.148 / llvm-cov 0.9.1 ([#649](https://github.com/adorsys/status-list-server/issues/649)):** separate test-runner/coverage upgrade. Nextest changes timeout and failure classification; validate container test groups, leak handling, retries, doctest execution, and coverage before changing the shared CI/local runner. llvm-cov crosses incompatible pre-1.0 version lines.
- **Helm 4.3 ([#650](https://github.com/adorsys/status-list-server/issues/650)):** defer the deployment-tool upgrade because upstream changes ownership verification during deletion and Kubernetes dependencies. Validate install/upgrade/rollback and all supported platform checksums together, preserving the chart's deployment contract.
- **Zizmor 1.30.1 and typos 1.51.1 ([#651](https://github.com/adorsys/status-list-server/issues/651)):** separate lint-policy refresh. New audit rules/dictionaries can change the fail-closed gate, and Zizmor's pinned image and negative fixture must change together. This batch updates the Zizmor action wrapper while explicitly retaining scanner 1.28.0; no severity is suppressed to make a bump pass.
- **cargo-auditable 0.7.7 ([#652](https://github.com/adorsys/status-list-server/issues/652)):** defer until both architecture builds demonstrate readable, nonempty `.dep-v0` sections with rust-audit-info 0.5.4 under release LTO/strip settings. The pinned builder/compiler pair remains current. The [tool ownership process](supply-chain.md#tool-ownership) applies; a native Cargo test is not evidence of auditable musl output on both architectures.
- **MySQL container 9.2 to 9.7.2 ([#653](https://github.com/adorsys/status-list-server/issues/653)):** defer as a separate database-image migration because it crosses innovation releases; run the MySQL provider/profile and integration checks before changing the local compose service. The existing `mysql:9.2` tag remains documented in [the image inventory](#container-and-build-images).

### npm security

[#547](https://github.com/adorsys/status-list-server/issues/547) is **closed as not planned** upstream (2026-10-08), not evidence that all performance dependencies are safe. Keep it linked as the performance-workspace security blocker; do not create a duplicate issue.

The existing scoped overrides remain intact. `npm ls brace-expansion minimatch` confirms the old 1.x/3.x paths resolve to brace-expansion 1.1.21 and minimatch 3.1.5. Other major versions belong to different dependency paths and must not be forced onto those old majors.

After `npm ci`, the Artillery workspace still reports **7 vulnerabilities (4 moderate, 3 high)** through Artillery 2.0.34. Advisory roots include [braces](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm), [csv-parse](https://github.com/advisories/GHSA-8cw4-87c7-c6xx), and [sprintf-js](https://github.com/advisories/GHSA-hp3w-g68c-fv3c). npm proposes Artillery **0.0.2**, an incompatible downgrade, not a supported remediation. An upstream dependency migration and unchanged-workload validation are required. No broad cross-major overrides or `npm audit fix --force` were applied.

The local CI npm workspace also reports **9 vulnerabilities (3 low, 1 moderate, 5 high)** through current markdownlint-cli2 0.23.3, including braces, smol-toml, and KaTeX dependency paths. npm proposes downgrading markdownlint-cli2 to 0.21.0. Keep this tooling-security follow-up under [#618](https://github.com/adorsys/status-list-server/issues/618); adopting that downgrade would replace the supported lint version. Neither npm audit is recorded as passing.

## Update ownership

- Cargo: Dependabot at `/` owns both workspace members and the shared lockfile. Major upgrades are no longer grouped into one PR. Proposed lockfile updates must pass cargo-vet before merge; the current refresh is deferred under the [cargo-vet blocker](#cargo-vet-blocker).
- npm: Dependabot covers both committed package-lock v3 workspaces. Only patch/minor updates are grouped.
- Demo: the `uv` ecosystem owns `pyproject.toml` and `uv.lock`. There is deliberately no competing pip updater for the exported requirements. The new required CI job checks the lock and exact hashed export; update PRs must regenerate the export before merging.
- Local CI Python: one pip updater owns the explicit `requirements.in` and hashed `requirements.txt`; uv is the documented native refresh command.
- Actions/Docker: existing Dependabot ownership remains; action major upgrades are ungrouped. Full SHA and builder digest pinning is preserved.
- Shell tool pins and configuration-coupled validation images: manual review under the deferrals above and [Tool Ownership](supply-chain.md#tool-ownership); do not add a second bot that competes for Cargo/npm/uv files.

[GitHub's supported-ecosystem documentation](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories) lists native Cargo, npm, uv, pip, Actions, and Docker support. The demo's uv format is version 1, revision 3. The inventory tool does not query latest releases: use Cargo's sparse index, npm registry metadata, PyPI JSON metadata, and upstream GitHub release/tag APIs to reproduce the latest-version comparison, and resolve action tags to commits before editing pins.
