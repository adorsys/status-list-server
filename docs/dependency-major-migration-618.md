# Major dependency migration — issue #618

This branch is stacked on the compatible maintenance PR (#654). It groups the
breaking upgrades requested for one major PR. The inventory and original
deferral rationale are in [the maintenance audit](dependency-audit-618.md).

## Changes in this branch

| Area | Upgrade |
| --- | --- |
| Database | SeaORM and migration 1.1 → 2.0.4, with SQLx 0.9 and Sea Query 1.0 API changes |
| Telemetry | OpenTelemetry stack 0.32 → 0.33 and tracing bridge 0.33 → 0.34 |
| Crypto and encoding | PEM 3 → 4, SHA-2 0.10 → 0.11, base64 0.22 → 0.23 |
| Actions | SHA-pinned setup-rust-toolchain 2, cache 6, setup-go 7 |
| Security scanners | setup-trivy 0.3.1, Trivy 0.75.0, Zizmor 1.30.1, typos 1.51.1 |
| Test and deployment tools | nextest 0.9.148, llvm-cov 0.9.1, Helm 4.3.0, cargo-auditable 0.7.7 |
| Local images | MySQL 9.7.2, Alertmanager 0.34.1, Grafana 13.2.3, Pushgateway 1.11.3 |

Action references remain full commit SHAs. The Trivy and Zizmor image digests
were resolved from their release tags. Helm checksums were taken from the four
published platform checksum files.

## Validation and merge blocker

`cargo check --workspace --all-targets --all-features --locked --offline`,
`cargo fmt --all --check`, the local CI runner unit tests, and `git diff --check`
pass. The focused Rust tests and GitHub CI must also pass.

`cargo vet --locked --cache-dir /tmp/cargo-vet-cache-618` currently fails on 57
new crate versions. SeaORM 2 brings SQLx 0.9 and a large Arrow dependency tree;
the telemetry and crypto upgrades add the rest. These releases need trusted
upstream audits or completed crate reviews under the existing `safe-to-deploy`
policy. Do not add broad exemptions to turn the gate green.

This machine has no Docker daemon, so Compose profiles, image scans, both musl
release variants, and the auditable `.dep-v0` sections require CI or a Docker
host. In particular, check database migrations and quota behavior on PostgreSQL,
SQLite, and MySQL; Alertmanager receivers and Grafana provisioning; Trivy
JSON/SARIF and exit codes; Helm install, upgrade, and rollback; and the release
SBOM on both architectures before marking this migration ready.
