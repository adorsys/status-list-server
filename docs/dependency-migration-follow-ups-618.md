# Dependency migration follow-ups for #618

The issues below are linked from [the tracker](https://github.com/adorsys/status-list-server/issues/618). Keep its major-migration criterion open until the work lands in separate reviewable PRs. The existing Artillery security issue [#547](https://github.com/adorsys/status-list-server/issues/547) remains the performance-workspace blocker.

## [#640: Migrate SeaORM and SeaORM Migration from 1.1 to 2.x](https://github.com/adorsys/status-list-server/issues/640)

Part of #618. Move `sea-orm` and `sea-orm-migration` from 1.1.20 to a matched 2.x release in one database-focused PR. Preserve the mock-enabled dev dependency and optional database feature profiles.

Acceptance: prove existing-schema upgrades, migrations, transactions, and repository behavior on PostgreSQL, MySQL, and SQLite; pass `cargo xtask check-profiles`, affected tests, and cargo deny/audit/vet; document operator-visible migration effects.

## [#641: Migrate the OpenTelemetry Rust stack together](https://github.com/adorsys/status-list-server/issues/641)

Part of #618. Move the application OpenTelemetry API, SDK, OTLP exporter, Prometheus exporter, and tracing appender from 0.32 to 0.33 alongside `tracing-opentelemetry` 0.33 to 0.34 in one telemetry-focused PR. The Google SDK's transitive versions do not replace the application's direct API.

Acceptance: prove traces and metrics reach the configured collector and Prometheus; validate dashboards and collector configuration; pass feature profiles, tests, and cargo deny/audit/vet; document emitted metric or configuration changes.

## [#642: Migrate PEM, base64, and SHA-2 Rust API versions](https://github.com/adorsys/status-list-server/issues/642)

Part of #618. Move the direct `pem` 3.0.6, `base64` 0.22.1, and `sha2` 0.10.9 dependencies to their reviewed newer lines in a crypto/encoding PR. Do not infer direct API compatibility from transitive copies.

Acceptance: preserve PEM/DER round trips, certificate loading, JWT/COSE signatures, ETags, and encoded status-list bytes; pass relevant profiles, tests, and cargo deny/audit/vet; record any compatibility effects.

## [#643: Upgrade major GitHub Actions runtime and cache wrappers](https://github.com/adorsys/status-list-server/issues/643)

Part of #618. Review `actions-rust-lang/setup-rust-toolchain` 1.17 to 2.x, `actions/cache` 5 to 6, and `actions/setup-go` 6 to 7 in a CI-focused PR. Keep full commit-SHA pins.

Acceptance: resolve tags to pinned SHAs; verify syntax, runner/runtime support, permissions, cache hit/miss behavior, and reusable workflows in CI; document contributor-visible changes.

## [#644: Migrate the local Grafana image from 12.0 to a supported release](https://github.com/adorsys/status-list-server/issues/644)

Part of #618. The Compose image is `grafana/grafana:12.0.0`; reviewed releases on 2026-10-12 include 12.4.12 on the 12.x line and 13.2.3 on the latest major. Choose a supported target after reviewing migration notes. Keep this separate from Alertmanager.

Acceptance: start the `observability` Compose profile; load committed dashboards and datasource/provisioning files; document operator-visible changes.

## [#645: Migrate the local Alertmanager image and notification config](https://github.com/adorsys/status-list-server/issues/645)

Part of #618. The Compose image is `prom/alertmanager:v0.28.1`; the reviewed newer release on 2026-10-12 is v0.34.1. Keep this migration separate from Grafana and patch-only image updates.

Acceptance: validate generated configuration with the target `amtool`; exercise webhook, chat, email, inhibition, and dead-man's-switch behavior; pass the `observability` Compose profile and existing tests; document notification behavior changes.

## [#646: Refresh Cargo.lock in cargo-vet-audited groups](https://github.com/adorsys/status-list-server/issues/646)

Part of #618. The proposed broad Cargo lockfile refresh was reverted because `cargo vet --locked` reported 121 unvetted versions after the available imported audits were refreshed. The baseline lockfile and imports pass the current gate.

Acceptance: refresh compatible groups with Cargo; obtain trusted upstream audits or complete reviews for new versions without blanket exemptions; pass `cargo vet --locked`, cargo deny/audit, and affected feature tests; update the direct-dependency audit rows as groups land.

## Other migration and validation follow-ups

- [#648: Upgrade Trivy scanner, installer, and release scan contract together](https://github.com/adorsys/status-list-server/issues/648)
- [#649: Upgrade nextest and llvm-cov with shared test contracts](https://github.com/adorsys/status-list-server/issues/649)
- [#650: Migrate the deployment toolchain to Helm 4.3](https://github.com/adorsys/status-list-server/issues/650)
- [#651: Refresh Zizmor and typos lint policy with fixtures](https://github.com/adorsys/status-list-server/issues/651)
- [#652: Validate cargo-auditable 0.7.7 in both musl release images](https://github.com/adorsys/status-list-server/issues/652)
- [#653: Migrate the local MySQL image from 9.2 to a reviewed 9.7 release](https://github.com/adorsys/status-list-server/issues/653)
