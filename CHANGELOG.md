# Changelog

All notable changes to this project will be documented in this file.
<!-- markdownlint-disable line-length no-bare-urls ul-style emphasis-style -->

## [Unreleased]

### Changed

- Bump the Helm chart to `0.5.0` for render-time validation changes.
- Increase the built-in status-list cache capacity default from 100 to 1000 entries; deployments can override with `APP_CACHE__MAX_CAPACITY`.
- Add runtime-selectable status-list cache backends (`memory` and Redis). Cache hit, miss, and Redis error metrics now include a `backend` label; use `memory`, `redis`, or `disabled` when updating dashboards and alerts.
- Redis-backed deployments support TLS, a private CA file, configurable key prefixes and timeouts. Configure Redis with `maxmemory-policy noeviction` and a dedicated ACL user restricted to the configured cache prefix and documented cache commands.
- Helm deployments can source Redis credentials through `statuslist.secretEnv`, including `APP_CACHE__PASSWORD`, rather than placing them in values files.
- Helm MySQL deployments are external-only and now require `statuslist.env.APP_DATABASE__HOST` plus an explicit `statuslist.image.tag` or `statuslist.image.digest`; when NetworkPolicy is enabled they also require `statuslist.networkPolicy.databaseEgress`.
- The Helm chart intentionally accepts only `postgres` and `mysql` backends. Use non-Helm local/custom deployment paths for `sqlite` or `memory`.
- `mysql.enabled=true` remains unsupported, while `mysql.enabled=false` is accepted for overlays that explicitly disable unused components.

## [1.0.0] - 2026-08-20

### Miscellaneous Tasks

- [f4ea335](
https://github.com/adorsys/status-list-server/commit/f4ea335c21bc5b85aa9f39b2cc4ebc74c096471b) *(uncategorized)* Initialize project baseline for release automation by @Hermann-Core

