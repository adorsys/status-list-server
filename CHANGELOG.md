# Changelog

All notable changes to this project will be documented in this file.
<!-- markdownlint-disable line-length no-bare-urls ul-style emphasis-style -->

## [Unreleased]

### Fixed

- `PATCH /status-lists/{list_id}/statuses` no longer writes when the payload
  leaves the list unchanged: an empty `statuses` array and a payload that
  re-sets every affected index to its current value are now successful no-ops
  that neither advance the list version nor insert a redundant history
  snapshot. A payload containing duplicate `index` values is rejected with
  `400 duplicate_index` on both `PUT` and `PATCH`.

### Changed

- Bump the Helm chart to `0.5.0` for render-time validation changes.
- Helm MySQL deployments are external-only and now require `statuslist.env.APP_DATABASE__HOST` plus an explicit `statuslist.image.tag` or `statuslist.image.digest`; when NetworkPolicy is enabled they also require `statuslist.networkPolicy.databaseEgress`.
- The Helm chart intentionally accepts only `postgres` and `mysql` backends. Use non-Helm local/custom deployment paths for `sqlite` or `memory`.
- `mysql.enabled=true` remains unsupported, while `mysql.enabled=false` is accepted for overlays that explicitly disable unused components.

## [1.0.0] - 2026-08-20

### Miscellaneous Tasks

- [f4ea335](
https://github.com/adorsys/status-list-server/commit/f4ea335c21bc5b85aa9f39b2cc4ebc74c096471b) *(uncategorized)* Initialize project baseline for release automation by @Hermann-Core


