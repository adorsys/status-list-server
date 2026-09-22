# Changelog

All notable changes to this project will be documented in this file.
<!-- markdownlint-disable line-length no-bare-urls ul-style emphasis-style -->

## [Unreleased]

### Added

- Reject `PATCH /status-lists/{list_id}/statuses` requests whose `statuses`
  array is empty with `400 empty_status_update`, and reject any payload (PUT or
  PATCH) containing duplicate `index` values with `400 duplicate_index`.

### Changed

- **Breaking:** an empty PATCH (`{"statuses": []}`) is now rejected with `400`
  instead of being silently applied as a redundant no-op write, so it no longer
  advances the list version or inserts a duplicate history snapshot.
- Bump the Helm chart to `0.5.0` for render-time validation changes.
- Helm MySQL deployments are external-only and now require `statuslist.env.APP_DATABASE__HOST` plus an explicit `statuslist.image.tag` or `statuslist.image.digest`; when NetworkPolicy is enabled they also require `statuslist.networkPolicy.databaseEgress`.
- The Helm chart intentionally accepts only `postgres` and `mysql` backends. Use non-Helm local/custom deployment paths for `sqlite` or `memory`.
- `mysql.enabled=true` remains unsupported, while `mysql.enabled=false` is accepted for overlays that explicitly disable unused components.

## [1.0.0] - 2026-08-20

### Miscellaneous Tasks

- [f4ea335](
https://github.com/adorsys/status-list-server/commit/f4ea335c21bc5b85aa9f39b2cc4ebc74c096471b) *(uncategorized)* Initialize project baseline for release automation by @Hermann-Core


