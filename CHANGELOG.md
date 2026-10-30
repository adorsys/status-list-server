# Changelog

All notable changes to this project will be documented in this file.
<!-- markdownlint-disable line-length no-bare-urls ul-style emphasis-style -->

## [Unreleased]

### Upgrade notes

- Fixed-size status-list metadata is stored inside the status-list document. Do not run this release side by side with older pods: an older pod that updates a fixed-size list can write the document back without `size` and `default_status`, turning that list into a caller-managed list. Complete the rollout before sending fixed-size publish or allocation traffic.
- `limits.max_lists_per_issuer` is new and enforced. Fresh installs enforce it from the first start. When upgrading an existing SQL database, pods refuse to start until it is enabled: deploy with `APP_LIMITS__LIST_QUOTA_TRANSITION=true`, then, once no pod of the previous release is left, run `status-list-server list-quota recount` and `status-list-server list-quota enable`, and remove the setting. See `docs/troubleshooting.md`, "Upgrading to the list quota".
- Issuers have a `tier` (`standard` or `sandbox`) from the issuer registry, with per-tier limits under `APP_TIERS__*`. Pods refuse to start when a tier value exceeds its `APP_LIMITS__*` cap or a `sandbox` value is looser than `standard`. See `docs/architecture.md`, "Issuer tiers".
- `APP_RATE_LIMIT__STRICT_*` no longer limits verified management requests: it now counts rejected authentications (`401`) per client IP, and an address that spends it gets `429` for every request until a token is replenished. Verified issuers are limited by their tier instead (`APP_TIERS__<TIER>__WRITE_BURST_SIZE` / `..._WRITE_PERIOD_SECS`, default burst 100 and one token per second for `standard`), on every authenticated route including `GET /api/v1/credentials`. Deployments that raised `STRICT_BURST_SIZE` for write throughput should set the tier values instead.
- The strict gate now keys on the TCP peer address and ignores `X-Forwarded-For`, `X-Real-Ip` and `Forwarded`, which any client could set. Behind an ingress or load balancer, set `APP_RATE_LIMIT__TRUSTED_PROXIES` to its addresses or CIDRs, so the gate keys on the rightmost `X-Forwarded-For` entry that is not a trusted proxy; without it, every client behind the ingress shares one strict budget.
- The admin listener serves `GET /admin/v1/issuers` and `GET /admin/v1/issuers/{issuer_id}` (`docs/openapi-admin.yaml`), reporting each registry issuer's tier, keys and quota usage. They accept only `statuslist-admin+jwt` tokens signed with a key listed under `admins`, and require the `issuers:read` scope. New settings: `APP_ADMIN_AUTH__AUDIENCES` and `APP_ADMIN_AUTH__MAX_TOKEN_LIFETIME_SECS` (default 300). In production, the admin API rejects every token until `APP_ADMIN_AUTH__AUDIENCES` is set.
- Pods refuse to start, and reloads are refused, when an issuer holds more registry keys whose `not_after` has not passed than its tier's `max_keys` (default 5 for `standard`, 2 for `sandbox`). Check existing registries before upgrading.
- `PATCH .../statuses` may now update an index above `max_status_index` when the list already holds it. When an index is above the bound, a missing or foreign list is reported (`404`/`403`) before `400 index_too_large`.
- Every `429` carries the JSON error body with `"error": "too_many_requests"` and a `Retry-After` header.
- `tiers.*.max_lifetime_days` is validated but not applied: the registry records no issuer creation time.

### Changed

- Bump the Helm chart to `0.5.0` for render-time validation changes.
- Helm MySQL deployments are external-only and now require `statuslist.env.APP_DATABASE__HOST` plus an explicit `statuslist.image.tag` or `statuslist.image.digest`; when NetworkPolicy is enabled they also require `statuslist.networkPolicy.databaseEgress`.
- The Helm chart intentionally accepts only `postgres` and `mysql` backends. Use non-Helm local/custom deployment paths for `sqlite` or `memory`.
- `mysql.enabled=true` remains unsupported, while `mysql.enabled=false` is accepted for overlays that explicitly disable unused components.

## [1.0.0] - 2026-08-20

### Miscellaneous Tasks

- [f4ea335](
https://github.com/adorsys/status-list-server/commit/f4ea335c21bc5b85aa9f39b2cc4ebc74c096471b) *(uncategorized)* Initialize project baseline for release automation by @Hermann-Core


