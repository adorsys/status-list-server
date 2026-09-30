# 2. Status list `sub` is a publish-time artifact, derived from `server.public_base_url`

- **Status:** Accepted
- **Date:** 2026-09-30
- **Issue:** Referenced-token `sub`/URI compliance (spec §5.1, §5.2, §8.3)

## Context

The spec requires the token's `sub` to equal the URI the issuer embedded in the
Referenced Token. Today `sub` is rebuilt at publish time from a hardcoded
`https://{server.domain}/api/v1/status-lists/{list_id}` and frozen into the
stored row; the publish endpoint returns a bare `201` with no `Location` or
body, so issuers never see the URI they are supposed to embed; and
`server.domain` defaults to `localhost` and is never validated, so a
misconfiguration silently signs `sub = https://localhost/...`, which relying
parties then reject.

The fix introduces a `server.public_base_url` option that is the single source
of truth for the URI prefix signed into `sub`, returns that URI to issuers on
publish, and validates both `server.domain` and `server.public_base_url` at
startup.

## Decision

**`server.public_base_url` is the source of truth for the `sub` prefix.** It
defaults to `https://{server.domain}/api/v1` so existing deployments that only
configure `server.domain` keep working. It must be an absolute `https` URL with
no query or fragment. `server.domain` is validated as a bare host (no scheme,
port, path, userinfo, query, or fragment).

**`sub` remains a publish-time artifact: the value stored at publish time is
what is served forever.** When `public_base_url` changes, existing rows keep
their stored `sub` (which then goes stale), and only newly published lists use
the new prefix.

### Why keep the stored `sub` rather than re-derive it at serve time

The aggregation endpoint (`GET /api/v1/aggregation`) returns each list's `sub`
URI by reading the **stored** value. If the serve path re-derived `sub` from the
current `public_base_url`, the signed claim of every already-issued token would
diverge from what aggregation reports — two sources of truth for the same
identifier, guaranteed to disagree after a base-URL change. It would also
silently rewrite the signed `sub` of tokens relying parties have already fetched
and cached. Keeping the publish-time value gives exactly one source of truth
(the stored row) shared by both aggregation and token issuance, at the cost of
stale `sub`s for pre-change rows.

The stale-`sub` cost is bounded and operator-controlled: `public_base_url` is
expected to change only when the public host actually moves, and issuers embed
the URI returned at publish time, so lists published under the old prefix are
correctly resolved by the URI the issuer already holds. An operator migrating
hosts is responsible for republishing or otherwise reconciling pre-change rows.

## Consequences

- Issuers receive the exact URI to embed via the `Location` header and the
  `{"uri", "list_id"}` body of a `201` publish, so full spec compliance now
  depends on issuers embedding the returned URI (documented in the README and
  `docs/openapi.yaml`).
- A misconfigured `server.domain` or `server.public_base_url` fails at startup
  rather than silently signing unusable tokens.
- The token-generation and publish paths both derive `sub` from
  `AppState.public_base_url`, so the served token's `sub` is byte-for-byte the
  URI handed to the issuer (covered by the round-trip test
  `test_published_token_sub_matches_publish_location`).
