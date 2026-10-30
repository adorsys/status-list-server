# Changelog

All notable changes to this project will be documented in this file.
<!-- markdownlint-disable line-length no-bare-urls ul-style emphasis-style -->

## [2.0.0] - 2026-10-30

### Features

- [e56e1ce](
https://github.com/adorsys/status-list-server/commit/e56e1ce12e315f0fe3f443b362687e46606e1548) *(aggregation)* Scope status list aggregation to one issuer by @martcpp in [#595](
https://github.com/adorsys/status-list-server/pull/595) [**breaking**]

  > * fix(aggregation): reject NUL in aggregation cursors
  >
  > decode_cursor accepted any non-empty payload after the v1 prefix, so a
  > cursor decoding to a list_id containing NUL reached the database.
  > Postgres rejects NUL in text, which surfaced as a 500 on a public
  > endpoint. Such a cursor is now a 400 invalid_query like any other bad
  > cursor.
  >
  > Only NUL is rejected. Other control characters stay accepted so walks
  > over legacy non-UUID list_ids keep working on MySQL and SQLite.
  >
  > * fix(status-list): reject NUL in list_id on GET
  >
  > GET /api/v1/status-lists/{list_id} passed the path segment straight to
  > storage. A list_id containing NUL (%00) reached Postgres, which rejects
  > NUL in text, and the request failed with a 500 on the endpoint relying
  > parties use to check revocation. It now returns 400 invalid_list_id,
  > for both live and historical (?time=) requests.
  >
  > The check is NUL only, not the UUID check publish and update use:
  > lists created before list_id validation have non-UUID IDs, and issued
  > credentials still point at them.
  >
  > The OpenAPI spec now documents the 400 response for this endpoint,
  > which it already returned for invalid time and query values.
  >
  > * test(metrics): stop asserting a gauge value other tests overwrite
  >
  > list_quota_enforced_is_exported recorded 0 and expected to read 0 back,
  > but every SQL publish records the same global gauge, and the SQL tests
  > run in parallel with it. A test that publishes under an enforced quota
  > turns the reading into 1. Assert only that the gauge is exported.
  >
  > * feat(aggregation)!: give each issuer an opaque aggregation ID
  >
  > Scoping aggregation to one issuer needs a public name for that issuer.
  > The issuer identifier cannot be it: Status List Tokens never disclosed
  > it, and it is often an internal tenant name. Each credential now gets a
  > random AggregationId at registration, which publish_credential returns
  > and CredentialRepo resolves in both directions.
  >
  > Service::list_issuer_uris lists the status lists of the issuer an ID
  > belongs to, and is None for an ID no issuer has. Service::find_aggregation_id
  > keeps the IDs it finds in memory: every signed token will need one, and
  > a query per token would tie status list reads served from cache to the
  > database. Misses are not kept, so an ID assigned later is picked up.
  >
  > Schema:- credentials.aggregation_id, nullable, with a unique index. Pods on the
  >   previous release keep registering without one during a rolling
  >   deploy. Such a row gets an ID on its first lookup, through an UPDATE
  >   guarded by aggregation_id IS NULL, so pods racing there agree on one.
  > - status_lists (issuer, list_id) index, so a scoped page is a range scan
  >   rather than a read and sort of all the issuer's lists. On Postgres the
  >   index build blocks writes to status_lists while it runs.
  >
  > Each migration step is guarded with has_column/has_index so a failed
  > MySQL run can be re-run, and down avoids IF EXISTS, which sea-query
  > cannot render for MySQL.
  >
  > BREAKING CHANGE:CredentialRepo::insert takes the aggregation ID, and
  > CredentialRepo gains find_aggregation_id and
  > find_issuer_by_aggregation_id. StatusListRepo::list_uris takes an
  > optional issuer. Service::publish_credential returns the AggregationId.
  >
  > * feat(aggregation)!: scope aggregation to one issuer
  >
  > GET /api/v1/aggregation/{aggregation_id} lists only that issuer's status
  > lists, and status list tokens advertise that URI in aggregation_uri. The
  > ID is a path segment rather than a query parameter: a cache that ignores
  > query strings still keeps issuers apart, and the relative Link to the
  > next page keeps the issuer without repeating it, so cursors need no
  > binding to their scope and keep the v1 format.
  >
  > limits.max_lists_per_issuer may no longer exceed AGGREGATION_DEFAULT_LIMIT,
  > the page a draft-21 §9.3 client gets without sending a limit. While the
  > list quota is enforced, every issuer's aggregation therefore fits in one
  > response and next_cursor is null. Paging remains for issuers that
  > already hold more lists, and for any issuer while the quota runs in
  > transition.
  >
  > - An unknown aggregation ID is a 404, so a relying party whose URI went
  >   stale finds out instead of caching an empty aggregation.
  > - Pages carry a weak ETag and answer a matching If-None-Match with 304.
  > - GET /api/v1/credentials tells an authenticated issuer its aggregation
  >   ID and URI, which issuers registered before this change never got.
  > - The status list handler resolves aggregation_uri before signing and
  >   keys the ETag on it, so a token that gains the claim is not
  >   revalidated as unchanged. A failed lookup signs the token without the
  >   OPTIONAL claim rather than failing a revocation check.
  >   aggregation_uri_omitted counts those, and aggregation_pages counts
  >   pages by scope and outcome, truncated included.
  > - server.aggregation_uri is checked when the config loads, before any
  >   migration runs, and must have no query or fragment.
  > - GET /api/v1/aggregation keeps listing every issuer's lists, deprecated,
  >   for tokens issued before this change.
  >
  > BREAKING CHANGE:pods refuse to start when limits.max_lists_per_issuer
  > exceeds 1000, and an issuer already above it cannot publish another list
  > until it is back under. Tokens carry <aggregation_uri>/<aggregation_id>
  > instead of the server-wide URI. The POST /api/v1/credentials response
  > gains aggregation_id and aggregation_uri. AppState::aggregation_uri is
  > now a Url, and build_status_list_token takes the aggregation_uri to
  > sign.
  >
  > * docs(aggregation): document issuer-scoped aggregation
  >
  > Architecture, the deployment runbook and troubleshooting now cover the
  > scoped endpoint and its upgrade:
  >
  > - The 1000-list ceiling on max_lists_per_issuer, and that a complete
  >   page holds only while the list quota is enforced.
  > - Finding issuers at or near 1000 lists before upgrading, since those
  >   above it can no longer publish.
  > - Building the Postgres index concurrently beforehand, which the
  >   migration then skips.
  > - Old pods answering 404 for scoped URIs until the rollout completes.
  > - Rolling back: the previous release refuses to start while the database
  >   records migrations it does not know, so their two records are deleted
  >   first. The down migration would destroy published aggregation IDs.
  > - The metrics to watch, when the unscoped form can be removed, and what
  >   a scoped aggregation discloses on a server shared by several issuers.
  >
  > The config templates state the ceiling, and the load test runs with
  > aggregation_uri set so it measures the lookup that comes with it.
  >
  > * docs(compliance): mark aggregation_uri compliant
  >
  > Row 6 still said aggregation_uri was not implemented. Tokens now carry
  > an issuer-scoped aggregation_uri and GET /api/v1/aggregation/{id}
  > returns that issuer's draft-21 §9.3 status_lists, complete in one
  > response while the list quota is enforced, so the row is Compliant, with
  > the tests that pin it.
  >
  > * refactor(aggregation): cache aggregation IDs in an outbound adapter
  >
  > The domain layer may not depend on infrastructure crates, and CI's purity
  > check rejected the moka cache in Service. The cache now wraps
  > CredentialRepo as CachingCredentialRepo, wired in setup, and
  >
  > Service::find_aggregation_id calls the port directly again. Found IDs are
  > still kept, misses still are not.
  >
  > * perf(aggregation): cache the aggregation ID to issuer lookup
  >
  > Every scoped aggregation page resolved its ID to an issuer before the page
  > scan, so each request cost two queries. CachingCredentialRepo now keeps the
  > ID to issuer mappings it finds as well, with the same capacity and TTL as
  > the other direction, since an ID never changes. Misses are not kept, so
  > random IDs sent to the public endpoint can't fill the cache.
  >
  > * docs(compliance): note next_cursor is an extension member
  >
  > The §9.3 aggregation structure defines only status_lists. Row 6 now says
  > next_cursor is an extension member, which relying parties that know only
  > §9.3 ignore.
  >
  > * fix(config): name AGGREGATION_DEFAULT_LIMIT in the quota ceiling error
  >
  > The issue asks for the startup error to name both bounds. It now names the
  > setting and AGGREGATION_DEFAULT_LIMIT with their values. The check compares
  > against the default page size rather than AGGREGATION_MAX_LIMIT because a
  > draft-21 §9.3 client never sends a limit, so the default page is the one
  > that must hold an issuer's whole aggregation.
  >
  > * fix(aggregation): close revalidation, quota transition and URI validation gaps
  >
  > - If-Modified-Since no longer certifies a 304 when aggregation_uri is
  >   configured. Last-Modified tracks the list only, so a token that gained
  >   or lost the claim could be revalidated as unchanged; only the ETag,
  >   which covers it, may now do that.
  > - Tokens carry no aggregation_uri while the list quota runs in
  >   transition. Publishes past the cap are accepted then, so an issuer can
  >   outgrow one page that a draft-21 §9.3 client takes as complete.
  > - server.aggregation_uri must be http(s) without credentials, and https
  >   in production, since relying parties fetch it from signed tokens.
  > - The 200 helper derives Last-Modified and Cache-Control itself, so it no
  >   longer takes eight arguments that callers could mismatch.
  >
  > The runbook no longer says every publish past the cap is refused while
  > the quota is in transition.
  >
  > * fix(aggregation): withhold aggregation_uri while an issuer exceeds one page
  >
  > The list quota bounds new lists only, so an issuer can still hold more
  > than one aggregation page from under an earlier, higher cap. An enforced
  > quota now also counts each issuer's lists at startup; while any has more
  > than one page, tokens carry no aggregation_uri and the pod names the
  > issuers.
  >
  > Test quota transition and that case through build_state on SQLite, cover
  > removing the claim and If-Modified-Since in the revalidation test, and add
  > the aggregation error codes to the OpenAPI error enum.
  >
  > * fix(aggregation): never answer an issuer's aggregation in part
  >
  > Pods decide at startup whether tokens advertise aggregation_uri, so after
  > a live `list-quota disable` an issuer can outgrow one page while served
  > tokens still point at it. A scoped request with neither limit nor cursor
  > that does not fit now gets 409 paging_required instead of the first page;
  > sending limit opts in to paging.
  >
  > Cursors now name their aggregation, or `all`, so one replayed on another
  > aggregation is refused instead of skipping lists. The list quota counts
  > each issuer's lists in one GROUP BY pass.
  >
  > * fix(aggregation): count refused aggregation requests as refused
  >
  > A 409 paging_required was counted as a truncated page served and logged
  > as one. It now has its own outcome, recorded before anything is logged as
  > served, and the metrics test asserts the series the runbook alerts on.
  >
  > The runbook now says that one issuer over one page turns aggregation_uri
  > off for every issuer's tokens until the pods restart, and the architecture
  > notes keep only the invariants changes must preserve.

- [d7cf262](
https://github.com/adorsys/status-list-server/commit/d7cf2625ab035b67354bfa90e39dbd7bb689c1eb) *(cache)* Implement Redis cache support and update configuration options by @Ngha-Boris in [#554](
https://github.com/adorsys/status-list-server/pull/554)

  > * feat(cache): implement Redis cache support and update configuration options
  >
  > * refactor(cache): update cache feature handling and documentation
  >
  > * feat(config): add new exemptions for backon, redis, and sha1_smol
  >
  > * feat(cache): enhance Redis cache implementation with max capacity and eviction logic
  >
  > * feat: add Redis cache backend support and enhance caching mechanisms
  >
  > * feat: add fscert-redis variant to deployment and scheduled image scan workflows
  >
  > * feat(cache): enhance Redis cache support with invalidation markers and network policy configuration
  >
  > * feat(network-policy): enforce cache egress requirement for Redis image variant and improve cache port validation
  >
  > * test: update cache port validation test to ignore output variable
  >
  > * feat(cache): introduce Redis cache backend and configuration options
  >
  > * feat(setup): include cache-redis feature in secrecy::ExposeSecret usage
  >
  > * feat(cache): implement Redis cache support with enhanced validation and network policy integration
  >
  > * fix(tests): simplify rendered_chart_default_env_loads_application_config test logic
  >
  > * feat(cache): add timeout handling for Redis connection and improve error reporting
  >
  > * refactor(cache): rename cache-redis feature to redis and update related configurations
  >
  > * refactor(redis): improve Redis cache initialization and error handling
  >
  > * fix: update Redis cache feature references in configuration files
  >
  > * feat(cache): enhance Redis cache configuration and error handling
  >
  > * chore: remove unnecessary blank line in README.md
  >
  > * feat(cache): implement Redis cache backend with runtime selection and enhanced configuration
  >
  > * feat(cache): increase default cache capacity and add runtime-selectable backends
  >
  > * feat(cache): remove REDIS_MARKER_TTL_SECS constant and update cache invalidation logic
  >
  > * feat(cache): update exemptions and versions in config.toml
  >
  > * build: vet merged crypto dependencies
  >
  > * feat(tests): update signing_material to use generated SigningKey
  >
  > * build: remove unused p256 dependency
  >
  > * refactor: remove unnecessary comment from cache.rs
  >
  > * fix(cache): keep Redis invalidation fence monotonic
  >
  > * test(cache): supply list quota to Redis fixtures
  >
  > * fix(cache): bound Redis failures and document fencing
  >
  > * docs: clarify Redis cache support
  >
  > * docs: remove cache backend ADR
  >
  > * docs: update Redis cache backend description in README
  >
  > * ci: remove Redis-specific cache guard

- [21c67e2](
https://github.com/adorsys/status-list-server/commit/21c67e24b96cb65f8df0db5225234c24653e5cca) *(compose)* Split optional services into profiles by @Hermann-Core in [#597](
https://github.com/adorsys/status-list-server/pull/597)

  > * feat(compose): profile optional local services
  >
  > * docs(compose): document modular startup profiles
  >
  > * fix(compose): align local runtime defaults
  >
  > * docs(compose): clarify profile requirements
  >
  > * ci(compose): smoke-test default startup
  >
  > * fix(compose): align profile runtime defaults
  >
  > * docs(compose): normalize profile guidance formatting

- [f991468](
https://github.com/adorsys/status-list-server/commit/f9914685f55430a2dfff15138a879a35b6dc828a) *(crypto)* Support multi-curve keys with PEM-only provisioning by @Hermann-Core in [#559](
https://github.com/adorsys/status-list-server/pull/559) [**breaking**]

  > * feat(deps): migrate to aws-lc-rs and bump jsonwebtoken to 11.1
  >
  > * feat(crypto): implement multi-algorithm signing key and TokenSigner
  >
  > * refactor(domain): update SigningMaterial to use SigningKey and support From for Issuer
  >
  > * refactor(outbound): adapt certificate and memory adapters to SigningKey
  >
  > * refactor(cert_manager): integrate SigningKey and update strategy normalization
  >
  > * feat(token): support dynamic JWT and CWT signing via TokenSigner
  >
  > * docs: update private key documentation and test utilities to generic PEM format
  >
  > * refactor(crypto): group encoding key and rng into SigningKeyInner
  >
  > * refactor(crypto): rename inner variable to pair for clarity in SigningKey::from_pkcs8
  >
  > * fix(crypto): decouple token signing boundary
  >
  > * feat(domain): add token model with SigningAlgorithm
  >
  > * fix(domain): re-export token signing contracts
  >
  > * fix(crypto): harden signing-key validation tests
  >
  > * refactor(token): consolidate signer metadata
  >
  > * fix(cert): enforce PEM-only store material
  >
  > * fix(cert): clarify PEM-only input errors
  >
  > * fix(crypto): accept standard PEM key bundles
  >
  > * docs: stabilize troubleshooting guidance
  >
  > * fix(test): stabilize revalidation metrics test

- [46b4804](
https://github.com/adorsys/status-list-server/commit/46b480426560059b7a774eb869d3f4e415435b55) *(uncategorized)* Troubleshoot and fix docker compose configuration conflict when both env and envtemplate exist. by @Blindspot22 in [#609](
https://github.com/adorsys/status-list-server/pull/609)

  > * fix(compose): remove template from env_file and add db defaults
  >
  > * fix(compose): format env template syntax
  >
  > * ci(compose): update compose validation comment
  >
  > * docs(compose): update local deployment env docs
  >
  > * fix(compose): resolve merge conflict marker in env template
  >
  > Remove merge conflict markers left in .env.template around AWS_ENDPOINT_URL
  > and configure the Floci endpoint cleanly.
  >
  > * fix(compose): default container listener host to 0.0.0.0
  >
  > Add an explicit, overridable APP_SERVER__HOST default of 0.0.0.0 to
  > docker-compose.yml so Docker port forwarding functions when no .env
  > file is present or when .env omits APP_SERVER__HOST. Published host
  > interface remains controlled by BIND_ADDR.
  >
  > Add startup smoke tests covering both missing and partial .env, and
  > add CI validation and a unit test to verify container host binding.
  >
  > * fix(compose): clear database split defaults to support URL-only configuration
  >
  > Default APP_DATABASE__HOST, PORT, USERNAME, PASSWORD, and NAME to
  > empty strings in docker-compose.yml rather than hardcoded postgres
  > fallbacks. This prevents Docker Compose from injecting conflicting split
  > connection fields when a backend URL (APP_DATABASE__URL) is configured.
  >
  > Update CI validation to assert no unconditional split database fields
  > are injected, add a URL-only configuration check and smoke test, and
  > pass APP_DATABASE__HOST=db explicitly for PostgreSQL testing.
  >
  > * fix(compose): remove split DB defaults
  >
  > * test(compose): cover listener and URL defaults
  >
  > * ci(compose): build matching smoke features
  >
  > * ci(compose): trim redundant checks
  >
  > * docs(compose): document database env
  >
  > * chore(env): normalize comments
  >
  > * fix(deps): upgrade quinn-proto
  >
  > * chore(supply-chain): vet quinn-proto
  >
  > * fix(compose): address review feedback
  >
  > * fix(compose): align postgres settings
  >
  > * docs(compose): clarify overrides

- [5b196bd](
https://github.com/adorsys/status-list-server/commit/5b196bde230500f06b6b4196d9e6cb13b6e07e0b) *(uncategorized)* Add postman assets and Microcks contract testing support by @Ngha-Boris in [#561](
https://github.com/adorsys/status-list-server/pull/561)

  > * feat: add postman assets and Microcks contract testing support
  >
  > * fix(docs): format environment variable tables for better readability
  >
  > * fix(docs): adjust formatting of environment variable tables for clarity
  >
  > * feat(ci): add Postman collection testing workflow and update documentation
  >
  > * feat: add package.json and update test script for Newman integration
  >
  > * fix(postman): improve test for metrics response content type
  >
  > * fix: update pinned Microcks CLI image to latest version
  >
  > * fix(docs): correct formatting of MICROCKS_IMAGE entry in API testing documentation
  >
  > * refactor: remove package.json and update Postman tests for improved clarity and structure
  >
  > * fix: update pinned Microcks CLI image to latest version
  >
  > * fix: set APP_SERVER__HOST to 0.0.0.0 in API configuration for local testing
  >
  > * feat: add Microcks OpenAPI conformance job to GitHub Actions workflow and update verbosity settings
  >
  > * fix: correct formatting in API testing documentation for Microcks_VERBOSE variable
  >
  > * feat: enhance Postman collection and API contract tests with historical status list support and metrics configuration
  >
  > * feat: add detailed Microcks test result logging and error handling in conformance script
  >
  > * fix: remove incorrect Accept header for status list API endpoint
  >
  > * feat: add allocation list ID handling and update API request/response examples in Microcks conformance script
  >
  > * feat: enhance publish response validation and update allocation list handling in conformance script
  >
  > * fix: remove microcks conformance testing
  >
  > * feat(tests): add JWT payload validation tests for status values
  >
  > * feat(tests): enhance response validation and add CWT decoding tests
  >
  > * feat(tests): add Postman badge and enhance CWT decoding tests with error handling
  >
  > * fix: update Postman collection link in README
  >
  > * fix: correct byte handling in CWT decoder functions
  >
  > * test: enhance CWT decoder tests with valid input scenarios

- [5db173e](
https://github.com/adorsys/status-list-server/commit/5db173e1df6a57cd1b1f2bcd85a4d66dd5f65e49) *(uncategorized)* Adopt cargo xtask workflow by @Hermann-Core in [#608](
https://github.com/adorsys/status-list-server/pull/608)

  > * feat(xtask): add profile-aware workflow commands
  >
  > * chore: add clap and dependency exemptions to supply-chain config
  >
  > * docs: remove status list publishing section from README
  >
  > * fix(xtask): use sh instead of bash in CI command spec test
  >
  > * style(xtask): fix formatting
  >
  > * chore(xtask): migrate from anyhow to color-eyre for error reporting
  >
  > * chore(supply-chain): add tempfile audits and remove exemption
  >
  > * test(sql): isolate contention probes by status list
  >
  > * fix(xtask): address backend profiles and workflow review
  >
  > * fix(xtask): align test runner and continuous profile validation
  >
  > * fix(tests): align SQL fixtures with backend feature gates
  >
  > * fix(xtask): use bash and keep profile matrix in full CI
  >
  > * refactor(tests): group database-backed SQL helpers
  >
  > * fix(tests): reconcile pagination helpers after develop merge

- [a6a49e2](
https://github.com/adorsys/status-list-server/commit/a6a49e223644df7a179bdffd7ff09ec16218949a) *(uncategorized)* Replace LocalStack with Floci for AWS emulation and update related configurations by @Ngha-Boris in [#607](
https://github.com/adorsys/status-list-server/pull/607)

  > * feat: replace LocalStack with Floci for AWS emulation and update related configurations
  >
  > * fix: address Floci migration review feedback
  >
  > * docs: remove duplicate Floci setup section

- [3e9bf7b](
https://github.com/adorsys/status-list-server/commit/3e9bf7b56b188bf23ed5afd2a309c27beff3a760) *(uncategorized)* Cache signed status-list tokens per validity window and use weak identity-derived ETags by @ndefokou in [#572](
https://github.com/adorsys/status-list-server/pull/572)

  > * fix(ci): fix pipeline
  >
  > * fix: invalidate cached status-list tokens on key rotation and config change
  >
  > Address review findings on the per-window signed-bytes cache :
  >
  > - Self-invalidate the signed-token bytes cache on signing-key rotation and
  >   certificate renewal by folding a signer fingerprint (SHA-256 of the key PEM
  >   and certificate chain) into the cache key. A rotated key or renewed cert
  >   immediately misses and re-signs, so the server never serves or ETag-certifies
  >   stale bytes signed with a superseded key. The signing material is fetched once
  >   and passed to the signer so an entry can never be written under a mismatched
  >   fingerprint.
  > - Fold aggregation_uri and token_ttl_secs into the cache key too, since both are
  >   embedded in the signed token bytes; a config change to either now invalidates
  >   the cache.
  > - Document historical (?time=) tokens as explicitly out of the signed-bytes
  >   cache scope (acceptance criterion #7).
  > - Tests: key rotation and certificate renewal each force a fresh sign and ETag
  >   ; a bounded property sweep asserts a 304 is never certified
  >   past the client's cached token exp ; the cache key dimensions
  >   and signer fingerprint are unit-tested.
  >
  > * fix: single-flight concurrent token re-signs and harden signed-token cache
  >
  > Address review findings on the per-window signed-bytes cache:
  >
  > - Deduplicate concurrent misses through a per-key in-flight lock so at most
  >   one signing operation runs per (list, window, format) per replica. Without
  >   it, every concurrent revalidation at a window rollover re-signed, and the
  >   randomized ECDSA signature produced divergent ETags within the same window,
  >   leaving some clients re-signing on every revalidation.
  > - Fold token_exp_secs into the cache key alongside token_ttl_secs, since both
  >   are embedded in the signed token bytes.
  > - Decouple the token cache from cache.ttl via a dedicated token_bytes_cache
  >   config (default TTL >= window so entries are not evicted mid-window) and
  >   make TTL=0 disable it consistently with the status-list record cache.
  > - Quote the historical ETag as a valid RFC 7232 strong validator.
  > - Tests: concurrent misses run the builder exactly once; concurrent GETs at a
  >   fresh window share a single ETag/body; token_bytes_cache config defaults and
  >   overrides.
  >
  > * style: format workspace with cargo fmt
  >
  > * fix: align table column in compliance matrix for markdownlint
  >
  > * fix(ci): fix pipeline
  >
  > * fix(ci): fix pipeline
  >
  > * fix: add missing max_lists_per_issuer to test AppState literal
  >
  > * docs: remove broken intra-doc link to test-only get method
  >
  > * test(cert_provisioning): retry Docker image pulls to avoid flaky registry failures
  >
  > The cert provisioning integration tests pull several Docker images (Pebble,
  > challtestsrv, LocalStack, Vault, OpenBao) at container start. A transient
  > registry/network failure such as a truncated download (e.g. 'bytes remaining
  > on stream' while pulling localstack/localstack:4.14) previously aborted the
  > whole test run.
  >
  > Wrap every container start in a small retry helper that tolerates these
  > transient pull failures by retrying the start up to three times with a short
  > backoff before giving up.
  >
  > * feat(cache): retain single-flight locks and validate token bytes TTL
  >
  > Address review feedback on the signed status-list token bytes cache:
  >
  > - Replace the capacity-bounded Moka lock registry with a ref-counted
  >   per-key registry so a key's in-flight lock is never evicted mid-build,
  >   preserving the one-build-per-key guarantee. Add a lock-churn regression
  >   test.
  > - Reject token_bytes_cache.ttl values that fall between 0 and
  >   status_list.token_exp_secs so cached bytes never expire mid-window.
  > - Remove issue references from inline and operator-facing documentation.
  >
  > * refactor(cache): relocate token-bytes cache out of handler utils
  >
  > Address review feedback on the signed status-list token cache:
  >
  > - Move the TokenBytesCache implementation from
  >   handlers::status_list::utils into a server-level module so AppState
  >   no longer depends on a handler-owned type re-exported upward.
  > - Replace the delimiter-encoded nine-parameter cache-key function with
  >   a typed TokenCacheKey value type deriving Eq and Hash, removing the
  >   too_many_arguments clippy suppression.
  > - Store cached representations as axum::body::Bytes so a cache hit is
  >   moved straight into the response body without deep-copying the
  >   (potentially large) token.
  > - Remove implementation details (internal types, source paths, line
  >   numbers) from the compliance matrix and clean up ETag doc comments.
  >
  > * fix(docs): fix cargo doc and markdown lint failures
  >
  > - Replace the intra-doc link to the private TokenCacheKey in the public
  >   TokenBytesCache documentation with a plain code reference so cargo doc
  >   no longer warns about a private item link.
  > - Re-align the compliance matrix table columns so the markdownlint MD060
  >   aligned table-column style passes.
  >
  > * refactor(cache): coalesce token-bytes single-flight via moka try_get_with_by_ref
  >
  > Replace the manual ref-counted in-flight lock registry with moka's
  > try_get_with_by_ref coalescing, which keeps a single build per key even
  > when the data cache evicts the entry mid-build. Drop the remaining
  > inline ticket reference from the cache doc comment.
  >
  > * fix(config): name env vars in token-bytes cache TTL error and pin them in tests
  >
  > The token_bytes_cache.ttl validation refusal now names the exact env vars
  > (APP_TOKEN_BYTES_CACHE__TTL / APP_STATUS_LIST__TOKEN_EXP_SECS) an operator
  > must fix, not just the dotted config paths. The mid-window rejection test now
  > asserts both the env var and the config path appear in the error message, so
  > removing the check or dropping the env-var mention fails the test.
  >
  > * docs(compliance): clarify ttl carries no positivity guarantee in row 9
  >
  > Row 9 (iat/exp/ttl) now states that ttl is RECOMMENDED, not required, by the
  > spec, so the server makes no positivity guarantee: it accepts any u64 ttl and
  > degrades safely (window width clamped to >= 1), including degenerate
  > ttl >= exp and exp == 0 configs, where the conditional logic falls back to
  > re-signing a 200 rather than certifying a 304.
  >
  > * test(config): harden token-bytes cache TTL validation assertions
  >
  > Address review feedback:
  > - Pin the mid-window rejection error to name both the APP_STATUS_LIST__TOKEN_EXP_SECS
  >   env var and the status_list.token_exp_secs config path, not just the ttl knob.
  > - Add test_token_bytes_cache_ttl_validation_boundaries exercising TokenBytesCacheConfig::validate
  >   directly across all boundary cases (ttl==exp, ttl==0, and the rejected mid-window), so
  >   removing or loosening the check fails the tests instead of silently passing through the
  >   positive Config::load_from_overrides path.
  > - Add rendered_chart_rejects_integer_env_values to the helm suite: integer env values are
  >   rejected by the string-typed statuslist.env schema ("got number, want string") instead of
  >   being rendered by Helm in scientific notation (e.g. 2592000 -> 2.592e+06) and crashing the
  >   u64 parse.
  >
  > * fix(cache): scope token-bytes single-flight guarantee to concurrent misses
  >
  > Capacity eviction in the max_capacity-bounded data cache can evict a
  > still-valid in-window entry, so a later request in the same window re-signs
  > unchanged bytes. The honest single-flight contract covers concurrent misses
  > (coalesced by moka try_get_with_by_ref), not every request in a window.
  >
  > Narrow the struct and get_or_build docs, clarify the ttl/max_capacity config
  > semantics, and add a sequential A->(churn)->A capacity-eviction test that
  > documents the accepted re-sign behaviour.
  >
  > * style: rustfmt test fixture in token_cache
  >
  > * fix(status-list): harden token validity, weak ETags and byte-budget cache
  >
  > Address code-review findings on the signed-token cache / ETag work:
  >
  > - Anchor live-token iat to max(window_start, updated_at) so a mid-window
  >   content change never mints a token claiming to predate the change.
  > - Cap the token window at min(exp - ttl, ttl) so iat + ttl is always in the
  >   future (draft-21 s13.7 refresh strategy) and a 304's max-age=ttl never
  >   outlives the token it vouches for.
  > - Certify a 304 only while now + ttl <= exp (runway rule) on the If-None-Match
  >   path, matching If-Modified-Since.
  > - Validate status_list.token_ttl_secs < token_exp_secs at startup, refusing
  >   ttl >= exp and exp == 0 configs.
  > - Replace the strong byte-derived ETag with a weak W/"..." validator over the
  >   representation identity (list, content hash, signer, window, format,
  >   encoding), stable across replicas/restarts and never requiring a sign for a
  >   304.
  > - Re-key the signed-bytes cache by bytes (weigher + byte budget), expire each
  >   entry at the end of its own window (moka Expiry), drop the token_bytes_cache
  >   TTL config, and expose entry-count/size gauges.
  > - Add tests: same-window content change, two-replica ETag stability, cache
  >   byte-budget and window-end expiry, bounded 304-lifetime property sweep; fix
  >   tests that relied on fake pre-epoch clocks.
  > - Update compliance matrix, deployment runbook, OpenAPI, and Helm values.
  >
  > * fix: resolve rustdoc and markdownlint pipeline failures
  >
  > - Replace intra-doc links to the private EntryExpiry type with plain text
  >   in TokenBytesCache docs so public docs build without
  >   --document-private-items (-D rustdoc::private-intra-doc-links).
  > - Switch MD060 table style from aligned to consistent so the long
  >   compliance_matrix Notes column no longer fails table alignment.
  >
  > * fix: fold all TokenCacheKey dimensions into weak ETag and adopt 1 MiB token byte budget
  >
  > - Hash aggregation_uri, token_ttl_secs, and token_exp_secs into the weak
  >   ETag so a config change/restart within an unchanged window cannot serve a
  >   304 against a token with the old aggregation URI, ttl, or exp.
  > - Assert each semantic representation dimension in TokenCacheKey changes
  >   the ETag; remove the assertion that ttl/exp/aggregation_uri are identity-neutral.
  > - Migrate the built-in token_bytes_cache.max_capacity default from 100 to
  >   1048576 (1 MiB) to match the Helm values, since max_capacity is now a byte
  >   budget; a representative token is a few hundred bytes.
  > - Drop the obsolete APP_TOKEN_BYTES_CACHE__TTL from .env.template (expiry
  >   is now per entry).
  > - Add a default-config test that retains a representative signed token.
  >
  > * fix(status-list): no signing on 304, canonical weak ETag, review cleanup
  >
  > - Derive cache key + weak ETag before evaluating the conditional request so a
  >   matching If-None-Match answers 304 without ever minting a token; only build
  >   signed bytes for a Modified response.
  > - Hash a canonical (length-prefixed string, fixed-width integer) encoding of the
  >   TokenCacheKey so distinct keys can never collide across field boundaries.
  > - Consume the status record by value in build_status_list_token, removing the
  >   clone in the spawn_blocking path; cache callers clone only on a miss.
  > - Correct signer_fingerprint contract and trim cache/mod/config comments to
  >   durable contracts.
  > - Drop the unused moka 'sync' feature (only 'future' is used) and revert the
  >   MD060 markdownlint relaxation (aligned passes on all docs).
  > - Keep weak ETag and 304 behaviour at the HTTP contract level in openapi.yaml and
  >   qualify the cross-replica ETag claim in the deployment runbook.
  > - Add a cold-cache test counting signing attempts during a matching If-None-Match
  >   revalidation.
  >
  > * fix(build): resolve rustdoc private-link and markdownlint MD060 CI failures
  >
  > - Replace the intra-doc link to the private TokenCacheKey in the public
  >   TokenBytesCache docs with plain text so docs build under
  >   -D rustdoc::private-intra-doc-links.
  > - Restore the MD060 table style to 'consistent': the compliance_matrix Notes
  >   column fails the stricter 'aligned' style (markdownlint v0.41.1), so the
  >   relaxation is required for the lint pipeline.
  >
  > * fix(status-list): make historical ETag weak and include format/encoding
  >
  > The historical ETag emitted a strong validator ("...") built from the
  > snapshot only, so byte-different JWT/CWT and gzip/identity responses
  > shared it. Make it weak (W/"...") and fold format and encoding into the
  > hash, so each served representation gets a distinct validator.
  >
  > * fix(status-list): expire token-bytes cache at window end and raise byte budget
  >
  > Address review feedback on the signed-token bytes cache:
  > - Expire each entry at its anchored validity window end
  >   (window_start + min(exp - ttl, ttl)) instead of window_start + exp_secs,
  >   so a closed window's bytes are freed promptly instead of lingering for
  >   the rest of exp_secs.
  > - Raise the default byte budget from 1 MiB to 64 MiB so several
  >   maximum-permitted lists (each near 1 MiB once wrapped in JWT/base64)
  >   plus many small ones are retained; the 1 MiB budget was smaller than a
  >   max-size representation.
  > - Replace size gauges that only updated on misses with observable gauges
  >   read at scrape time, so entry count and total resident bytes stay
  >   accurate across hits, evictions, and expiries.
  >
  > * fix(status-list): key signed-token cache by iat to handle mid-window reinstatement
  >
  > A status list whose content reverts to an earlier state within one window
  > (A -> B -> A, e.g. a suspend followed by a reinstate) returns to the same
  > content hash, so the signed-token-bytes cache key and weak ETag previously
  > collided with the earlier identical-content entry and served its stale bytes
  > carrying the old iat. Those bytes claim VALID from before the suspension,
  > contradicting ?time= queries covering the suspension.
  >
  > Include the minted iat = max(window_start, updated_at) in the cache key and
  > the ETag, so a reinstated token is a distinct identity and is freshly signed
  > with an iat reflecting the reinstate time. Fix the OpenAPI iat description
  > (still said it was anchored to the window start) and add a regression test
  > covering the A -> B -> A reinstatement path.
  >
  > * fix(docs): remove double blank line in compliance matrix
  >
  > Fix markdownlint MD012/no-multiple-blanks in docs/compliance_matrix.md
  > introduced by the develop merge; collapse the two blank lines before the
  > RFC link references into one.
  >
  > * fix(status-list): decouple concurrency version from updated_at timestamp
  >
  > Address review feedback on the signed-token cache work:
  >
  > - Split the monotonic optimistic-concurrency version out of the
  >   updated_at timestamp. update_status previously advanced updated_at
  >   by max(now, previous + 1) because it doubled as the SQL concurrency
  >   guard, which let a burst of writes to one list drift updated_at -
  >   and therefore the served token's iat - ahead of the wall clock (RPs
  >   reject a future iat). A new status_lists.version column is now the
  >   guard and cache-fencing stamp, while updated_at stays a real
  >   timestamp. version joins the token cache key and weak ETag, so a
  >   mid-window A -> B -> A reinstatement is still a distinct identity
  >   without inflating iat.
  >
  > - Share the token window width via a window_width helper used by both
  >   token_window and the signed-bytes cache expiry, so the two can never
  >   drift apart.
  >
  > - Remove the now-unreachable degenerate exp == 0 branch and the window
  >   bound check at the top of get_or_build; get_or_build returns
  >   Result<CachedToken, E> and drops the redundant window_start/exp_secs/
  >   now parameters, and the exp == 0 test is removed.
  >
  > * fix(status-list): fence cache on version, keep updated_at monotonic, version history
  >
  > Resolve review feedback on the version/updated_at split:
  >
  > - Redis cache: fence stale fills on the monotonic version instead of the
  >   wall-clock updated_at, store the version in the hash, and move the
  >   invalidation marker to a new version-scoped key name so old timestamp
  >   markers never fence out version-stamped fills.
  > - update_statuses: set updated_at = max(now, previous) so it stays a real
  >   timestamp (never drifting ahead of the clock) while not moving backwards.
  > - History: record the record version on status_list_history snapshots and
  >   tie-break find_valid_at on (iat, version) so ?time= returns the
  >   post-change snapshot when two updates share a second.
  > - Conditional requests: If-Modified-Since on its own no longer certifies a
  >   304; the exact ETag (which includes version) is the revalidation path.
  > - Migrations: move add_status_list_version to the end of the list and add
  >   the status_list_history version column migration.
  > - Fix test_mysql_lock_wait_timeout_maps_to_contention to use the
  >   version-based guard.
  >
  > * test(status-list): fix version-guard contention tests after version/updated_at split
  >
  > * docs(openapi): clarify only If-None-Match returns 304
  >
  > * docs(runbook): require Recreate/scale-to-one rollout for version-guard release
  >
  > * fix(chart): expose deployment rollout strategy and correct Recreate guidance
  >
  > The runbook previously claimed scaling to one replica avoids overlap during a
  > rolling deploy, but with the default RollingUpdate maxSurge rounds up to 1 so
  > the new pod starts while the old one is still running.
  >
  > - Add statuslist.strategy to the chart (Deployment.spec.strategy), defaulting
  >   to a plain RollingUpdate with no overrides
  > - Document statuslist.strategy in values.schema.json
  > - Update the runbook to use --set statuslist.strategy.type=Recreate and note
  >   that the only safe fallback is scaling to zero before the upgrade
  >
  > * docs(runbook): wait for pods to drain before Recreate upgrade
  >
  > * docs(runbook): scope rollback wait selector to server pods
  >
  > The old selector app.kubernetes.io/instance=statuslist also matches
  > the OpenTelemetry collector and Postgres subchart pods, which never
  > get deleted, so the wait would time out on a default install. Narrow
  > it to the server's own pods with the app.kubernetes.io/name label.
  >
  > * fix(status-list): fail closed on cached-token expiry and frame signer fingerprint
  >
  > Preserve the checked token-expiry conversion on the cached live-token path:
  > derive the validity window via token_expiry (i64::try_from + checked_add)
  > instead of a raw as i64 plus saturating_add, so a directly constructed
  > AppState with token_exp_secs = u64::MAX returns TokenExpiryOverflow (500)
  > rather than minting an already-expired token. Add a handler-level regression.
  >
  > Frame the signer fingerprint canonically by length-prefixing the algorithm,
  > public key, chain count, and each certificate, so structurally different
  > chains such as ["YWJj", "ZGVm"] and ["YWJjZGVm"] cannot collide before
  > hashing and break rotational self-invalidation. Add a boundary regression.
  >
  > * fix(tests): give shared AppState a realistic token-bytes cache and drop redundant assertions
  >
  > - size the shared test token-bytes cache to a realistic byte budget so a
  >   representative signed token fits and is resident before reuse/invalidation
  >   assertions run
  > - remove the duplicate status_list.validate() call from config loading
  > - correct the TokenBytesCacheConfig contract (per-replica, byte-bounded,
  >   expires at window boundary; capacity pressure may re-sign within a window)
  > - remove the redundant chain-count framing claim in the signer-fingerprint
  >   test
  >
  > * docs(runbook): correct signed-token cache invalidation invariant
  >
  > The ETag and cache key include both iat and the monotonic version. A
  > same-second A -> B -> A revert can leave iat unchanged, so it is the
  > monotonic version, not iat, that forces a new key and ETag. Update the
  > conditional-GET and cache sections to teach the correct invariant.
  >
  > * fix(status-list): strong token ETags, expiry-sized windows, one sign per (list,window,format), generation invalidation
  >
  > Addresses ticket 564 review:
  > - Strong ETag derived from the served representation bytes (proposal 3);
  >   cross-replica deviation from randomized signatures is documented.
  > - Expiry-sized windows (iat=window_start, exp=window_start+exp_secs);
  >   max-age bounded by the token's remaining lifetime; drop ExpiredToken.
  > - Cache keyed by (list, window, format); gzip/identity derived from the same
  >   uncompressed bytes, so an encoding change never triggers a second sign.
  > - Generation-aware invalidation reclaims superseded list entries.
  > - Capacity eviction re-sign policy documented and tested.
  >
  > * refactor(cache): decouple token-bytes cache from status-list handler
  >
  > Compute the window width directly from TokenCacheKey::token_exp_secs in
  > EntryExpiry instead of calling handlers::status_list::window_width and
  > constructing its TokenValidity. Remove the status_list/mod.rs re-export
  > of those utilities, which existed solely for this upward dependency, so
  > server::cache no longer depends on a handler module.
  >
  > * docs(cache): fix private intra-doc link in TokenBytesCache
  >
  > The public TokenBytesCache doc linked to the private
  > invalidate_superseded method, which breaks cargo doc under
  > -D warnings (rustdoc::private-intra-doc-links) even with
  > --document-private-items. Drop the link to plain code text.
  >
  > * fix: address review comments for ticket 564
  >
  > - Fix expiry-boundary regression: recheck clock after async work to detect window
  >   rollover during request processing (get_status_list.rs)
  >
  > - Implement two-tier cache for capacity guarantee: protected tier (latest
  >   generation, within window, never evicted) + cold tier (byte-bounded, for
  >   superseded/expired entries). Guarantees at most one signature per
  >   (list, window, format) per replica even under capacity pressure (cache.rs)
  >
  > - Fix generation invalidation: track latest generation per list_id, discard stale
  >   builds that complete after invalidation. Added test for stale generation
  >   build discard (cache.rs)
  >
  > - Fix gzip recomputation: pre-compute encoded variants (gzip for JWT) and their
  >   strong ETags at cache insertion time. Revalidation uses pre-computed values,
  >   no re-compression needed (cache.rs, get_status_list.rs)
  >
  > - Add explicit 'now' parameter to cache methods for deterministic test time
  >   handling (cache.rs)
  >
  > - Update OpenAPI spec: strong ETags, expiry-sized windows, bounded freshness,
  >   replica ETag differences (openapi.yaml)
  >
  > - Update deployment runbook: strong ETags, expiry-sized windows, two-tier cache,
  >   pre-computed encodings, capacity guarantee (deployment-runbook.md)
  >
  > - Make utils modules public (pub(crate)) for cross-module access (mod.rs, utils/mod.rs)
  >
  > - Add dashmap dependency for protected tier implementation (Cargo.toml)
  >
  > * style: run cargo fmt
  >
  > * fix: remove dead code and unused imports that broke the build
  >
  > * fix: use request-time now for cache-control and collapse nested if

- [922311d](
https://github.com/adorsys/status-list-server/commit/922311da6f70414939c75c3a09b6f05828220077) *(uncategorized)* Rewrite local CI script for improved functionality and clarity by @Ngha-Boris in [#593](
https://github.com/adorsys/status-list-server/pull/593)

  > * feat: rewrite local CI script for improved functionality and clarity
  >
  > * feat: enhance local CI setup with improved tool management and testing
  >
  > * refactor: share local CI validation and isolate runner tests
  >
  > * fix(tests): enhance error message checks for zero token lifetime in Helm chart
  >
  > * fix(ci): address local tooling review feedback
  >
  > * fix(ci): pin validation images and defer Docker requirements
  >
  > * fix(ci): finish Rust checks before requiring Docker
  >
  > * fix(ci): clarify rendered paths and quiet manifest checks

- [94595f5](
https://github.com/adorsys/status-list-server/commit/94595f5146d775d21e8e6ea98bfdb626753c9404) *(uncategorized)* Make the status list sub URI one authoritative value that issuers can read by @ndefokou in [#594](
https://github.com/adorsys/status-list-server/pull/594)

  > * feat: return status list URI on publish and make sub configurable
  >
  > Add server.public_base_url, defaulting to https://{server.domain}/api/v1,
  > as the single source of truth for the status list sub URI signed into
  > issued tokens. Validate server.domain as a bare host and public_base_url
  > as an absolute https URL with no query or fragment, failing at startup on
  > misconfiguration instead of silently signing unusable tokens. Warn when
  > server.domain is localhost in a production profile.
  >
  > PUT /api/v1/status-lists/{list_id}/statuses now returns 201 with a
  > Location header and {"uri", "list_id"} body, so issuers receive the exact
  > URI they must embed as the Referenced Token's sub (spec 5.1/5.2/8.3). The
  > served token's sub equals that URI byte for byte in both JWT and CWT form.
  >
  > Record in ADR 0002 that stored sub stays a publish-time artifact and goes
  > stale when the base URL changes, since aggregation reads the stored value.
  > Update openapi, README, env template and helm chart to document the option
  > and the issuer embed requirement.
  >
  > * fix(status-list): harden publish sub URI validation and Location handling
  >
  > Tightens the publish sub/URI feature so a misconfigured deployment fails
  > at startup instead of silently signing unusable tokens (draft-21
  > §5.1/§5.2/§8.3).
  >
  > - config: reject public_base_url with a trailing slash or a path other
  >   than /api/v1, so the published sub resolves to the served GET route;
  >   validate the *derived* default (not only an explicitly-set value) and
  >   bracket bare IPv6 domains so https://{domain}/api/v1 stays valid.
  > - publish: surface a 500 instead of silently dropping the Location
  >   header if the URI cannot be represented as a header value.
  > - test: assert the stored whitelist row's sub equals the publish
  >   Location, closing the acceptance-criterion wording directly.
  > - docs: fix stale compliance-matrix row 8 (route/URI format) and align
  >   .env.template, helm values and ADR 0002 with the path requirement.
  >
  > * chore: align compliance matrix with develop and tidy config comments
  >
  > Restore docs/compliance_matrix.md to the develop version, reverting the
  > authoritative-URI and ttl-validation entries added on this branch, and trim
  > verbose comments in values.yaml, config.rs, and setup.rs.
  >
  > * docs: reorder compliance matrix ttl validation row
  >
  > * style: format publish status handler test
  >
  > * fix(status-list): reject userinfo in public base URL and key localhost warning on resolved URL
  >
  > - Reject server.public_base_url values carrying userinfo so credentials
  >   cannot leak into Location, aggregation output, or the signed sub
  > - Base the production localhost warning on the resolved public base URL
  >   host instead of server.domain, covering loopback/private/local hosts
  > - Assert the Location authority and path mapping in the publish round-trip
  >   test alongside the JWT/CWT sub checks
  > - Drop the ADR and trim the Helm comment noise
  >
  > * fix(status-list): correct typo in setup comment
  >
  > * fix(status-list): address publish URI review feedback
  >
  > Harden the status-list publish sub/Location path and document the
  > stored-sub decision the removed ADR used to carry.
  >
  > - config: parse public_base_url once at load and sign the normalized URL
  >   into sub; allow a custom path (proxy prefix) and share the /api/v1
  >   prefix with the router so the two cannot drift; drop the raw value from
  >   parse errors (password-leak risk); rename database_host_is_ipv6; restore
  >   the token-lifetime doc reasoning
  > - publish: accept only lowercase hyphenated UUIDs; build the sub/Location
  >   before the write and echo the stored record.sub; carry the stored URI on
  >   a republish 409; restore size/bits in the response body
  > - setup: fail startup in production on localhost/loopback base URL, warn on
  >   private/local hosts, and warn when the ACME cert host differs from the
  >   public_base_url host
  > - docs: correct sub vs status.status_list.uri wording (README, openapi),
  >   record the stored-sub decision, extend StatusPublishResponse with
  >   uri/list_id, fix the helm externalDnsHostname comment, add runbook/env
  >   notes for non-443 ports and cert-host vs sub-host
  >
  > * fix(mysql): make test-container MySQL boot in AIO-restricted runtimes
  >
  > Use a GenericImage with native InnoDB AIO disabled (--innodb-use-native-aio=0)
  > so MySQL boots on Docker Desktop and restricted CI sandboxes where io_setup
  > is unavailable, and wait for the real server's "port: 3306" line so tests do
  > not connect during the init phase.
  >
  > Also apply rustfmt to the status-list publish URI review changes.
  >
  > * chore(env): condense public_base_url comment to two lines
  >
  > Keep the same guidance (absolute https, no userinfo/query/fragment/trailing
  > slash, any reachable path, non-443 port note) in a compact two-line comment.
  >
  > * fix(config): validate server.domain with the url host parser
  >
  > * fix(clippy): replace expect with format with unwrap_or_else
  >
  > * fix(status-list): address publish URI review feedback
  >
  > - Only attach the conflict Location header when the stored list belongs to
  >   the caller, and derive the 409 from err.into() instead of duplicating
  >   error.rs's code and message (publish_status.rs).
  > - Reword the sub-URI construction comment: the URI is infallible given the
  >   normalized base URL and canonical list_id, so it no longer claims to
  >   protect a stored list from an unseeable URI.
  > - Document in openapi.yaml that only the lowercase hyphenated list_id UUID
  >   form is accepted; other forms are rejected with 400.
  > - Validate aggregation_uri against the resolved public_base_url path so a
  >   proxy prefix no longer fails startup (startup.rs).
  > - Gate the production localhost check on APP_ENV directly, not
  >   telemetry.environment, and note the startup guard in the runbook
  >   (setup.rs, deployment-runbook.md).
  > - Compare the ACME sub host against the host parsed from server.domain so
  >   IPv6 and case normalization never false-warn (setup.rs).
  > - Drop the test-container MySQL change; it is out of scope for this issue
  >   and conflicts with #598.
  >
  > * refactor(config): centralize APP_ENV normalization into shared helpers
  >
  > Extract the APP_ENV normalization logic (trim, lowercase, prod/production
  > aliases) into config::normalize_app_env and a pure is_production
  > predicate, and use them in both config and setup so the deployment
  > profile guard matches what config itself decided. Previously the setup
  > guard compared the raw APP_ENV value to exactly "production", missing
  > profiles set via the "prod" alias or with casing/whitespace.
  >
  > Add unit tests covering the predicate and a regression test asserting the
  > prod alias fires the localhost base-URL guard. Update the OpenAPI list_id
  > path parameter docs to reflect that PUT restricts to the lowercase
  > hyphenated UUID form while PATCH accepts any form Uuid::try_parse
  > accepts.
  >
  > * test(config): cover APP_ENV prod-alias normalization for the base-URL guard
  >
  > Extract the pure classify_app_env mapping from normalize_app_env so the
  > prod/case/whitespace -> production aliases are testable without mutating
  > the process environment, and add regression tests proving a prod-style
  > APP_ENV now fires the production base-URL localhost guard.
  >
  > * refactor(config): centralize APP_ENV normalization into shared helpers
  >
  > * fix(clippy): drop redundant borrow of APP_ENV in setup guard
  >
  > * refactor(config): unify APP_ENV classification and fix production detection
  >
  > Introduce classify_app_env as the single authoritative prod/production
  > mapping and route the TelemetryEnvironment deserializer, base_builder,
  > DnsConfig::resolve, and the setup base-URL/ACME checks through it. This
  > removes the string trap where raw APP_ENV values such as 'prod' or
  > 'PROD' were compared against the canonical 'production' literal and
  > silently treated as non-production. Document that PATCH finds a status
  > list only by the exact spelling it was published with.
  >
  > * style(config): cargo fmt DnsConfig::resolve production check
  >
  > * fix(acme): only trust Pebble test CA in an explicit development environment
  >
  > * fix(acme): gate TelemetryEnvironment import behind acme feature

- [1e3fd85](
https://github.com/adorsys/status-list-server/commit/1e3fd85fe1367906931d0bbd3cdafb825164d200) *(uncategorized)* Add allocation and recording of indices for status lists by @Ngha-Boris in [#583](
https://github.com/adorsys/status-list-server/pull/583)

  > * feat: add allocation and recording of indices for status lists
  >
  > * fix: ensure correct expression type in status list update query
  >
  > * fix: allow unreachable_pub for status_list_allocations module
  >
  > * fix: prevent double allocation in management API and ensure unique index validation
  >
  > * fix: improve handling of default status in status list updates
  >
  > * feat: enhance status list management with allocation validation and error handling
  >
  > * fix: enforce fixed-size requirement for status list index allocation and improve error handling
  >
  > * feat: add tests for distinct allocations and rollback behavior in status list management
  >
  > * fix: update compliance matrix to reflect prevention of double allocation in management API
  >
  > * fix: update compliance matrix to reflect prevention of double allocation and duplicate index handling in management API
  >
  > * feat: enhance status list management with fixed-size metadata and improved error handling
  >
  > * fix: correct compliance matrix entry for bits packing specification
  >
  > * refactor: use status list creation command
  >
  > * fix: enhance error handling for list allocation and enforce issuer checks
  >
  > * fix: reject zero size in status list creation and handle allocations correctly

- [2364fa3](
https://github.com/adorsys/status-list-server/commit/2364fa3f8d58079efa2a979ca5fd3ffa297b7cff) *(uncategorized)* Consolidate license badges and restore dependencies and release tag badges in readme by @Blindspot22 in [#579](
https://github.com/adorsys/status-list-server/pull/579)

  > * docs: consolidate dual license badges
  >
  > * docs: restore dependencies status badge
  >
  > * docs: add release tag badge

- [9568296](
https://github.com/adorsys/status-list-server/commit/956829647af974877985f6a76d7cf507dae08987) *(uncategorized)* Status list aggregation endpoint by @martcpp in [#566](
https://github.com/adorsys/status-list-server/pull/566)

  > * fix(aggregation): paginate aggregation endpoint and enforce per-issuer list quota
  >
  > GET /api/v1/aggregation loaded every status list URI in one query and
  > response. It now returns bounded pages via keyset pagination on list_id:
  > `limit` (default and max 1000) and an opaque `cursor`, with `next_cursor`
  > in the body and an RFC 8288 `Link: rel="next"` header. No total count is
  > returned, since counting every row is itself an unbounded read.
  >
  > Publishing is capped by `limits.max_lists_per_issuer` (default 1000).
  > A new `credentials.list_count` column is incremented by a guarded UPDATE
  > in the publish transaction, before the status list INSERT, so the quota
  > is exact under concurrency, a failed publish gives its slot back, and
  > InnoDB's FK shared lock cannot deadlock concurrent publishes. A full
  > quota returns 400 `list_quota_exceeded` without Retry-After.
  >
  > The migration adds the column as NOT NULL DEFAULT 0 so pods on the
  > previous release keep registering credentials during a rolling deploy,
  > and backfills it. Re-run the recount SQL in docs/troubleshooting.md once
  > the rollout completes.
  >
  > The quota bounds lists per issuer only: while POST /api/v1/credentials is
  > unauthenticated, a new issuer brings a fresh quota.
  >
  > Co-Authored-By:Claude Opus 5.5 <noreply@anthropic.com>
  >
  > * fix(aggregation): harden cursor paging and list quota edge cases
  >
  > - Report 409 instead of list_quota_exceeded when a publish at a full
  >   quota targets a list_id that already exists, so a retried publish is
  >   recognisable (SQL and memory adapters).
  > - Accept any stored list_id in aggregation cursors instead of UUIDs
  >   only, so rows from before list_id validation cannot strand a walk.
  >   Cap cursor length and tag cursors with a v1 version prefix.
  > - Log aggregation handler errors at INFO and drop the duplicate WARN.
  > - Guard the list_count migration with has_column so a failed MySQL
  >   backfill can be re-run; enable the sea-orm-migration backend
  >   features that has_column needs.
  > - Restrict the status list delete_by to tests: it bypasses list_count.
  > - Test the migration backfill on MySQL and Postgres, slot return after
  >   a failed snapshot insert, publishes during a cursor walk, and an
  >   end-to-end HTTP walk on each SQL backend.
  > - Docs: qualify the walk completeness guarantee, make the list_count
  >   recount a required step after any rollout that served a pre-quota
  >   release, and document 409 precedence over the quota.
  >
  > * chore(typos): ignore base64 aggregation cursor examples
  >
  > * fix(aggregation): bound in-memory list paging and document rollout quota gap
  >
  > The memory backend cloned and sorted every list on each aggregation page
  > while holding the read lock, and counted an issuer's lists by scanning all
  > of them on every publish. Keep lists in a BTreeMap keyed by list_id so a
  > page is a range scan taking at most limit + 1 entries, and keep a per-issuer
  > count so the quota check is constant time.
  >
  > Document that the list quota is exact only once every pod enforces it:
  > lists a pre-quota pod publishes during the rollout are kept, like lists
  > that predate the migration, and the post-deploy recount blocks further
  > publishes from an issuer left over quota. Add a test for that on SQLite,
  > MySQL and Postgres.
  >
  > * style(tests): apply rustfmt to over-quota recount test
  >
  > * feat(quota): gate list quota behind an operator activation step
  >
  > Pods of a release that predates the quota publish without counting, so
  > during a rolling deploy they could push an issuer past
  > max_lists_per_issuer, and a later recount could not undo that.
  >
  > Ship the quota off on the SQL backends. A new single-row list_quota
  > table holds the switch; publishes keep maintaining list_count but are
  > not refused until an operator runs, once no older pod is left:
  >
  >   status-list-server list-quota recount
  >   status-list-server list-quota enable
  >
  > enable refuses, naming the issuers, while any issuer has more lists
  > than the cap or a list_count that differs from its lists. It holds the
  > switch row's exclusive lock while checking, and publishes read the
  > switch under a shared lock while it is off, so an in-flight publish is
  > either counted by the check or refused by the enforced quota. recount
  > is refused while the quota is enforced; disable turns it off again
  > before a rollback. Pods log a warning at startup until it is enabled.
  > The memory backend enforces the quota from startup, as before.
  >
  > Tests cover activation succeeding within the cap and failing with the
  > over-cap issuer named, stale counts, recount while enforced, and enable
  > waiting for an in-flight publish on MySQL and Postgres.
  >
  > * docs(troubleshooting): fix markdownlint MD038 in list quota section
  >
  > * docs(quota): drop private intra-doc link from list_quota module docs
  >
  > * feat(quota): enforce list quota on fresh installs and fail closed on upgrade
  >
  > The quota shipped off for every SQL deployment, so a missed manual step
  > left the configured cap unenforced with only a startup warning.
  >
  > A pod that finds no migration applied now enables the quota right after
  >
  > migrating:no release without it has written to that database. On a
  > database such a release served, a pod refuses to start while the quota
  > is off, unless APP_LIMITS__LIST_QUOTA_TRANSITION=true is set for that
  > rollout. With it set, pods start unenforced, log an error on every
  > start and report list_quota_enforced=0 until `list-quota recount` and
  > `list-quota enable` run; a leftover setting on an enforced database is
  > warned about.
  >
  > Also simplify the list quota code: derive the error with thiserror,
  > use sea-query idens and lock types instead of hand-rolled ones, and
  > replace the memory store's check/insert/replace helpers with a single
  > entry-based try_insert. Trim comments to what the code does not say.
  >
  > ---------

- [7a8b968](
https://github.com/adorsys/status-list-server/commit/7a8b96889c0d1f8d8f1b1f1f24dce453f062d7c8) *(uncategorized)* Enforce 8-bit capacity for application-specific status values and update related validations by @Ngha-Boris in [#557](
https://github.com/adorsys/status-list-server/pull/557)

  > * feat: enforce 8-bit capacity for application-specific status values and update related validations
  >
  > * feat: enhance application-specific status value handling and validation
  >
  > * feat: implement 8-bit capacity enforcement for status values and enhance token representation handling
  >
  > * fix: correct CWT emission to use tagged CBOR format and enhance compliance with §4.3
  >
  > * feat: add Redis cache support and enhance network policy configuration
  >
  > * Revert "feat: add Redis cache support and enhance network policy configuration"
  >
  > This reverts commit d373756cb1e8bd33dda2cd4aaadc34fb0d98e80c.
  >
  > * feat: enhance Draft-21 compliance and legacy status handling
  >
  > * refactor: remove outdated Draft-21 legacy status list audit documentation
  >
  > * fix: ensure compliance with Draft-21 for bits representation in status list

- [3289d23](
https://github.com/adorsys/status-list-server/commit/3289d23094ae8b4d80ea2c825dd8e9b40f0be1d9) *(uncategorized)* Align openapi status contract dual stringinteger deserialization by @Blindspot22 in [#555](
https://github.com/adorsys/status-list-server/pull/555)

  > * feat: dual string/integer status deser
  >
  > * docs: status value oneof schema
  >
  > * test: status dual deser coverage
  >
  > * docs: update statusvalue openapi schema
  >
  > * test: add status deserialization tests

- [1dafcbe](
https://github.com/adorsys/status-list-server/commit/1dafcbe74195b96f794908ad8809341eff392214) *(uncategorized)* Update database password handling and support MySQL by @Ngha-Boris in [#521](
https://github.com/adorsys/status-list-server/pull/521)

  > * feat: update database password handling and support MySQL
  >
  > * feat: decouple MySQL support from PostgreSQL in Helm chart and CI configurations
  >
  > * feat(auth): enhance JWT management claims validation and configuration
  >
  > * feat(auth): enhance JWT management claims validation and configuration
  >
  > * feat(auth): enhance management JWT claims validation and configuration
  >
  > * docs: remove outdated validation and security sections from README
  >
  > * docs: remove redundant example commands from README
  >
  > * docs: add example for building with PostgreSQL support and filesystem key loading
  >
  > * feat: enhance database backend support and update image variants
  >
  > * fix(watcher): only rotate on real content changes, not read/open events
  >
  > * fix(watcher): only rotate on real content changes, not read/open events
  >
  > * refactor(watcher): harden fingerprinting and logging per review
  >
  > * fix(docs): update image variant table formatting in README
  >
  > * refactor: helm chart to remove MySQL support and streamline PostgreSQL configurations
  >
  > * fix(dependencies): update windows-sys version to 0.60.2 and rustls to 0.23.45
  >
  > * fix(dependencies): update rustls version to 0.23.45
  >
  > * fix(dependencies): downgrade windows-sys to 0.52.0 and rustls to 0.23.43
  >
  > * fix(helm): enhance database password secret key handling and add tests for secret mounts
  >
  > * fix(helm): update MySQL backend handling and documentation for explicit image requirements
  >
  > * chore: bump chart version to 0.5.0 and update changelog
  >
  > * fix(helm): update digest validation regex in image reference verification script
  >
  > * fix(helm): update secret key references and enhance error handling in Helm templates
  >
  > ---------

- [3fba209](
https://github.com/adorsys/status-list-server/commit/3fba2096037b62a2e5d3a810cad599fc443ec843) *(uncategorized)* Image provenance self asserted by @martcpp in [#511](
https://github.com/adorsys/status-list-server/pull/511)

  > * refactor(ci): extract manifest resolution, report derivation and gate self-test into shared scripts
  >
  > * feat(scripts): surface trivyignore exceptions approaching expiry before they lapse
  >
  > * feat(ci): add scheduled re-scan of released images with SARIF and issue tracking
  >
  > * docs(supply-chain): restore the post-merge advisory claim and document the nightly re-scan
  >
  > * fix(ci): stop the scheduled re-scan reading absent coverage as a clean run
  >
  > * feat(scripts): assert the image variant lists agree across deploy and the re-scan
  >
  > * fix(ci): fail the deploy when IMAGE_VARIANT is invisible to the scheduled re-scan
  >
  > * fix(ci): correct the nightly's expiry notice and scope its red to production
  >
  > * docs(supply-chain): document the tiered verdict, expiry notice and variant parity
  >
  > * fix(scripts): reject a malformed arch manifest digest before it reaches GITHUB_ENV
  >
  > * feat(scripts): constrain ignore-file ids to the character set their consumers assume
  >
  > * refactor(ci): keep the nightly's severity floor and summary schema in one place
  >
  > * docs(supply-chain): correct the aggregation gating claim and the SARIF derivation
  >
  > * docs(adr): record the decision to keep both container image provenance documents
  >
  > Co-Authored-By:Claude Opus 5 <noreply@anthropic.com>
  >
  > * feat(scripts): verify signed image provenance and prove the verifier can fail
  >
  > Co-Authored-By:Claude Opus 5 <noreply@anthropic.com>
  >
  > * feat(ci): attest build provenance and verify it survived tag promotion
  >
  > Co-Authored-By:Claude Opus 5 <noreply@anthropic.com>
  >
  > * ci: run the attestation self-test on every pull request and in local-ci
  >
  > Co-Authored-By:Claude Opus 5 <noreply@anthropic.com>
  >
  > * docs(supply-chain): document which provenance to verify and what disagreement means
  >
  > Co-Authored-By:Claude Opus 5 <noreply@anthropic.com>
  >
  > * fix(scripts): pin the signing workflow in attestation verification and document what a signature does not prove
  >
  > Co-Authored-By:Claude Opus 5 <noreply@anthropic.com>
  >
  > * fix(scripts): pin the signing identity exactly and read the verification result from gh's JSON
  >
  > Co-Authored-By:Claude Opus 5 <noreply@anthropic.com>
  >
  > * fix(ci): verify signed provenance before promotion and against the digest deployed
  >
  > Co-Authored-By:Claude Opus 5 <noreply@anthropic.com>
  >
  > * ci: run the attestation self-test as its own job
  >
  > Co-Authored-By:Claude Opus 5 <noreply@anthropic.com>
  >
  > * docs: correct what the provenance check enforces and record the ADR amendment
  >
  > Co-Authored-By:Claude Opus 5 <noreply@anthropic.com>
  >
  > * ci: fix YAML indentation, markdown lint, typos, and yamlfmt
  >
  > - Fix .github/workflows/scheduled-image-scan.yml YAML indentation for run block
  > - Fix docs/supply-chain.md MD049 emphasis style (asterisk -> underscore)
  > - Fix helm/chart/values-rotation-example.yaml yamlfmt trailing whitespace
  > - Fix scripts/attestation-selftest.sh typo 'unparseable' -> 'unparsable'
  >
  > * chore(ci): make verify-attestation.sh executable in git index
  >
  > Required for attestation-selftest CI job to run verify-attestation.sh without
  > Permission denied on ubuntu-latest runners.
  >
  > * fix: resolve DEPLOY_TAG scope, zizmor permissions, attestation troubleshooting, and gh download consistency
  >
  > - Fix DEPLOY_TAG not defined in 'Verify signed provenance survived promotion' step
  > - Add zizmor ignore directive for excessive-permissions in build-and-push job
  > - Add Attestation Verification Failure troubleshooting section
  > - Fix inconsistent gh run download invocation in verify-provenance job
  >
  > * docs: remove ADR 0001 container image provenance
  >
  > * docs: restore ADR 0001 container image provenance
  >
  > fix:restore YAML indentation in values-rotation-example.yaml
  > - Fix comments in statuslist.env block (lines 164, 166-174)
  > - Fix serviceAccount.annotations comment for EKS IRSA
  >
  > * docs: trim provenance rationale from ADR, supply-chain doc, script header and workflow comments
  >
  > ---------

### Bug Fixes

- [e0b303d](
https://github.com/adorsys/status-list-server/commit/e0b303d8cdf9c1e5f064d3e495650ef106ae4a80) *(ci)* Give each Trivy SARIF run a distinct category and move codeq… by @martcpp in [#537](
https://github.com/adorsys/status-list-server/pull/537)

  > * fix(ci): give each Trivy SARIF run a distinct category and move codeql-action to v4
  >
  > * fix(ci): catch colliding and id-less SARIF runs and correct the URI-prefix rationale

- [5435e9d](
https://github.com/adorsys/status-list-server/commit/5435e9d176d15931826e033a05c22f0b9fd8d296) *(demo)* Replace Jupyter notebooks with plain workflow scripts by @ndefokou in [#631](
https://github.com/adorsys/status-list-server/pull/631)

  > * fix(demo): repair and continuously verify the demo workflows end-to-end
  >
  > The four demo notebooks were never executed in CI or by any
  > committed script, so they could silently drift from the server API or
  > the setup instructions. There was no non-interactive command that
  > would run them, and doing so required an undeclared certificate and
  > shared mutable state.
  >
  > Replace the interactive Jupyter notebooks with plain Python workflow
  > scripts and add a deterministic driver (run-demo-smoke.py) that:
  >
  > - syncs an isolated demo environment (uv sync --locked),
  > - generates temporary self-signed signing material,
  > - starts the server against in-memory storage on a free port with a
  >   raised rate limit,
  > - executes all four workflows from fresh state (fresh random issuer
  >   labels and status-list UUIDs per run),
  > - stops the server and cleans up temporary material even on failure.
  >
  > The driver starts the server in its own process group so cleanup kills
  > the whole tree instead of orphaning the server, fails fast when the
  > server exits during startup, and persists partial workflow output on
  > timeout. Add unit tests for the driver's helpers.
  >
  > Wire a demo-smoke CI job (required status check) that runs the driver
  > unit tests, executes the full smoke twice to prove repeated runs are
  > isolated, asserts demo/workflows is unchanged by execution, and uploads
  > failure logs as artifacts.
  >
  > Document the root cause in demo/REPRODUCTION.md and update
  > demo/README.md with the one-shot command and interactive usage.
  >
  > * docs(demo): record the real root cause of the notebook failure
  >
  > The reported failure was a server startup problem: launching Jupyter Lab
  > served every static asset with HTTP 500 due to a jupyter_server/tornado
  > incompatibility ('FileFindHandler' missing 'allowed_symlink_directory').
  > jupyter_server 2.21.0 overrides FileFindHandler.initialize() without
  > calling super(), so the attribute tornado 6.4+ relies on was never set;
  > upgrading or downgrading tornado did not help, and uv re-syncing from
  > uv.lock undid manual pinning. The fix was upgrading jupyter_server to
  > 2.21.1, then redirecting the approach to plain Python scripts to drop
  > the Jupyter chain entirely.
  >
  > Rewrite demo/REPRODUCTION.md to document this root cause accurately.
  >
  > * fix(ci): resolve markdownlint and zizmor pipeline failures
  >
  > - demo/README.md: remove extra blank line (MD012)
  > - demo/REPRODUCTION.md: annotate fenced code block with language (MD040)
  > - CI.yml: pin astral-sh/setup-uv to tagged v10.2.0 so the hash pin
  >   version comment matches a real ref (zizmor)
  >
  > * fix(ci): remouving the reproduction.md file
  >
  > * fix(ci): remouving the demo-smoke on the ci
  >
  > * fix(ci): restore demo-smoke gate and harden smoke driver
  >
  > Re-add the demo-smoke job removed in e94aa74f and gate it via
  > ci-success.needs, so the demo workflows stay continuously verified in CI
  > and demo/README.md's claim matches the pipeline.
  >
  > Harden run-demo-smoke.py per review:
  > - retry server startup with a fresh free port when the port was
  >   auto-selected, avoiding the find_free_port TOCTOU race
  > - make server a required wait_for_health parameter (drop dead None path)
  > - guard os.killpg against ProcessLookupError during cleanup
  > - read SMOKE_LOG_DIR once instead of twice
  >
  > * fix(ci): remove smoke test from ci
  >
  > * fix(demo): drop the CI smoke driver and Jupyter from the demo
  >
  > The demo is run manually, not in CI, so remove the CI smoke driver
  > (run-demo.py and its test) and the Smoke check / interactive sections in
  > the README. Drop the jupyterlab dependency and regenerate uv.lock and
  > requirements.txt, and clean up the .smoke-logs and Jupyter entries in
  > .gitignore.
  >
  > * fix(demo): apply review feedback to the workflow scripts
  >
  > - Remove the unused is_valid_cwt helper; workflow 01 uses decode_cwt_status_list.
  > - Make the multiple-status-lists script use a fixed list size so runs are repeatable.
  > - Clarify in the README that only issuer names are random, not the fixture keys.
  > - Restore *.tgz in .gitignore for Helm chart dependency archives.

- [7aab549](
https://github.com/adorsys/status-list-server/commit/7aab5490958092b3f2bd4ac3c9f2517afe406e22) *(demo)* Move demo environment to uv and align notebooks by @martcpp in [#541](
https://github.com/adorsys/status-list-server/pull/541)

  > * fix(demo): move demo environment to uv and align notebooks with current server API
  >
  > * fix(demo): address review findings on Python pin, rate limit, CWT and status checks
  >
  > * fix(demo): address review on gitignore, README and status enum
  >
  > * fix(demo): tighten dev cert extensions and bounds-check get_status

- [0e05912](
https://github.com/adorsys/status-list-server/commit/0e059120638ae013145702c12fdcbeb1417f2cad) *(deploy)* Point release at datev-wallet ClusterSecretStore by @Christiantyemele in [#589](
https://github.com/adorsys/status-list-server/pull/589)

  > * fix(deploy): point release at datev-wallet ClusterSecretStore
  >
  > ESO is installed cluster-wide in the datev-wallet namespace, not in
  > statuslist-production. A namespaced SecretStore cannot be referenced
  > across namespaces, so the deploy now points the ExternalSecrets at the
  > cluster-scoped store served by that ESO (ClusterSecretStore
  > datev-secret-store) and stops rendering its own namespaced SecretStore.
  > This fixes the production deploy failing with 'no matches for kind ...
  > external-secrets.io/v1'.
  >
  > Also adds scripts/deploy-local-esm.sh for validating the fix against the
  > floci + Minikube emulation (wallet-eks-env PR #47).
  >
  > * chore: keep local emulation test script out of the deploy fix PR
  >
  > * fix(deploy): create namespace on install per review
  >
  > * fix(deploy): drop --create-namespace for statuslist-production
  >
  > The statuslist-production namespace is owned by Terraform, and the deploy
  > role only has namespace-scoped access, so it cannot create a cluster-scoped
  > Namespace. --create-namespace would fail with Forbidden and can cause
  > Terraform ownership drift. Namespace and RBAC provisioning is handled via
  > wallet-eks-env#32.
  >
  > * ci(deploy): assert release ESO config and gate deploy on secret reconciliation
  >
  > Per review, two gaps in the release-only ESO configuration (values-aws.yaml +
  > values-production.yaml + the three --set overrides that point the release at
  > the cluster-scoped store) went unverified:
  >
  > 1. Add a production render assertion in render-helm-templates/action.yml that
  >    renders with the same three overrides the deploy applies and asserts no
  >    namespaced SecretStore is emitted and that every release ExternalSecret
  >    references ClusterSecretStore/datev-secret-store. The existing wl-prod
  >    render only supplied the two value files and therefore could not detect a
  >    regression in this release-only configuration.
  >
  > 2. Gate the deploy on the newly selected secret path actually reconciling. On
  >    an upgrade, statuslist-secret and aws-credentials-secret can remain from the
  >    old namespaced store, so a Helm and Deployment rollout could succeed even if
  >    neither ExternalSecret syncs from datev-secret-store, leaving production on
  >    stale credentials while the release reports success. After applying the
  >    chart, wait (with a timeout) for the ClusterSecretStore and both release
  >    ExternalSecrets to report Ready/SecretSynced and fail otherwise.
  >
  > * fix(deploy): render ESO resources as external-secrets.io/v1beta1
  >
  > Per review, keep the cluster on its current ESO version instead of requiring a
  > cluster-wide ESO upgrade. The production cluster only serves
  > external-secrets.io/v1beta1, while the chart hardcoded external-secrets.io/v1,
  > so the deploy failed with 'no matches for kind ExternalSecret in version
  > external-secrets.io/v1'. Upgrading ESO would force every component using ESO to
  > upgrade too, so instead switch the chart to render the API version the
  > currently-deployed cluster already serves.
  >
  > - external-secrets.yaml: all three ExternalSecret resources now use
  >   external-secrets.io/v1beta1.
  > - secret-store.yaml: SecretStore uses external-secrets.io/v1beta1.
  > - README: document the v1beta1 API requirement and that ClusterSecretStore
  >   references must already exist.
  >
  > The deploy workflow keeps pointing the release at the cluster-scoped
  > ClusterSecretStore datev-secret-store and renders no namespaced SecretStore.
  > The ESO upgrade is deferred (tracked as a separate infra concern); this change
  > makes the release work with the current ESO version.
  >
  > * ci(deploy): remove verbose ESO comment from helm command
  >
  > Per review, drop the long-running explanatory comment about ESO being
  > installed cluster-wide in datev-wallet from the helm upgrade command. The
  > --set overrides (externalSecret.spec.secretStoreRef.*, secretStore.enabled)
  > are self-explanatory in the release configuration.
  >
  > * ci(deploy): gate ESO sync on refreshTime change and drop cluster store check
  >
  > Address review:
  > - Remove the cluster-scoped ClusterSecretStore readiness check; the deploy
  >   role's EKS/RBAC is namespace-scoped, so reading it would get Forbidden and
  >   time out every deployment. Rely on both namespaced release ExternalSecrets.
  > - Record each ExternalSecret's pre-deploy refreshTime and require it to move
  >   past that baseline (plus Ready=True) so a stale Ready condition from before
  >   the upgrade cannot pass verification.
  >
  > * ci(deploy): force-sync ESO and roll back on verification failure
  >
  > Address two review comments from @Hermann-Core on PR #589:
  >
  > 1. Trigger reconciliation before requiring refreshTime to change. The chart
  >    uses refreshInterval 30m, so an image-only release leaves the ExternalSecret
  >    spec unchanged and ESO could keep the old refreshTime for the whole wait
  >    window. Annotate both release ExternalSecrets with a unique
  >    external-secrets.io/force-sync value (RUN_ID-RUN_ATTEMPT) before waiting.
  >
  > 2. Keep the verification inside the rollback boundary. The post-deploy checks
  >    ran after helm upgrade --install --rollback-on-failure had already succeeded,
  >    so a failure marked the workflow failed but left the new revision live. Record
  >    the pre-deploy Helm revision and explicitly roll back (or uninstall on a fresh
  >    install) when either ExternalSecret fails to reconcile.
  >
  > * ci(deploy): trim verbose ESO verification comments
  >
  > Condense the 'Verify ESO secret path reconciles' step comment to keep only
  > the non-obvious constraints and decisions that are not evident from the
  > code: the namespace-scoped RBAC limitation (no ClusterSecretStore read),
  > the refreshTime baseline (Ready alone can be stale), the force-sync
  > requirement, and the explicit rollback boundary.

- [52f641a](
https://github.com/adorsys/status-list-server/commit/52f641ac39547e7e859cae23c39206746ec76274) *(deps)* Update quinn-proto by @Blindspot22 in [#658](
https://github.com/adorsys/status-list-server/pull/658)

- [99d80c9](
https://github.com/adorsys/status-list-server/commit/99d80c9feb24ed6905258f3951ef71f80b70a55f) *(docker)* Pin builder base images to immutable sha256 digests by @Christiantyemele in [#604](
https://github.com/adorsys/status-list-server/pull/604)

  > * fix(docker): pin builder base images to immutable sha256 digests
  >
  > Pin blackdex/rust-musl:x86_64-musl and blackdex/rust-musl:aarch64-musl
  > builder base images in the Dockerfile to immutable @sha256 index digests.
  > A mutable tag can change upstream without notice, producing
  > non-reproducible builds, unexpected compiler differences, or
  > supply-chain risk. Both tags are multi-architecture index manifests, so
  > pinning the index digest keeps both linux/amd64 and linux/arm64
  > reproducible while --platform=$BUILDPLATFORM still selects the correct
  > child.
  >
  > Document the manual bump path in docs/supply-chain.md, since the pins
  > are invisible to Dependabot's docker ecosystem.
  >
  > Closes #486
  >
  > * docs(supply-chain): fix markdown lint on builder digest steps
  >
  > Nest the fenced code block inside the ordered list item at the correct
  > indentation so markdownlint's MD031 (blanks around fences) and MD029
  > (ordered list prefix) both pass.
  >
  > * fix(docker): verify builder digests and correct dependabot docs per review
  >
  > * style(docker): trim builder comment block per review
  >
  > * docs(supply-chain): clarify toolchain coupling breaks on digest bump
  >
  > * fix(ci): fail builder digest check unless two FROM refs found
  >
  > * docs(supply-chain): correct builder digest wording per review
  >
  > * refactor(ci): drop redundant builder-digest group and check per review
  >
  > ---------

- [24b9bb8](
https://github.com/adorsys/status-list-server/commit/24b9bb87cdf2624ced1baf2fe931699c86511349) *(helm)* Align chart monitoring with shared kube-prometheus-stack by @ndefokou in [#512](
https://github.com/adorsys/status-list-server/pull/512)

  > * feat: add webhook-based alert notifications for observability alerts
  >
  > Forward observability alerts to external notification systems through
  > Alertmanager webhooks. Prometheus sends fired/resolved alerts to
  > Alertmanager, which renders a native receiver config from environment-only
  > credentials so no webhook URL is committed.
  >
  > - Add Alertmanager service to docker-compose
  > - Wire alerting.alertmanagers into dev and production Prometheus configs
  > - Use generic webhook_configs for Teams/Mattermost/Discord/Slack/email
  > - Add webhook delivery test (firing and resolved) against a mock endpoint and
  >   wire it into CI
  > - Document setup in observability/runbooks/webhook-notifications.md and update
  >   .env.template with required variables
  >
  > * feat: add support for GKE and AKS Workload Identity in DNS provider configuration
  >
  > * feat: add support for GKE and AKS Workload Identity in DNS provider configuration
  >
  > * fix: streamline ClientSecretCredential initialization in DefaultAzureCredential
  >
  > * refactor: azure and gcp dns providers to use defaultazurecredential and application default credential
  >
  > * refactor: simplify project_id assignment and update token module condition
  >
  > * refactor: streamline acme dependencies and clean up test configurations in GoogleCloudDnsProvider
  >
  > * refactor: remove test-specific from_token_provider implementation in AzureDnsProvider
  >
  > * fix(docs): update error response formats to use JSON instead of plain text
  >
  > * fix(helm): align chart monitoring with shared kube-prometheus-stack
  >
  > Scope all PromQL selectors and the metrics-absent alert to the release
  > namespace so rules never evaluate another deployment's data or stay
  > silent cluster-wide. Make the prometheus.io/* pod annotations opt-in
  > (since the ServiceMonitor is the authoritative discovery path), publish
  > the generated SLO dashboard as a grafana_dashboard:"1" ConfigMap for the
  > central Grafana sidecar, enable it in production values, and document the
  > retention (>30d) and CRD install-order dependencies of the shared stack.
  >
  > Adds CI render tests for namespace-scoped rules, the dashboard ConfigMap,
  > and the opt-in annotations.
  >
  > * feat(auth): introduce AuthenticatedIssuer struct for better issuer management
  >
  > * feat(auth): introduce AuthenticatedIssuer struct for better issuer management
  >
  > * refactor(auth): streamline AuthenticatedIssuer usage and improve request handling
  >
  > * feat: refresh readme to match current implementation and configuration
  >
  > * docs: fix architecture link
  >
  > * docs: update documentation index
  >
  > * docs: remove stale redis references
  >
  > * docs: add pebble dns provider
  >
  > * docs: add rate limit limits
  >
  > * docs: add nextest prerequisite note
  >
  > * docs: update README.md
  >
  > * docs: overhaul README to highlight features and simplify overview
  >
  > * fix(env): increase status cache max capacity to 1000

- [bfa7eee](
https://github.com/adorsys/status-list-server/commit/bfa7eee7a9b2cc8ed1c6a24052696d1ba1d88167) *(migrations)* Make rollbacks across migrations recoverable by @martcpp in [#634](
https://github.com/adorsys/status-list-server/pull/634)

  > * docs(migrations): record forward-only migrations and the rollback recovery
  >
  > Rolling back across a migration leaves the previous release unable to
  > start: it refuses a database that records migrations it has no file
  > for. Both automatic rollbacks in deploy.yml can do this, and nothing
  > said what to do. The deployment runbook now has the recovery: delete
  > the records of the migrations the previous release does not know, keep
  > the schema, and keep the newer release serving until the old pods are
  > ready. Restoring a backup is the last resort, and the runbook leads with
  > its cost: status changes since the backup are lost, revocations
  > included.
  >
  > ADR 0003 records why down migrations are refused rather than fixed,
  > including the InnoDB 1553 failure the suggested has_index guards would
  > have hit on MySQL.
  >
  > * fix(migrations): refuse down migrations
  >
  > Nothing outside the tests ran down, and it could not reach zero on
  > MySQL: the three oldest index drops panic in sea-query, and guarding
  > them instead fails with error 1553 after two drops have committed.
  > Undoing the aggregation ID migration would also break every aggregation
  > URI already handed out. Every down now returns an error that points at
  > the runbook's rollback section.
  >
  > The two upgrade tests that rolled MySQL and Postgres back to an earlier
  > schema now apply only the first migrations, as the SQLite ones already
  > did. New tests pin the refusal, that rolling back keeps aggregation IDs,
  > and that every migration after the four oldest re-runs once its record
  > is deleted, which the rollback recovery depends on.
  >
  > * fix(migrations): name unknown migrations at startup and refuse fresh
  >
  > A release rolled back past a migration exits with sea-orm's "migration
  > file is missing", which says nothing about the recovery. When migrating
  > fails, the error now names every migration the database records that
  > the release does not know, and points at the runbook. The records are
  > read only after migrating has failed, and the original error comes back
  > unchanged when there are none, so the check cannot stop a start that
  > would have succeeded. It helps rollbacks to releases that contain it.
  >
  > fresh drops every table without running any down, so it is refused at
  > the Migrator level, like down, reset and refresh already were.
  >
  > Tests now hold each migration's down to the refusal itself rather than
  > any error, cover fresh, reset and refresh, check list_count after every
  > re-run, and stand in for v1.2.0 with a migrator that knows only the four
  > oldest migrations: it refuses the newer database, naming all five, and
  > starts once their records are deleted. That proves the migrator side of
  > the recovery, not that the previous release runs on the newer schema.
  >
  > * ci(deploy): point automatic rollbacks at the migration recovery
  >
  > A failed upgrade that rolls back can look clean while the database
  > records migrations the restored release cannot start against: its
  > running pods keep serving, and the next restart, scale-up or node drain
  > crash-loops. The job's failure says only that the upgrade failed. Both
  > rollback paths now emit an error annotation naming the risk and the
  > runbook section.
  >
  > * docs(migrations): make the rollback recovery followable and cut the restore procedure
  >
  > The restore procedure could not be followed for backups older than the
  > allocation or aggregation migrations, and as written it handed status
  > indices out twice: allocation takes the lowest index no record claims,
  > and a restore removes every record written after the backup. It is now
  > a warning until a procedure exists.
  >
  > The rollback recovery gains what an operator needed and did not have:
  > the warning above the rollback commands, how to open a SQL session, the
  > pod log in preference to applied_at, the DELETE inside a transaction
  > with its row count checked before COMMIT, the recount's row locks, and
  > a table of which migrations are safe to leave in place. The table is
  > what step 2 now points at. Writing it found that rolling back past
  > m20260925_000001_status_list_allocations is not safe: v1.2.0 rewrites a
  > fixed-size list without its size whenever it updates it, so the list
  > stops accepting allocations.
  >
  > ADR 0003 extends rule 1 to partial states and to the data the previous
  > release writes, records the startup check, and corrects its claim about
  > down: DROP TABLE avoids error 1553, checked on MySQL 26.7.0, so down was
  > possible but undesirable.
  >
  > * fix(migrations): hold the version migrations to the forward-only rules
  >
  > The two version migrations that landed with the signed-token cache had
  > working downs, and add_status_list_version set every list's version back
  > to 1 each time it ran. After a rollback recovery re-ran it, lists would
  > fall below the version marker the Redis cache keeps, which rejects older
  > writes. Both downs now refuse, and the backfill is gone: DEFAULT 1
  > already fills existing rows. A test checks that a list's version
  > survives every re-run.
  >
  > The runbook's table gains a row for each, and the import the MySQL and
  > Postgres list_count tests use is no longer gated to SQLite.
  >
  > * docs(migrations): move the forward-only decision to the SQL README and cover overlap-unsafe rollbacks
  >
  > Drop ADR 0003; the decision and the two rules for new migrations now live in src/outbound/sql/README.md.
  >
  > The runbook's recovery kept old and new pods serving together, which the add_status_list_version upgrade forbids. Give that rollback its own scale-to-zero procedure, say what a failed Recreate upgrade costs, and tell operators never to delete the four oldest records.
  >
  > * ci(deploy): raise the migration error only when the rollback fails
  >
  > A rollback that finishes with --wait started its pods, so no unknown migration is in the way.
  >
  > * test(migrations): require a runbook row per migration and pin the quota switch across re-runs
  >
  > * docs(migrations): state the rolling-update invariant instead of replica arithmetic
  >
  > The arithmetic restated Kubernetes' defaults and production's sizes, which this runbook does not own and which would drift.

- [9a72331](
https://github.com/adorsys/status-list-server/commit/9a7233152face3c767513710a751f6bed5fdae2c) *(tests)* Clean up scoped database fixture containers by @Ngha-Boris in [#598](
https://github.com/adorsys/status-list-server/pull/598)

  > * fix(tests): enhance error messages for zero token lifetime validation in Helm chart
  >
  > * fix(tests): address database fixture lifecycle review
  >
  > * fix(tests): reuse nextest run IDs for fixture cleanup

- [cc265c4](
https://github.com/adorsys/status-list-server/commit/cc265c4f64d22b86dba15985e2d8e7838e02048d) *(uncategorized)* Negotiate Accept per RFC 9110 for status list retrieval by @ndefokou in [#585](
https://github.com/adorsys/status-list-server/pull/585)

  > * fix: negotiate Accept per RFC 9110 for status list retrieval
  >
  > Resolve the Accept header per RFC 9110 §12.5.1 instead of matching it as
  > an exact string, so */*, wildcards, comma-separated ranges, q-values and
  > case-insensitive type/subtype all work. Serve the supported type with the
  > highest acceptable q (JWT wins ties and absent-header/wildcard cases);
  > return 406 with a body listing both supported media types only when no
  > supported type is acceptable.
  >
  > Correctness:an explicit q=0 exclusion now takes precedence over a
  > wildcard for its type (media-range specificity), so e.g.
  > `application/statuslist+jwt;q=0, */*` serves CWT rather than the
  > explicitly-excluded JWT. The q parameter name is case-insensitive, OWS
  > around `=` is tolerated, malformed weights are treated as excluded, and
  > out-of-range weights are clamped to [0,1].
  >
  > Caching:the 406 response now carries `Vary: Accept, Accept-Encoding` via
  > a new ApiError extra-header capability so shared caches never serve the
  > error to a client with a different Accept.
  >
  > Docs:update the OpenAPI Accept parameter and NotAcceptable response to
  > describe the negotiated behavior.
  >
  > Adds table-driven tests for every scope case plus the wildcard-vs-q0,
  > case-insensitive Q, OWS and malformed/out-of-range weight edge cases, and
  > extends the 406 integration test to assert Vary.
  >
  > * fix: harden Accept negotiation per RFC 9110 review
  >
  > Address reviewer feedback on the content-negotiation change:
  >
  > - Enforce three-tier wildcard precedence (exact > application/* > */*) so
  >   an explicit q=0 exclusion is never overridden by a wildcard.
  > - Read every Accept field line (RFC 9110 s5.3 folds them into one list).
  > - Parse q-values with plain decimals only: reject NaN, inf, sign and
  >   exponents while keeping the .2 shorthand.
  > - Move negotiation helpers to utils/negotiation.rs and share one weight
  >   parser between Accept and Accept-Encoding, fixing gzip;Q=0.
  > - Pass AcceptType through build_status_list_token; drop string
  >   re-matching in token.rs.
  > - Document the deliberately parameter-agnostic media-range policy (media
  >   parameters other than q are ignored) as a non-RFC deviation.
  > - Build the 406 message from the constants and advertise Vary on it.
  > - Fix RFC citations (RFC 9111 s4.1) and the stale Vary sentence in
  >   openapi.yaml; document Vary on the 406 response.
  > - Guard against silently overwriting Cache-Control/Retry-After in the
  >   ApiError extra-header loop.
  > - Add table cases for every fix plus /;q=0, empty list elements, a CWT-
  >   first tie and the legacy JDK header; make handler tests table-driven.
  > - Add ops notes on normalizing Accept at the CDN and signing load.
  >
  > * fix: address negotiation review (quoted parsing, strict qvalues)
  >
  > - negotiate_accept and client_accepts_gzip split commas/semicolons only at
  >   the top level, so a ',' or ';q=' inside a quoted media-parameter value is
  >   data, not a delimiter (RFC 9110 §5.3).
  > - qvalue rejects out-of-range weights (e.g. q=2, q=1.5) instead of clamping
  >   to 1.0; an invalid weight as the only match now yields 406 rather than the
  >   previously clamped-to-1 type.
  > - restore #582: build_status_list_token takes the record by value, dropping
  >   the re-introduced clone on the fresh-200 path.
  > - add handler regression for multi-line Accept folding; add gzip regressions
  >   for Q=0 and malformed q.
  > - use HeaderValue::from_static for the static media type and reword the Vary
  >   comment on the 406 path.
  >
  > * test: drop gzip Q= regression that missed the bug
  >
  > test_accepts_gzip_uppercase_q asserted Q=0.8 was accepted, which the
  > old q=-only parser also did (it ignored Q= and treated the entry as
  > having no q). Keep test_rejects_gzip_uppercase_q0, which covers the
  > actual bug the parser fix addresses: Q=0 must not serve gzip.
  >
  > * fix: address second negotiation review (q trailing dot, quoted parsing)
  >
  > - Accept q=1. and q=0. as valid per RFC 9110 0*3DIGIT; only a bare dot
  >   is malformed (add table cases for q=1. and q=.)
  > - Only open a quoted-string after '=' in top-level parsing so a stray
  >   quote no longer swallows the rest of the header
  > - Correct RFC reference for quoted media parameters (S5.6.4)
  > - Clarify Vary is on 200/304/406 only and the 406 is no-store
  >
  > * fix: restore find_top_level to single clean quoted-string parse
  >
  > The earlier review change was pasted in twice, leaving duplicated, nested
  > initializers and a nested loop that did not compile. Collapse to the single
  > intended version that only opens a quoted-string right after '=', so a stray
  > quote no longer swallows the rest of the range. Add a regression test that
  > text/"html, application/statuslist+jwt now resolves to JWT instead of 406.
  >
  > * fix: remove duplicated block in find_top_level unclosed delimiter

- [b1968c7](
https://github.com/adorsys/status-list-server/commit/b1968c7aea6641c626088eea913a5ff39db740b0) *(uncategorized)* Reject token lifetime values the spec forbids by @Christiantyemele in [#578](
https://github.com/adorsys/status-list-server/pull/578)

  > * fix: reject token lifetime values the spec forbids
  >
  > * fix(config): reject token_exp_secs that overflow iat per review
  >
  > * fix(helm): reject zero string token lifetime values per review
  >
  > * style(helm): format test args per cargo fmt
  >
  > * fix(config): guard token exp overflow at issuance per review
  >
  > * fix(helm): validate token lifetime via canonical env route per review
  >
  > * fix(config): cap token lifetime at one year per review
  >
  > * fix(token): fail closed on lifetime overflow via try_from per review
  >
  > * fix(helm): tighten token lifetime schema and add numeric zero test per review
  >
  > * docs(compliance): add ttl positive section 5.1 row per review
  >
  > * fix(docs): align compliance matrix row per markdownlint
  >
  > * refactor(domain): extract shared token_expiry helper per review
  >
  > * fix(token): fail closed on unrepresentable ttl via try_from per review
  >
  > * test(config): name failing overrides and assert ceiling message per review
  >
  > * fix(helm): cap token lifetime at one year in schema per review
  >
  > * docs(compliance): append ttl row at end and mark fixed per review

- [6def63e](
https://github.com/adorsys/status-list-server/commit/6def63e0f9d17f41d385ecf7325380b76f2990d2) *(uncategorized)* Reject empty PATCH and validate duplicate indices by @ndefokou in [#562](
https://github.com/adorsys/status-list-server/pull/562)

  > * fix: reject empty PATCH and duplicate indices in status updates
  >
  > Prevent empty PATCH requests ({statuses: []}) from advancing the status
  > list version and inserting duplicate history snapshots by rejecting them
  > at the service boundary with 400 empty_status_update. Reject update
  > payloads containing duplicate index values with 400 duplicate_index on
  > both PATCH and PUT.
  >
  > Request-shape validation (count, empty, duplicate, index bound) now runs
  > before any storage access, so these 400s take precedence over 404/403 and
  > a malformed request never triggers a wasted find or write. The domain
  > model retains the duplicate-index invariant as defense in depth.
  >
  > Documents the new error codes in OpenAPI, notes the empty-PATCH breaking
  > change in the changelog, and adds unit, service, and handler tests
  > including PUT duplicate rejection and error-precedence coverage.
  >
  > * style: reorder imports in domain service for consistency
  >
  > * fix: make empty and value-identical PATCHes successful no-ops
  >
  > Rejecting only the literal empty array with 400 empty_status_update left a
  > redundant-write and history-bloat hole: a non-empty update that re-set every
  > affected index to its current value still bumped updated_at and inserted a
  > duplicate snapshot. Compare the updated list with the current list after the
  > update and return a successful no-op when they are equal, so both the literal
  > empty payload and a value-identical update neither advance the version nor
  > insert a redundant history snapshot. This keeps the change non-breaking, so
  > release-plz's patch-level cut remains correct.
  >
  > Extract the shared count/index-bound validation used by publish and update,
  > drop the empty-request error code and its precedence claims from the docs, and
  > add router-level raw-JSON coverage plus repo-level no-op tests (reading
  > updated_at from the repo rather than the cache).
  >
  > * fix(ci): fix pipeline
  >
  > * test: cover no-op and duplicate-index edge cases from review feedback
  >
  > Address review comments on the empty/value-identical PATCH no-op and duplicate-index work:
  > - run the no-op check before the serialized-size check so an unchanged list never
  >   trips TooLarge and update_statuses short-circuits first
  > - correct the doc comment to match the code ordering (count bound, index bound,
  >   duplicate indices) and drop the stale #484 reference
  > - add service tests pinning the duplicate-after-index-bound ordering, the mixed
  >   changed/unchanged update, and the past-end VALID index write
  > - add domain tests for a duplicate negative index, non-adjacent duplicates, and
  >   value-identical update on a legacy-width row
  > - assert snapshot stability and cache retention in the handler no-op tests, and
  >   restore empty-PATCH coverage for a non-owner and a missing list
  > - file PUT duplicate rejection and the removed history heartbeat in the CHANGELOG
  >
  > * chore: revert manual CHANGELOG.md changes from PR branch
  >
  > * test: fix flaky revalidation metrics outcome labels test
  >
  > Revalidate at the same now0 instant instead of now0+60 so the wall-clock-anchored token window cannot roll over in between, which could turn the expected 304 into a fresh 200 depending on the time of day.
  >
  > * Revert "test: fix flaky revalidation metrics outcome labels test"
  >
  > This reverts commit 018c804c23ce5b86bbffdb4d80c570d8aa918b48.
  >
  > * style: reorder imports in domain service
  >
  > * fix: make unchanged PATCHes a no-op and reject duplicate status indices

- [ab15624](
https://github.com/adorsys/status-list-server/commit/ab1562423f500b2119c53d9d82a33be29b8216cd) *(uncategorized)* Prevent 304 Not Modified when client JWT has expired by @ndefokou in [#556](
https://github.com/adorsys/status-list-server/pull/556)

  > * fix: return fresh token on revalidation of expired JWT
  >
  > Prevent GET /status-lists/{list_id} from returning 304 Not Modified with an
  > empty body when the client's cached Status List Token has expired.
  >
  > Factor token expiration into conditional revalidation by anchoring the cached
  > token's validity window at updated_at + token_exp_secs (the same horizon the
  > historical snapshot uses). When an If-None-Match match coincides with an
  > already-expired cached token, bypass the 304 and return a freshly signed
  > 200 OK token, per RFC 9110 §8.8.1. Unmodified revalidation within the token's
  > validity period still returns 304 efficiently.
  >
  > Adds unit tests in conditional.rs and handler tests covering both an expired
  > token (fresh 200) and a still-valid token (304).
  >
  > * fix(ci): fix pipeline
  >
  > * fix(cache-revalidation): drop immutable cache directive and label expiry re-signs
  >
  > Address review findings on the conditional-revalidation fix:
  >
  > - Remove the `immutable` directive from the live response's Cache-Control.
  >   Live status-list tokens expire and their validators rotate, so a
  >   freshness-honouring cache/browser must still revalidate to obtain a fresh,
  >   unexpired token instead of serving a stale body forever (RFC 9111 §5.2.2.4).
  >   Historical snapshots keep `immutable`: they are time-anchored and never change.
  >
  > - Distinguish expiry-forced re-signs from content-change re-signs. Reintroduce a
  >   dedicated ConditionalResponse::ExpiredToken outcome and emit it on the
  >   `conditional_revalidation_total` metric, so operators can detect a config
  >   regression that silently turns every conditional GET into a full re-sign.
  >
  > Happy-path 304 behaviour is unchanged. Unit and handler tests updated to assert
  > the new ExpiredToken outcome.
  >
  > * style: apply cargo fmt to get_status_list
  >
  > rustfmt-clean the build_fresh_200_response helper introduced in the
  > cache-revalidation fix so the CI cargo-fmt gate passes.
  >
  > * refactor(cache-revalidation): use E-ttl window for 304 certification
  >
  > Adopt a validity window of length W = E - ttl for the live ETag so a
  > matching validator always leaves more than ttl of usable lifetime on the
  > cached token, letting the window rollover enforce the expiry boundary.
  > Drop the now-redundant runway branch in evaluate_conditional_request and
  > guard degenerate configs (E == 0 or ttl >= E) so a 304 is never certified.
  >
  > Also trim excess comments, drop the duplicate instrument span on
  > get_status_list_at, fix the immutable cache-directive explanation, and
  > align the OpenAPI spec with the actual E-ttl rules and claim names.
  >
  > Add tests for the CWT path, gzip handling on forced re-signs, revalidation
  > at the window boundary, degenerate ttl configs, the ExpiredToken 200
  > headers, content-change + window rollover, and the revalidation metric
  > outcome labels.

### Refactor

- [0b8daec](
https://github.com/adorsys/status-list-server/commit/0b8daec7c559082555b6dc0e1ef9551864f1ac39) *(deploy)* Consolidate helm and observability assets under deploy/ by @Ngha-Boris in [#545](
https://github.com/adorsys/status-list-server/pull/545)

  > * feat(observability): add webhook notifications guide and SLO definitions
  >
  > * fix: update paths in YAML configuration and README for consistency
  >
  > * fix: update formatting in SLO README for clarity and consistency
  >
  > * fix: correct REPO_ROOT path in test-alertmanager-config.sh for accurate directory resolution
  >
  > * refactor: helm chart directory structure and update CI/CD workflows
  >
  > ---------

- [28e30d3](
https://github.com/adorsys/status-list-server/commit/28e30d372528958d3bd4624963df22393daaec1b) *(uncategorized)* Consolidate Azure modules under outbound::azure by @Christiantyemele in [#580](
https://github.com/adorsys/status-list-server/pull/580)

  > * refactor: consolidate Azure modules under outbound::azure
  >
  > Move DefaultAzureCredential and the Azure Key Vault adapter out of their
  > standalone top-level modules (azure_identity, azure_kv) into a unified
  > outbound::azure submodule. Update the two consumers of DefaultAzureCredential
  > and the AzureKeyVaultClient call sites to the new paths. No behavior change.
  >
  > * style: run cargo fmt on azure_keyvault test import
  >
  > * fix: gate rotation and file watcher modules per feature set
  >
  > Address review feedback: azure enables acme, so the database/token
  > rotation and file-watcher code is compiled out and was producing unused
  > code warnings under --features azure. Gate mod file_watcher and the
  > rotation metrics on the same conditions as their callers in setup.rs.
  > Also gate the Gcloud DNS handler assertion on feature gcp so
  > cargo test --features azure passes.
  >
  > * refactor(azure): re-export kv types and hide identity per review
  >
  > Address review feedback: re-export AzureKeyVaultClient and
  > AzureKeyVaultClientBuilder from outbound::azure so the path matches the
  > other backends (outbound::aws::AwsSecretsManager), make identity
  > pub(crate) since it is only used inside the crate, and add a module doc.
  > Also log a warning when AZURE_* variables are present but the
  > ClientSecretCredential cannot be constructed, and fail startup on an
  > incomplete service-principal configuration.
  >
  > * fix: scope token signing key const to its consumers
  >
  > Only define TARGET_TOKEN_SIGNING_KEY when a consumer exists: the cert
  > rotation watcher (not acme) or the rotation metrics test (database
  > feature under test). This keeps single-cloud builds such as
  > postgres,azure,redis warning-free in both lib and test targets.
  >
  > * ci: compile test targets for single-cloud image feature set
  >
  > The all-features nextest and clippy jobs cannot catch feature-combination
  > regressions that only appear with a single cloud backend enabled (such as
  > the unused-code warnings and test gating fixed in this PR). Add a
  > single-cloud job that compiles the test targets for the shipped
  > postgres,azure,redis Docker image variant, gated by ci-success.
  >
  > * style: run cargo fmt
  >
  > * fix(ci): gate SQL store integration tests on backend features
  >
  > * fix(azure): preserve AKS workload identity and reject partial SP config
  >
  > * test(azure): strengthen workload identity and partial SP coverage per review
  >
  > * style(azure): format partial SP test assertion
  >
  > * ci(azure): drop single-cloud test-compile matrix per review
  >
  > * refactor(azure): hide kv module and make identity tests hermetic
  >
  > * style(azure): rustfmt identity module
  >
  > * feat(azure): log selected identity chain at startup
  >
  > * test(azure): use tempdir and pin dual-source identity ordering
  >
  > * refactor(metrics): document not(acme) rotation-metrics gating
  >
  > * docs: note Azure partial-SP fail-closed behavior change
  >
  > * chore(supply-chain): exempt tempfile dev-dependency from cargo vet
  >
  > * revert: drop manual CHANGELOG note on Azure partial-SP behavior per review
  >
  > * revert: remove file_watcher feature gating per review
  >
  > * revert: restore SQL store tests to cfg(test) per review
  >
  > * revert: remove rotation metrics feature gating per review
  >
  > ---------

- [4f4461f](
https://github.com/adorsys/status-list-server/commit/4f4461f5b5c15504172b5bb30391575782d82be1) *(uncategorized)* Split store.rs tests into concern-based modules by @Christiantyemele in [#506](
https://github.com/adorsys/status-list-server/pull/506)

  > * refactor: split store.rs tests into concern-based modules
  >
  > Move the ~2,600 lines of #[cfg(test)] content out of src/outbound/sql/store.rs
  > into store/tests/{fixtures,credentials,status_list,history,contention}.rs,
  > consolidating duplicate sqlite/mysql/postgres tests into shared assert_*
  > helpers. No production code changed; the implementation stays in store.rs
  > with a thin #[cfg(test)] mod tests; re-export.
  >
  > * refactor: rename imp module to database_implementation in contention tests
  >
  > * refactor(store): trim verbose test comments and move mod tests per review
  >
  > * refactor(store): remove redundant test module doc comment per review
  >
  > * refactor(store): move test module declaration to top of file per review

### Documentation

- [b26a55a](
https://github.com/adorsys/status-list-server/commit/b26a55ae5395f40ea4d793ba8b182ef7cb89c0d6) *(adr)* Add an ADR template and record the issuer trust decision by @Hermann-Core in [#635](
https://github.com/adorsys/status-list-server/pull/635)

  > * docs(adr): record issuer trust, onboarding and access control decision
  >
  > * docs(adr): distinguish a missing token from an invalid one
  >
  > * docs(adr): reduce ADR-0002 to its decision and invariants
  >
  > * docs(adr): add an ADR template
  >
  > * docs(adr): drop the contract from ADR-0002's references
  >
  > * docs(adr): let the management listener share the public hostname

- [0f2ffcb](
https://github.com/adorsys/status-list-server/commit/0f2ffcb519db9439653e8202ebea36009726f44d) *(helm)* Expand chart value and template documentation by @ndefokou in [#563](
https://github.com/adorsys/status-list-server/pull/563)

  > * docs(helm): expand chart value and template documentation
  >
  > Comprehensively document every configurable property in values.yaml
  > and mirror the descriptions/titles into values.schema.json. Cover
  > multi-cloud Workload Identity (EKS, GKE, AKS), digest-vs-tag image
  > resolution, multi-database backends (postgres/mysql), External Secrets
  > Operator vs fallback Secret delivery, and SLO/observability settings.
  >
  > Add top-level podAnnotations value (previously template-referenced but
  > undocumented) and clarify the postgres backend default/failure behavior
  > and the footgun of disabling postgres without switching the backend.
  >
  > Document template logic in deployment.yaml, network-policy.yaml,
  > secret.yaml, prometheusrule.yaml, and _helpers.tpl:
  >
  > - deployment.yaml: render-time guard rails (secret delivery exclusivity,
  >   backend validation, image resolution, URL/PASSWORD rejection), replica
  >   omission under HPA, and pod annotation emission.
  > - network-policy.yaml: ingress any-source default, egressInternal
  >   inheriting the database port, unrestricted 443/53 egress, and OTLP
  >   scoping.
  > - secret.yaml: two-key password reconciliation, lookup-based reuse across
  >   upgrades, GitOps regeneration caveat, and resource-policy: keep survival.
  > - prometheusrule.yaml: hard-coded alert summaries and %.3f rounding that
  >   are not CI-covered, and the certRenewalFailureMax value that is unused.
  >
  > helm lint and all example overlay renders pass.
  >
  > * docs(helm): address review feedback on chart documentation
  >
  > Expand helper comments in _helpers.tpl (serviceAccountName name derivation
  > and Workload Identity trust, dbBackend consumers and render-time failure,
  > dbUsername/dbName env var names and fallback sources), add the missing
  > top-level opentelemetry-collector property to values.schema.json, align the
  > podAnnotations comment with the schema value types, warn that mysql.enabled
  > is not a valid field in values.yaml, and replace ASCII-unsafe em dashes with
  > hyphens throughout chart comments.

- [2d15b21](
https://github.com/adorsys/status-list-server/commit/2d15b21df9c68df829f685dd2b762512dfaa7225) *(perf)* Make the performance-test workspace discoverable and harness-agnostic by @ndefokou in [#637](
https://github.com/adorsys/status-list-server/pull/637)

  > * refactor(perf): rename artillery-tests workspace to perf
  >
  > * docs(perf): make the perf workspace documentation harness-agnostic
  >
  > * docs(perf): clarify harness-agnostic framing of the perf workspace
  >
  > - Retitle the performance-test README as 'Performance / load-validation tests'
  > - Add a note that swapping the harness only touches the npm scripts and the
  >   scenario files, keeping the workspace layout and generated-file contract
  >   tool-agnostic
  > - Qualify the LIVE_TESTING simulation token path as perf/scripts/test-tokens.json
  >
  > * docs(perf): fix MD028 by merging adjacent blockquotes
  >
  > markdownlint MD028 flags a blank line inside a blockquote when two
  > adjacent blockquotes are separated by a blank line. Merge the
  > 'Swapping the harness' and 'Performance vs correctness' callouts into
  > a single blockquote to satisfy the CI markdownlint check.
  >
  > * docs(perf): address review feedback on perf workspace README
  >
  > * docs(perf): reference package.json for Node requirement in prerequisites

### Performance

- [c4282f2](
https://github.com/adorsys/status-list-server/commit/c4282f2245990579d44693f8eb6f318c9d01147e) *(uncategorized)* Cache pre-parsed CWT x5chain and eliminate token clone allocations by @ndefokou in [#582](
https://github.com/adorsys/status-list-server/pull/582)

  > * perf: cache pre-parsed CWT x5chain and eliminate token clone allocations
  >
  > Eliminate repetitive base64 certificate chain decoding in the CWT signing hot path by caching pre-parsed DER bytes and CBOR x5chain structures on the certificate state, and move certificate ownership directly into the dedicated CWT and JWT signing functions without copying or cloning.
  >
  > - SigningMaterial now carries pre-decoded DER bytes (cert_chain_der) and the pre-built CBOR x5chain value, derived once at load/renewal time instead of on every request.
  > - issue_cwt consumes the pre-built x5chain by value, completely bypassing base64::decode during request handling.
  > - get_active_certificate() returns owned certificate components (CertificateComponents) so issue_cwt/issue_jwt take ownership and move certs_parts into the selected signing function with zero clone allocations.
  > - Added an ignored CWT throughput benchmark and extended the CWT test to assert a spec-compliant x5chain protected header.
  >
  > * fix(ci): retry transient LocalStack image-pull failures in ACME tests
  >
  > The ACME provisioning integration tests intermittently fail to start LocalStack with 'bytes remaining on stream' — a truncated Docker image pull for the large localstack/localstack:4.14 image. This is a transient registry/network failure, not a code defect.
  >
  > Add a bounded retry around the LocalStack startup that retries only image-pull errors (matching the retry-loop pattern already used in the codebase). Non-pull failures still surface immediately.
  >
  > * refactor: keep certificate snapshot transport-agnostic and reject malformed chains
  >
  > Address review feedback on the CWT x5chain hot-path optimization:
  >
  > - Remove CWT/COSE state (cert_chain_der, x5chain, CertificateComponents,
  >   get_active_certificate) from the generic CertificateProvider port;
  >   SigningMaterial now holds only base64 certificate chain and signer, and
  >   the CBOR x5chain is derived and cached in the CWT issuer
  > - Drop the per-request deep clone of CWT fields; JWT no longer copies
  >   unused CWT representations and only the encoder-selected form is built
  > - Make SigningMaterial::new fallible and validate base64 chain parts at
  >   construction, so a malformed chain is rejected at load/renewal time
  >   instead of silently surfacing as absent CWT material
  > - Remove the hardware-dependent tokens/sec benchmark unit test in favor of
  >   real JWT/CWT signature and header tests
  > - Revert the LocalStack image-pull retry from this PR (split into its own
  >   CI flake fix)
  >
  > * perf: return Arc signing material and eliminate per-request token copies
  >
  > Address review feedback on the CWT/JWT hot-path optimization:
  >
  > - CertificateProvider::signing_material now returns Arc<SigningMaterial> so
  >   providers no longer deep-clone the chain on every request; token encoders
  >   move the cheap Arc into spawn_blocking and borrow the material inside it
  > - build_status_list_token takes an owned StatusListRecord from the caller,
  >   removing the hot-path status_record.clone()
  > - classify the Accept header into a &'static str once instead of allocating
  >   accept.to_string() on each request
  > - SigningMaterial::new rejects empty certificate chains (which previously
  >   produced an invalid Array([]) x5chain) alongside malformed base64, with
  >   unit tests
  > - a missing/broken certificate chain is now a Backend (500) with an error
  >   log rather than a retryable Unavailable (503); update the runbook
  >
  > * style: apply cargo fmt to recent changes
  >
  > * refactor: address review comments on CWT x5chain optimization
  >
  > - Replace global-lock cached_x5chain with pre-decoded DER stored on
  >   SigningMaterial (Arc<[Box<[u8]>]>), removing per-request lock,
  >   base64 comparison, and deep copy
  > - Drop duplicate tracing::error! in missing_chain_error
  > - Match token format via TokenFormat enum instead of raw strings
  > - Take signer as &(impl TokenSigner + ?Sized) instead of Arc by value
  > - Preserve original error cause in CertError::Validation via #[source]
  > - Assert x5chain value equals DER bytes in CWT test and add
  >   single/multi-cert x5chain tests
  >
  > * docs: fix unresolved intra-doc link to SigningMaterial
  >
  > * refactor!: enforce signing-material invariants and add CWT benchmark
  >
  > SigningMaterial now keeps its two certificate views private and exposes
  > them through accessors so they can never fall out of sync, and its
  > constructor rejects empty chain entries in addition to an empty chain.
  >
  > CertificateProvider::signing_material returns Arc<SigningMaterial> and
  >
  > SigningMaterial::new returns Result, so external struct-literal
  > construction and trait implementations are broken; CertError::Validation
  > now boxes the underlying cause instead of a String. These public API
  > changes require a breaking release.
  >
  > Also preserve error causes in the cert manager (strategy and http client)
  > by passing them to CertError::Validation(Box::new(..)), surface a missing
  > chain as a 500 Backend for both CWT and JWT, and add a documented
  > provider-to-token CWT benchmark harness (examples/cwt_bench.rs).
  >
  > * docs: trim SigningMaterial and test-state comments

### Testing

- [ddabe92](
https://github.com/adorsys/status-list-server/commit/ddabe9225741cd4311bb5edeaf3acb95b38e6a32) *(uncategorized)* Add draft-21 status-list conformance coverage by @Ngha-Boris in [#605](
https://github.com/adorsys/status-list-server/pull/605)

  > * feat: add libz-sys dependency and update flate2 configuration
  >
  > * fix: address spec conformance review feedback
  >
  > * test: move conformance suite into tests directory
  >
  > * test: exercise production server in conformance suite
  >
  > * test: cover configured HTTP flows without compatibility changes
  >
  > * chore: remove unnecessary blank line in upgrade notes section of CHANGELOG.md
  >
  > * test: isolate conformance fixtures and restore production setup
  >
  > * test: simplify conformance documentation and server cleanup

### Miscellaneous Tasks

- [c7a6e20](
https://github.com/adorsys/status-list-server/commit/c7a6e20ff8db859c080be2d5c02ff0ab3836af54) *(uncategorized)* Restore the changelog to its state on main by @Hermann-Core in [#686](
https://github.com/adorsys/status-list-server/pull/686)

  > The changelog is generated automatically at release time, so the sync
  > should not carry develop's hand-written entries into it.
  >
  > Co-Authored-By:Claude Opus 5.5 <noreply@anthropic.com>

- [29d3503](
https://github.com/adorsys/status-list-server/commit/29d35036f22f56b82596173a29672fd35b15756f) *(uncategorized)* Sync develop into main by @Hermann-Core in [#686](
https://github.com/adorsys/status-list-server/pull/686)

  > Bring main up to date with the work accumulated on develop.
  >
  > Conflict resolution:
  > - Cargo.toml: keep main's 1.2.0 package version and take develop's
  >   dev-dependencies (sea-orm 2.0 to match the runtime dependency, tempfile).
  > - CHANGELOG.md: keep develop's Unreleased section on top of main's
  >   released 1.2.0, 1.1.2, 1.1.1 and 1.1.0 entries.
  >
  > Co-Authored-By:Claude Opus 5.5 <noreply@anthropic.com>

- [baacc3c](
https://github.com/adorsys/status-list-server/commit/baacc3c17fd79f16e1cfee8a78f9da20715f6799) *(uncategorized)* Upgrade artillery test dependencies and fix script paths by @ndefokou in [#528](
https://github.com/adorsys/status-list-server/pull/528)

  > * chore: upgrade artillery test dependencies and fix script paths
  >
  > - Bump artillery, jsonwebtoken, and artillery-plugin-metrics-by-endpoint to latest
  > - Fix npm scripts to reference ./tests/*.yml and results/*.json
  > - Resolve token-generator paths via __dirname and replace deprecated substr()
  >
  > * fix(artillery-tests): address review feedback for perf test tooling and scripts
  >
  > - ignore results/ so generated multi-MB JSON reports stay out of git status
  > - drop deprecated 'artillery report' from :report scripts (does nothing)
  > - replace Windows-incompatible 'mkdir -p results' with a cross-platform
  >   node -e mkdirSync call
  > - write keys and tokens atomically (temp file + rename); stop caching the
  >   private key in test-tokens.json
  > - read the credential JWK from test-tokens.json only so the key can never
  >   disagree with the signed JWTs
  > - use integer status codes (0/1/2) instead of strings so payloads no longer
  >   return 422, and enable the ensure plugin so thresholds are enforced
  > - fix the mis-indented expect block in stress-test.yml
  > - update how-to-run.md and LIVE_TESTING.md 7b for the new script paths and
  >   document the rate-limit env overrides the suite needs
  >
  > * fix(artillery-tests): address review feedback on perf tooling and auth
  >
  > - Token lifetime now respects the server's 3600s max (was 365 days), fixing
  >   every authenticated request returning 401
  > - Register the test issuer + seed real status lists once before each run via
  >   scripts/setup.js (the Artillery before: hook cannot run processor function
  >   steps in this version), removing the registration race in auth-test.yml
  > - Drop unneeded ec-private-key.pem/ec-public-key.jwk outputs; write only
  >   test-tokens.json atomically with mode 0600
  > - Remove unused artillery-plugin-statsd and redundant metrics-by-endpoint
  > - Read scenarios use published/seed list IDs instead of random IDs that never
  >   exist, sending the required Accept: application/statuslist+jwt header
  > - Replace unsupported responseTime and always-passing equals checks
  > - Document rate limits per suite (high enough for stress/spike) and correct the
  >   Node >= 22.18.0 requirement (package.json engines + docs)
  > - Fix observability/LIVE_TESTING.md issuer-key wording and generated-file set

### Continuous Integration

- [ef3ce2a](
https://github.com/adorsys/status-list-server/commit/ef3ce2a3c19f0a87abe22b54bae5cbfed00ffb13) *(workflows)* Extract helm checks into dedicated helm-checks workflow by @ndefokou in [#606](
https://github.com/adorsys/status-list-server/pull/606)

  > * ci(workflows): extract helm checks into dedicated helm-checks workflow
  >
  > Move the Helm chart rendering, linting and Kubernetes templating validation
  > jobs (trivy-config, helm-template-local, kube-linter,
  > otel-config-validation, prometheus-rules-validation) out of CI.yml and into
  > a new .github/workflows/helm-checks.yml that runs only when deploy/helm/**
  > or the workflow itself changes, so pure Rust PRs do not pay for Helm
  > feedback.
  >
  > Wire the new workflow into deploy.yml as a called job with the SARIF upload
  > scope kube-linter needs, add Helm Checks Success to the branch-protection
  > and documentation model alongside CI Success, and re-point stale comments
  > and docs that referenced the moved jobs from CI.yml to helm-checks.yml.
  >
  > * fix(ci): restore local-ci tests and move repo-wide guards to CI.yml
  >
  > Address review feedback on the helm-checks extraction:
  >
  > - Restore the local-ci-tests job in CI.yml (it was dropped during the
  >   develop merge) and re-add it to ci-success.needs, so the committed
  >   scripts/local-ci tests are exercised again.
  > - Revert an unrelated zizmor self-test change ([[ ]] glob -> grep -q)
  >   to keep the PR focused on the Helm extraction.
  > - Move the two repo-wide guards (Validate .trivyignore.yaml and the
  >   image-variant parity assertion) out of helm-checks.yml's trivy-config
  >   and into a new CI.yml config-guards job that runs on every pull
  >   request. helm-checks.yml only triggers on deploy/helm/** changes, so
  >   those guards no longer fired for pure-Rust PRs.
  > - Update docs/supply-chain.md and scripts/check-trivyignore.py to point
  >   at the new config-guards job.
  >
  > * fix(local-ci): check helm-checks.yml for extracted image and tool pins
  >
  > The helm-checks extraction moved the Helm/observability image pins
  > (OTEL_COLLECTOR, PROMETHEUS, JAEGER), the kube-linter SHA/version, and
  > the trivy-action reference out of CI.yml and into the path-gated
  > helm-checks.yml. The test_ci_versions_match_local_pins regression test
  > still only read CI.yml, so it failed to find those pins.
  >
  > Update the test to also read helm-checks.yml and assert each pin against
  > the workflow that now owns it, and check the Helm version across both
  > workflows. Also verify the azure/setup-helm version in helm-checks.yml.
  >
  > * fix(ci): run helm-checks on every PR so helm-success always reports
  >
  > The helm-checks workflow was path-gated on pull_request (deploy/helm/**),
  > so a pure-Rust PR never triggered it and the required 'Helm Checks Success'
  > check stayed in 'Expected - Waiting for status to be reported', blocking the
  > merge indefinitely. Run the workflow on every PR instead, gate the five
  > expensive jobs behind a dorny/paths-filter 'changes' job (with a guard that
  > forces them to run on push, workflow_call and workflow_dispatch so deploy.yml
  > still always gets Helm feedback), and let helm-success aggregate them. GitHub
  > treats skipped jobs as non-blocking, so helm-success always reports and merge
  > can proceed.
  >
  > Also correct the scheduled-image-scan comments that pointed at helm-checks.yml's
  > trivy-config for the PyYAML import guard; that guard lives in CI.yml's
  > config-guards job. Update CONTRIBUTING.md to describe the new trigger.
  >
  > * ci(helm-checks): widen helm gate to all consumed inputs and update branch-protection runbook
  >
  > Review fixes:
  > - Widen the changes filter and push.paths trigger to cover every input the
  >   validation jobs consume: deploy/observability/**, the render-helm-templates
  >   action and its scripts, .kube-linter.yaml, .trivyignore.yaml, and the
  >   check-helm-prometheus / check-dashboard-drift / verify-image-reference
  >   helper scripts, so broken observability config or a broken validator can no
  >   longer merge while helm-success reports green.
  > - Correct the CONTRIBUTING branch-protection snapshot: CI Success is already
  >   required on both develop and main (develop also requires Conventional
  >   Commits), so the rollout step now adds only the new Helm Checks Success
  >   requirement.
  >
  > * docs: simplify branch-protection runbook
  >
  > * ci(config-guards): shorten job placement comment

- [5987eb9](
https://github.com/adorsys/status-list-server/commit/5987eb97b48379b00165d6f9a747fecfed3c7bd8) *(uncategorized)* Add Trivy vulnerability database caching with staleness handling by @martcpp in [#530](
https://github.com/adorsys/status-list-server/pull/530)

  > * ci: add Trivy vulnerability database caching with staleness handling
  >
  > - Add explicit actions/cache step for Trivy DB in deploy.yml and scheduled-image-scan.yml
  > - Add ensure-trivy-db.sh script to refresh DB or degrade to cached version with warnings
  > - Add .trivy.yaml config to skip DB updates during scan
  > - Document cache strategy and staleness bounds in supply-chain.md
  > - Cache key uses run ID with restore-keys fallback to most recent DB
  > - 24-hour staleness bound matches Trivy's up-to-date threshold
  > - Degrades with warning if cached DB within bound, hard-fails beyond bound
  >
  > * fix(ci): prevent cache poisoning on Trivy DB cache in deploy.yml
  >
  > Split the actions/cache restore+save into actions/cache/restore and a
  > conditional actions/cache/save (github.event_name == 'push'), so the
  > cache-write path is explicit and gated to trusted triggers rather than
  > implicit in actions/cache's always-run post-step.
  >
  > Fixes zizmor cache-poisoning finding at deploy.yml:297.
  >
  > * style(ci): fix yamlfmt formatting in deploy.yml
  >
  > * fix(ci): scope Trivy DB cache save to one leg and drop .trivy.yaml
  >
  > * fix(ci): install kube-linter with retries and checksum instead of kube-linter-action

**Full Changelog**: https://github.com/adorsys/status-list-server/compare/v1.2.0...v2.0.0



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

