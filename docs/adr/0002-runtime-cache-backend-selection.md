# ADR 0002: Runtime Cache Backend Selection

## Status

Accepted

## Context

The original status-list cache ticket described compile-time selection through
cache-specific backend features. During implementation, the server already
needed one release image per certificate/database provider, while the cache
backend is an operational deployment choice. Helm and Docker Compose also select
cache settings through environment variables.

## Decision

Status-list cache backend selection is runtime configuration via
`APP_CACHE__BACKEND=memory|redis`. Release images include the `redis` Cargo
feature, and the default backend remains `memory`. A binary built without the
`redis` feature fails startup if configured with `APP_CACHE__BACKEND=redis`.

This keeps one image usable for memory-only and Redis-backed deployments while
preserving an explicit compile-time gate for the Redis dependency.

## Consequences

- Operators can switch from memory to Redis without changing image variants.
- Redis configuration must still be validated at startup.
- CI must continue checking `--all-features` and a memory-only build.
- Documentation and release metadata must describe runtime selection, not
  mutually exclusive cache backend features.
