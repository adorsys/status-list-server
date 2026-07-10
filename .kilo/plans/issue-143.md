# Plan: Make Database Configurable and Selectable (#143)

## Objective

Make the database layer configurable so users can choose from any database supported by sqlx (PostgreSQL, MySQL, SQLite, MariaDB).

## Current State

- `Cargo.toml` - uses `sea-orm` with `sqlx-postgres` feature only
- `src/config.rs` - has `DatabaseConfig` with just `url: SecretString`
- `src/database/mod.rs` - migrations using sea-orm-migration with Postgres-specific columns
- `src/database/queries.rs` - uses SeaOrm with Postgres backend in tests
- `src/utils/state.rs` - connects via `Database::connect(url)`
- `docker-compose.yml` - only provisions Postgres
- `.env.template` - only contains Postgres config

## Deliverables

### 1. Add `DatabaseBackend` enum to config (`src/config.rs`)

- Create `DatabaseBackend` enum with variants: `Postgres`, `MySql`, `Sqlite`, `Mariadb`
- Add `database.backend` config key with default "postgres"
- Add validation that URL scheme matches the backend type

### 2. Update Cargo.toml with multi-database features

- Add feature flags: `database-postgres`, `database-mysql`, `database-sqlite`, `database-mariadb`
- Keep `database-postgres` as default
- Enable appropriate sea-orm features per backend

### 3. Update database connection in `src/utils/state.rs`

- Implement `Database::connect()` with backend-aware selection
- Use runtime backend selection (not compile-time features) for flexibility

### 4. Audit and fix database compatibility issues

- Replace Postgres-specific `JSON` column type with `DbBackend::Json` which adapts to backend
- Update migrations to use backend-agnostic column types
- Fix `src/database/queries.rs` test to use `DatabaseBackend::Sqlite` for mock database

### 5. Update docker-compose.yml

- Add support for MySQL service
- Add support for SQLite as in-memory option
- Create separate compose file for different backends
- Implement least-privilege user pattern: separate migration vs application user

### 6. Update `.env.template`

- Add `APP_DATABASE__BACKEND` config option
- Add MySQL configuration options
- Document backend switching

## Implementation Order

1. Update `src/config.rs` with `DatabaseBackend` enum
2. Update `Cargo.toml` with feature flags
3. Update `src/utils/state.rs` for backend selection
4. Update `src/database/mod.rs` for cross-DB compatibility
5. Update `src/database/queries.rs` tests
6. Update `docker-compose.yml`
7. Update `.env.template`
8. Run CI checks
9. Commit and push

## Modified Files

- `src/config.rs`
- `Cargo.toml`
- `src/utils/state.rs`
- `src/database/mod.rs`
- `src/database/queries.rs`
- `docker-compose.yml`
- `.env.template`