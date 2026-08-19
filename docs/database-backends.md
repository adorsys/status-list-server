# Database Backend Guidance

The server validates the configured database backend at startup and supports the following runtime choices:

- `postgres`
- `mysql`
- `sqlite`

MariaDB is not a separate backend in this codebase. If you run MariaDB-compatible infrastructure, configure the app with `APP_DATABASE__BACKEND=mysql` and a `mysql://` URL.

## Recommended Use

### PostgreSQL

Best default for production deployments. PostgreSQL is the safest choice when you need:

- mature HA tooling
- managed cloud offerings
- strong transactional guarantees
- straightforward backup and restore workflows

### MySQL

Good fit when your infrastructure already standardizes on MySQL-compatible services or when you want a production database with familiar operational patterns. For MariaDB, use this same backend setting because the driver path is shared.

### SQLite

Best for local development, fast unit and integration tests, and simple single-node deployments.

SQLite is not a distributed database, so it is not a good match for horizontally scaled production storage. For in-memory tests, use a shared-cache URI such as `sqlite::memory:?cache=shared` and a single-connection pool.

## Transaction Isolation

Every client-facing write — publishing a list, updating one, the snapshot each writes alongside it, and credential registration — runs in a transaction pinned to **READ COMMITTED** on PostgreSQL and MySQL. The level is set by the application, not inherited from the server, so both backends behave identically instead of running at their differing defaults (PostgreSQL READ COMMITTED, InnoDB REPEATABLE READ).

The one write that is **not** pinned is the retention sweep (`delete_older_than`); see _Other notes_ below.

The guard itself does not depend on this. The guarded update is `UPDATE ... WHERE list_id = ? AND updated_at = ?`, a compare-and-set whose match count decides the outcome. That is a current read on both engines, so it sees the latest committed row at either level, and no write transaction issues a `SELECT` whose view could go stale.

Pinning buys two things.

**Independence from server configuration.** If an operator raises the global default:

```sql
-- PostgreSQL
ALTER SYSTEM SET default_transaction_isolation = 'serializable';
-- MySQL
SET GLOBAL transaction_isolation = 'SERIALIZABLE';
```

then without the pin these transactions would inherit it, and a routine race between two writers — normally a clean `409 update_conflict` telling the client to re-read — would instead surface as a serialization failure. Note that this is deliberately **not overridable**: the compare-and-set is the concurrency mechanism here and it wants READ COMMITTED, regardless of what else shares the database.

**Materially fewer deadlocks on MySQL.** This is the larger effect in practice, and it applies to every stock MySQL deployment, not just misconfigured ones — REPEATABLE READ _is_ the InnoDB default. At REPEATABLE READ InnoDB takes next-key (gap) locks; at READ COMMITTED it locks index records only. Concretely: every snapshot insert writes `exp = now + token_exp_secs`, so concurrent inserts for unrelated lists land in the same gap of `idx_status_list_history_exp`, while the retention sweep deletes a range of that same index. Those are the ingredients of an insert-intention deadlock. Pinning removes the gap locks and with them that entire class of `1213`.

### MySQL: binary logging must be ROW or MIXED

InnoDB at READ COMMITTED requires row-based binary logging. Under `binlog_format = STATEMENT` the server rejects these writes with error **1665** (`ER_BINLOG_STMT_MODE_AND_ROW_ENGINE`).

The server checks this at startup and **refuses to boot** if it finds `STATEMENT`, rather than letting the misconfiguration surface as a `500` on the first publish. MySQL 8.0 defaults to `ROW`, and `MIXED` is also fine (it promotes these statements to row format automatically), so this only affects deployments that set `STATEMENT` deliberately:

```sql
SET GLOBAL binlog_format = 'ROW';  -- then restart the server
```

### Other notes

- **SQLite is unaffected.** It has no per-transaction isolation level, so none is requested there.
- **The retention sweep is not pinned.** `delete_older_than` runs as batched autocommit statements and inherits the server default. It is the likeliest deadlock victim in the system — it sweeps a range of `idx_status_list_history_exp` while snapshot inserts write into the top of that range — so its errors are classified too: a deadlock there is a retryable classification the scheduler logs at `warn`, and the next run cleans up whatever the aborted batch left.
- **Pinning costs three extra round trips per write.** sea-orm issues the isolation level as its own statement, so a write that was one autocommit statement becomes `SET TRANSACTION`, `BEGIN`, the statement, `COMMIT`. That is the price of the two properties above, and it is paid on every publish, update and registration.

## Compose Profiles

`docker compose up` starts PostgreSQL by default and builds the container with `postgres,aws-secrets,acme` features enabled. To run the MySQL service instead:

```bash
FEATURES="mysql,aws-secrets,acme" docker compose --profile mysql up --build
```

There is no separate MariaDB service because MariaDB uses the same MySQL-driver path (`mysql://` URL). Connect to a MariaDB host by pointing `APP_DATABASE__URL` at your MariaDB instance on port 3306 (the default) and setting `APP_DATABASE__BACKEND=mysql`.

## HA And Distributed Storage

- For high availability, prefer PostgreSQL or MySQL backed by a managed HA service or a replicated cluster.
- Avoid SQLite for multi-replica production deployments.
- If you need distributed storage semantics, use a database that already provides them rather than trying to layer them on top of SQLite.

