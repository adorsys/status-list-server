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

## Compose Profiles

`docker compose up` starts PostgreSQL by default. To run the MySQL service instead:

```bash
docker compose --profile mysql up
```

There is no separate MariaDB service because MariaDB uses the same MySQL-driver path (`mysql://` URL). Connect to a MariaDB host by pointing `APP_DATABASE__URL` at your MariaDB instance on port 3306 (the default) and setting `APP_DATABASE__BACKEND=mysql`.

## HA And Distributed Storage

- For high availability, prefer PostgreSQL or MySQL backed by a managed HA service or a replicated cluster.
- Avoid SQLite for multi-replica production deployments.
- If you need distributed storage semantics, use a database that already provides them rather than trying to layer them on top of SQLite.
