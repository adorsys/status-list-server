# 3. Schema migrations are forward-only

- **Status:** Accepted
- **Date:** 2026-10-05
- **Issue:** [#596](https://github.com/adorsys/status-list-server/issues/596)

## Context

A rollback runs the previous release's image against a database the newer release has migrated. sea-orm-migration refuses to run when `seaql_migrations` records a migration the binary has no file for (`Migration file of version '…' is missing`), so every pod the previous release starts exits. `deploy.yml` rolls back on its own in two places: `helm upgrade --rollback-on-failure`, which can fire after the failed upgrade's first pod has migrated, and `helm rollback` after a successful upgrade whose ExternalSecrets do not sync, by which point every migration has run.

Undoing `m20260929_000001_credentials_aggregation_id` by any route (its down migration, dropping the column, restoring a backup taken before it) discards the aggregation IDs. Their replacements are random, so every `aggregation_uri` already in tokens or issuer metadata (draft-21 §9) returns `404`, and nothing in the protocol tells relying parties about a new one.

`down` had no caller outside tests: the binary exposes only `list-quota`. It could not run to zero on MySQL either. The three oldest migrations drop indexes with `if_exists()`, which sea-query 0.32.7 panics rendering for MySQL. The panic comes before any statement executes, so it blocked the rollback without damaging anything.

Replacing `if_exists()` with `has_index` guards, as the newer migrations do, does not fix it. Creating `idx_status_lists_issuer` makes InnoDB silently drop the index it had created for `fk_status_lists_issuer`, so the foreign key now depends on `idx_status_lists_issuer` and dropping it fails with error 1553 (`needed in a foreign key constraint`). MySQL commits each DDL statement on its own, so the two index drops before it would stay done while the migration stays recorded. Re-running `down` would fail at the same point, and `up` would never restore the dropped indexes. Reproduced on MySQL 26.7. The panic was the safe failure; the guards would have turned it into a half-reverted schema.

## Decision

**`down` is refused.** Every migration's `down` returns `DbErr::Migration` naming the runbook section, before touching anything. `reset` and `refresh` run each migration's `down`, so they are refused too. `fresh` drops every table without it, and nothing calls it.

**A release is rolled back by deleting the records of the migrations it does not know, and keeping the schema.** Upgrading again re-runs those migrations. The procedure is in `docs/deployment-runbook.md`, "Rolling back across migrations".

**Every new migration must meet both of these:**

1. The previous release runs correctly on the schema the migration leaves. In practice the migration is additive: new tables, nullable or defaulted columns, indexes.
2. Its `up` runs again cleanly after its record is deleted, over the schema and data it left. Guard each step with `has_column`, `has_index` or `if_not_exists()`, as `m20260923_*` and `m20260929_*` do. MySQL needs the guards anyway: a failed run leaves its committed steps behind, unrecorded.

The four oldest migrations predate the rule; their `up`s are not guarded. Every release that can still be rolled back to knows them.

## Consequences

**Rule 2 is enforced; rule 1 is not.** `src/outbound/sql/store/tests/migrations.rs` deletes the records of every migration from each point after the four oldest and re-runs `up`, on SQLite, MySQL and Postgres. A migration added later is covered without anyone listing it. Nothing checks rule 1, which would need the previous release's binary run against the new schema; it rests on review. A migration that breaks it turns the documented rollback into starting the previous release on a schema it cannot use, so such a migration must ship its own rollback procedure in its release notes.

**There is no schema rollback.** Restoring a backup is the only way back past a migration, and a last resort: everything written since the backup is lost, so credentials revoked since then read as valid again, and aggregation IDs assigned since then are regenerated. The runbook says what to do before and after.

**Availability during an automatic rollback rests on a Deployment strategy nobody chose for it.** The chart sets none, so Kubernetes' rolling-update defaults apply: `maxSurge` and `maxUnavailable` of 25%. The rolled-back pods never become ready until the records are deleted, so the rollout stalls. With two or three replicas `maxUnavailable` rounds down to zero and every pod of the newer release keeps serving. From four replicas up (production's HPA ajllows ten) a quarter of them are replaced by pods that crash-loop. A `Recreate` strategy or a larger `maxUnavailable` would make the same rollback an outage. Change either with this in view.

**On MySQL, `idx_status_lists_issuer` backs `fk_status_lists_issuer`.** `src/outbound/sql/README.md` calls it redundant next to `idx_status_lists_issuer_list_id`. A migration can drop it only while another index led by `issuer` exists; otherwise MySQL refuses with 1553.

**Tests build an earlier schema by applying only the first migrations** (`sqlite_connection_migrated`, `MysqlTestDb::start_migrated`, `postgres_connection_migrated`). That is the schema the previous release actually left, which rolling back from the newest never reproduced faithfully.
