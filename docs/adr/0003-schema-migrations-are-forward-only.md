# 3. Schema migrations are forward-only

- **Status:** Accepted
- **Date:** 2026-10-05
- **Issue:** [#596](https://github.com/adorsys/status-list-server/issues/596)

## Context

A rollback runs the previous release's image against a database the newer release has migrated. sea-orm-migration refuses to run when `seaql_migrations` records a migration the binary has no file for (`Migration file of version '…' is missing`), so every pod the previous release starts exits. `deploy.yml` rolls back on its own in two places: `helm upgrade --rollback-on-failure`, which can fire after the failed upgrade's first pod has migrated, and `helm rollback` after a successful upgrade whose ExternalSecrets do not sync, by which point every migration has run.

Undoing `m20260929_000001_credentials_aggregation_id` by any route (its down migration, dropping the column, restoring a backup taken before it) discards the aggregation IDs. Their replacements are random, so every `aggregation_uri` already in tokens or issuer metadata (draft-21 §9) returns `404`, and nothing in the protocol tells relying parties about a new one.

`down` had no caller outside tests: the binary exposes only `list-quota`. It could not run to zero on MySQL either. The three oldest migrations drop indexes with `if_exists()`, which sea-query 0.32.7 panics rendering for MySQL. The panic comes before any statement executes, so it blocked the rollback without damaging anything.

Replacing `if_exists()` with `has_index` guards, as the newer migrations do, does not fix it. Creating `idx_status_lists_issuer` makes InnoDB silently drop the index it had created for `fk_status_lists_issuer`, so the foreign key now depends on `idx_status_lists_issuer` and dropping it fails with error 1553 (`needed in a foreign key constraint`). MySQL commits each DDL statement on its own, so the two index drops before it would stay done while the migration stays recorded. Re-running `down` would fail at the same point, and `up` would never restore the dropped indexes. Reproduced on MySQL 26.7. The panic was the safe failure; the guards would have turned it into a half-reverted schema. A working `down` was still possible: `DROP TABLE status_lists` takes the table's indexes and foreign key with it, and succeeds on MySQL 26.7.0 where dropping the index first fails. The decision below does not rest on this. It rests on `down` having no caller, and on what undoing `aggregation_id` destroys.

## Decision

**`down` is refused.** Every migration's `down` returns `DbErr::Migration` naming the runbook section, before touching anything. `reset` and `refresh` run each migration's `down`, so they are refused too. `fresh` drops every table without running any `down`, so `Migrator` overrides it to refuse as well. Tests hold all four to this.

**A release is rolled back by deleting the records of the migrations it does not know, and keeping the schema.** Upgrading again re-runs those migrations. The procedure is in `docs/deployment-runbook.md`, "Rolling back across migrations".

**A release that cannot start says why.** When migrating fails and the database records migrations the release does not know, the error names each of them and the runbook section. The records are read only after migrating has failed, and the original error is returned unchanged when there are none, so the check never stops a start that would have succeeded. It helps only rollbacks to releases that contain it; v1.2.0 and earlier print sea-orm's message.

**Every new migration must meet both of these:**

1. The previous release runs correctly on the database the migration leaves, and on every partial state a failed run of it can leave: MySQL commits each DDL statement on its own, so a failed run keeps its earlier steps, unrecorded, and an automatic rollback starts the previous release on that. In practice the migration is additive: new tables, nullable or defaulted columns, indexes. The migration's row in the runbook's table of migrations safe to leave in place records the judgement, and what rolling back past it costs.
2. Its `up` runs again cleanly after its record is deleted, over the schema and data it left. Guard each step with `has_column`, `has_index` or `if_not_exists()`, as `m20260923_*` and `m20260929_*` do. MySQL needs the guards anyway: a failed run leaves its committed steps behind, unrecorded.

The four oldest migrations predate the rule; their `up`s are not guarded. Every release that can still be rolled back to knows them.

## Consequences

**Rule 2 is enforced; rule 1 is not.** `src/outbound/sql/store/tests/migrations.rs` deletes the records of every migration from each point after the four oldest and re-runs `up`, on SQLite, MySQL and Postgres. A migration added later is covered without anyone listing it. Nothing checks rule 1, which would need the previous release's binary run against the new schema; it rests on review. A test stands in for the previous release with a migrator that knows only the first migrations, which proves the records' deletion lets it start, not that it then runs correctly. `m20260925_000001_status_list_allocations` already breaks rule 1, though its schema change is additive: a release before it rewrites fixed-size lists without their `size`, so they stop accepting allocations. Rule 1 concerns the data the previous release writes, not only the schema it reads. A migration that breaks it must say so in its table row, with the cost and what to do instead.

**There is no schema rollback.** Restoring a backup is the only way back past a migration, and the runbook has no procedure for it yet. Without one, a restore hands out status indices twice, since allocations made after the backup are lost, turns credentials revoked since then valid again, and regenerates aggregation IDs assigned since then.

**Availability during an automatic rollback rests on a Deployment strategy nobody chose for it.** The chart sets none, and the rolled-back pods never become ready until the records are deleted, so the rollout stalls. Under Kubernetes' defaults that keeps the newer release serving at production's usual size and costs a quarter of its pods from four replicas up; the runbook's "Rolling back across migrations" has the arithmetic. A `Recreate` strategy or a larger `maxUnavailable` would make the same rollback an outage. Change either with this in view.

**On MySQL, `idx_status_lists_issuer` backs `fk_status_lists_issuer`.** `src/outbound/sql/README.md` calls it redundant next to `idx_status_lists_issuer_list_id`. A migration can drop it only while another index led by `issuer` exists; otherwise MySQL refuses with 1553.

**Tests build an earlier schema by applying only the first migrations** (`sqlite_connection_migrated`, `MysqlTestDb::start_migrated`, `postgres_connection_migrated`). That is the schema the previous release actually left, which rolling back from the newest never reproduced faithfully.
