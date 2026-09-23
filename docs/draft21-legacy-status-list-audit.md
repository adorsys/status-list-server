# Draft-21 Legacy Status List Audit

Older releases accepted status values that could create stored status lists with
bit widths outside Draft-21's allowed set of `1`, `2`, `4`, and `8`. Before a
Draft-21 enforcement rollout, audit each environment for those rows.

## Audit Queries

PostgreSQL:

```sql
SELECT list_id, status_list->>'bits' AS bits
FROM status_lists
WHERE (status_list->>'bits')::int NOT IN (1, 2, 4, 8);
```

MySQL:

```sql
SELECT list_id, JSON_UNQUOTE(JSON_EXTRACT(status_list, '$.bits')) AS bits
FROM status_lists
WHERE CAST(JSON_UNQUOTE(JSON_EXTRACT(status_list, '$.bits')) AS UNSIGNED)
      NOT IN (1, 2, 4, 8);
```

SQLite:

```sql
SELECT list_id, json_extract(status_list, '$.bits') AS bits
FROM status_lists
WHERE json_extract(status_list, '$.bits') NOT IN (1, 2, 4, 8);
```

Repeat the same check for `status_list_history` if historical token serving is
enabled in the environment.

## Migration Behavior

The service fails closed for unsupported stored bit widths at token emission,
but first tries to repack legacy rows whose decoded status values are still
valid Draft-21 status types (`0`, `1`, `2`, `3`, and `12` through `15`).
Those rows can be read and updated; the next successful update writes the
normalized `{1, 2, 4}` representation back to storage.

Rows containing values outside the Draft-21 registry, such as `256`, cannot be
represented in a compliant status list. The service reports those rows as
corrupt stored state. They require a product decision: either map the legacy
value to a supported status type, revoke/reissue the affected referenced tokens,
or keep the list unavailable until a registered status type exists.
