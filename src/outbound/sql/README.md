# Database Overview

This document provides an overview of the database schema, including its tables and columns.

Column types are expressed via the sea-orm-migration DSL and map to a
backend-appropriate type per configured `DatabaseBackend` (PostgreSQL, MySQL or
SQLite). Schema identifiers below use the PostgreSQL/TEXT spelling; on other
backends the equivalent native character type is used.

## Tables

### `credentials`

Stores information about issuers and their cryptographic public keys.

| Column       | Type | Null | Key | Description                           |
| ------------ | ---- | ---- | --- | ------------------------------------- |
| `issuer`     | TEXT | NO   | PK  | Unique identifier for the issuer      |
| `public_key` | JSON | NO   |     | Public key associated with the issuer |

### `status_lists`

Stores status list entries and their associated issuer. Each status list is identified
by its `list_id`, which acts as the primary key.

| Column        | Type   | Null | Key | Description                                         |
| ------------- | ------ | ---- | --- | --------------------------------------------------- |
| `list_id`     | TEXT   | NO   | PK  | Unique identifier for the status list               |
| `issuer`      | TEXT   | NO   | FK  | References `credentials.issuer` (ON DELETE CASCADE) |
| `status_list` | JSON   | NO   |     | The status list entry                               |
| `sub`         | TEXT   | NO   |     | String identifier for the Status List Token         |
| `updated_at`  | BIGINT | NO   |     | UNIX timestamp of last status update                |

#### Indexes

The following indexes are created on the `status_lists` table to speed up lookups:

| Index name                 | Column    |
| -------------------------- | --------- |
| `idx_status_lists_list_id` | `list_id` |
| `idx_status_lists_issuer`  | `issuer`  |
| `idx_status_lists_sub`     | `sub`     |

### `status_list_history`

Stores historical status list snapshots for time-travel queries.

| Column        | Type   | Null | Key | Description                                           |
| ------------- | ------ | ---- | --- | ----------------------------------------------------- |
| `id`          | TEXT   | NO   | PK  | Unique identifier for the snapshot                    |
| `list_id`     | TEXT   | NO   | FK  | References `status_lists.list_id` (ON DELETE CASCADE) |
| `status_list` | JSON   | NO   |     | The historical status list entry                      |
| `valid_from`  | BIGINT | NO   |     | UNIX timestamp from which this snapshot is valid      |
| `valid_until` | BIGINT | YES  |     | UNIX timestamp until which this snapshot is valid     |
| `created_at`  | BIGINT | NO   |     | UNIX timestamp when snapshot was created              |

#### Indexes

| Index name                          | Column                             |
| ----------------------------------- | ---------------------------------- |
| `idx_status_list_history_list_time` | `list_id, valid_from, valid_until` |

### `certificate_storage`

Stores certificate-manager key/value material when SQL-backed certificate or
secrets storage is selected.

| Column        | Type   | Null | Key | Description                                      |
| ------------- | ------ | ---- | --- | ------------------------------------------------ |
| `storage_key` | TEXT   | NO   | PK  | Storage key used by the certificate manager      |
| `value`       | TEXT   | NO   |     | Opaque stored value; may contain secret material  |
| `metadata`    | JSON   | YES  |     | Optional provider metadata for future extensions |
| `created_at`  | BIGINT | NO   |     | UNIX timestamp when the row was created          |
| `updated_at`  | BIGINT | NO   |     | UNIX timestamp when the row was last updated     |

The `value` column can hold signing keys and ACME account material. Do not log
it, expose it in diagnostics, or grant read access to this table more broadly
than you would grant access to signing keys. Use this backend when a portable
single-database deployment is more important than secret-manager features. Use a
dedicated secrets manager for stronger key isolation, rotation and audit needs.

## Entity Relationship Diagram

```mermaid
erDiagram
    credentials {
        TEXT issuer PK "Unique identifier for the issuer"
        JSON public_key "Public key associated with the issuer"
    }
    status_lists {
        TEXT list_id PK "Unique identifier for the status list"
        TEXT issuer FK "References credentials.issuer"
        JSON status_list "The status list entry"
        TEXT sub "String identifier for the Status List Token"
        BIGINT updated_at "UNIX timestamp of last update"
    }
    status_list_history {
        TEXT id PK "Unique snapshot ID"
        TEXT list_id FK "References status_lists.list_id"
        JSON status_list "Historical status list entry"
        BIGINT valid_from "Start timestamp"
        BIGINT valid_until "End timestamp"
        BIGINT created_at "Creation timestamp"
    }
    certificate_storage {
        TEXT storage_key PK "Storage key"
        TEXT value "Opaque certificate or secret value"
        JSON metadata "Optional metadata"
        BIGINT created_at "Creation timestamp"
        BIGINT updated_at "Last update timestamp"
    }
    credentials ||--|{ status_lists : "issuer (ON DELETE CASCADE, ON UPDATE CASCADE)"
    status_lists ||--|{ status_list_history : "list_id (ON DELETE CASCADE)"
```
