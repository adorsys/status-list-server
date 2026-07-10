# Database Overview

This document provides an overview of the database schema, including its tables,
columns, indexes, and the relationships between them. The schema is defined by the
SeaORM migrations in [`mod.rs`](./mod.rs) and the entity models in [`../models.rs`](../models.rs).

## Tables

### `credentials`

Stores information about issuers and their cryptographic public keys. Each issuer is
identified by its `issuer` value, which acts as the primary key.

| Column       | Type  | Null | Key | Description                           |
| ------------ | ----- | ---- | --- | ------------------------------------- |
| `issuer`     | TEXT  | NO   | PK  | Unique identifier for the issuer      |
| `public_key` | JSONB | NO   |     | Public key associated with the issuer |

### `status_lists`

Stores status list entries and their associated issuer. Each status list is identified
by its `list_id`, which acts as the primary key.

| Column        | Type  | Null | Key | Description                                         |
| ------------- | ----- | ---- | --- | --------------------------------------------------- |
| `list_id`     | TEXT  | NO   | PK  | Unique identifier for the status list               |
| `issuer`      | TEXT  | NO   | FK  | References `credentials.issuer` (ON DELETE CASCADE) |
| `status_list` | JSONB | NO   |     | The status list entry                               |
| `sub`         | TEXT  | NO   |     | String identifier for the Status List Token         |

#### Indexes

The following indexes are created on the `status_lists` table to speed up lookups:

| Index name                 | Column    |
| -------------------------- | --------- |
| `idx_status_lists_list_id` | `list_id` |
| `idx_status_lists_issuer`  | `issuer`  |
| `idx_status_lists_sub`     | `sub`     |

## Entity Relationship Diagram

```mermaid
erDiagram
    credentials {
        TEXT issuer PK "Unique identifier for the issuer"
        JSONB public_key "Public key associated with the issuer"
    }
    status_lists {
        TEXT list_id PK "Unique identifier for the status list"
        TEXT issuer FK "References credentials.issuer"
        JSONB status_list "The status list entry"
        TEXT sub "String identifier for the Status List Token"
    }
    credentials ||--|{ status_lists : "issuer (ON DELETE CASCADE, ON UPDATE CASCADE)"
```

## Notes

- Neither table has an auto-incrementing `id` column. The primary keys are the
  natural keys `credentials.issuer` and `status_lists.list_id`, matching the
  SeaORM migrations.
- `status_lists.issuer` references `credentials.issuer` via the
  `fk_status_lists_issuer` foreign key, which cascades on both delete and update.
