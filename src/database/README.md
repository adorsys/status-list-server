# Database Overview

This document provides an overview of the database schema, including its tables and columns.

## Tables

### `credentials`

Stores information about issuers and their cryptographic public keys.

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
