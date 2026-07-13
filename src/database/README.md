# Database Overview

This document provides an overview of the database schema, including its tables and columns.

Column types are expressed via the sea-orm-migration DSL and map to a
backend-appropriate type per configured `DatabaseBackend` (PostgreSQL, MySQL or
SQLite). Schema identifiers below use the PostgreSQL/TEXT spelling; on other
backends the equivalent native character type is used.

## Tables

### `credentials`

Stores information about issuers and their cryptographic public keys.

| Column       | Type | Description                                |
| ------------ | ---- | ------------------------------------------ |
| `issuer`     | TEXT | Primary key — unique identifier for the issuer |
| `public_key` | JSON | Public key associated with the issuer      |

### `status_lists`

Stores information about status list entries and their associated issuer.

| Column        | Type | Description                                                |
| ------------- | ---- | ---------------------------------------------------------- |
| `list_id`     | TEXT | Primary key — unique identifier for the status list       |
| `issuer`      | TEXT | Issuer identifier (foreign key → `credentials.issuer`)   |
| `status_list` | JSON | Status list entry                                          |
| `sub`         | TEXT | Unique string identifier for the Status List Token        |