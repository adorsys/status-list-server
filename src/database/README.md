# Database Overview

This document provides an overview of the database schema, including its tables and columns.

## Tables

### `credentials`

Stores information about issuers and their cryptographic public keys.

| Column       | Type   | Description                                 |
| ------------ | ------ | ------------------------------------------- |
| `id`         | SERIAL | Auto-incrementing primary key               |
| `issuer`     | TEXT   | Unique identifier for the issuer            |
| `public_key` | JSONB  | Public key associated with the issuer       |

### `status_lists`

Stores information about status lists entries and their associated issuer.

| Column        | Type   | Description                                        |
| ------------- | ------ | -------------------------------------------------- |
| `id`          | SERIAL | Auto-incrementing primary key                      |
| `list_id`     | TEXT   | Unique identifier for the status list              |
| `issuer`      | TEXT   | Unique identifier for the issuer                   |
| `status_list` | JSONB  | status list entry                                  |
| `sub`         | TEXT   | Unique string identifier for the Status List Token |
