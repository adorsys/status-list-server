# Database Overview

This document provides an overview of the database schema, including its tables, columns, and basic usage instructions.

## Tables

### `credentials`
Stores information about issuers and their cryptographic public keys.

| Column       | Type   | Description |
|-------------|--------|-------------|
| `id`        | SERIAL | Auto-incrementing primary key |
| `issuer`    | TEXT  | Unique identifier for the issuer |
| `public_key`| JSONB  | Public key associated with the issuer |
| `alg`       | TEXT   | Algorithm used for cryptographic operations |

### `status_list_tokens`
| Column | Type | Description|
|--------|------|-------------|
| `id`        | SERIAL | Auto-incrementing primary key |
| `issuer`    | TEXT  | Unique identifier for the issuer |
| `statuslisttoken`| JSONB | status list token|

## Usage
```rust
// create a store instance of credentials
let store: Store<Credentials> = Store {

            table: Table::new(conn, "credentials", "issuer".to_string()),
        };
// insert into databas
store.insert_one(credential).await.unwrap()
```

