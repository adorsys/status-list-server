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
// implement Repository for your Store<T>
pub struct Store<T>
where
    T: Sized + Clone + Send + Sync + 'static,
    T: Unpin,
    T: Serialize + for<'de> Deserialize<'de>,
{
    pub table: Table<T>,
}

impl<T> Repository<T> for Store<T>
where
    T: Sized + Clone + Send + Sync + 'static,
    T: Unpin,
    T: for<'a> FromRow<'a, PgRow>,
    T: Serialize + for<'de> Deserialize<'de>,
{
    fn get_table(&self) -> Table<T> {
        self.table.clone()
    }
}

// create a store instance of credentials
let store: Store<Credentials> = Store {
            table: Table::new(conn, "credentials", "issuer".to_string()),
        };

// insert into database
store.insert_one(credential).await?;
```

