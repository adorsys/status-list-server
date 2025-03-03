use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, FromRow, PgPool};

use crate::model::{Credentials, StatusListToken};

use super::{connection::establish_connection, error::RepositoryError};

#[derive(Debug, Clone)]
pub struct Table<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    pub pool: PgPool,
    pub table_name: String,
    // column serving as query field id to table
    pub column: String,
    _phantom: std::marker::PhantomData<T>,
}

pub struct Store<T>
where
    T: Sized + Clone + Send + Sync + 'static,
    T: Unpin,
    T: Serialize + for<'de> Deserialize<'de>,
{
    pub table: Table<T>,
}

impl Store<StatusListToken> {
    pub async fn new() -> Store<StatusListToken> {
        let pool = establish_connection().await;
        Store {
            table: Table::new(pool, "statuslisttoken".to_string(), "issuer".to_string()),
        }
    }
}

impl Store<Credentials> {
    pub async fn new() -> Store<Credentials> {
        let pool = establish_connection().await;
        Store {
            table: Table::new(pool, "credentials".to_string(), "issuer".to_string()),
        }
    }
}

impl<T> Table<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    /// Creates a new `Table` instance.
    pub fn new(pool: PgPool, table_name: impl Into<String>, column: String) -> Self {
        Self {
            pool,
            table_name: table_name.into(),
            column,
            _phantom: std::marker::PhantomData,
        }
    }
}

pub fn to_map(value: Value) -> HashMap<String, Value> {
    let mut map = HashMap::new();
    if let Some(obj) = value.as_object() {
        for (key, val) in obj.iter() {
            map.insert(key.clone(), val.clone());
        }
    };
    map
}

pub trait Repository<T>
where
    T: for<'a> FromRow<'a, PgRow> + Send + Sync + Unpin + 'static,
    T: Serialize + for<'de> Deserialize<'de>,
{
    ///Get a handle to a table
    fn get_table(&self) -> Table<T>;

    async fn insert_one(&self, entity: T) -> Result<(), RepositoryError> {
        let mut columns = vec![];
        let mut values = vec![];

        // Convert entity to JSON and then to a map of key-value pairs
        let value = json!(entity);
        let map = to_map(value);

        // Filter out the `id` field if it's auto-incrementing
        for (key, val) in map {
            if key != "id" {
                // Skip `id` column
                columns.push(key);
                values.push(val);
            }
        }

        // Prepare dynamic query
        let value_placeholders: Vec<String> =
            (1..=values.len()).map(|i| format!("${}", i)).collect();
        let table = self.get_table();

        // Build the dynamic query
        let query = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            table.table_name,
            columns.join(", "),
            value_placeholders.join(", ")
        );

        let mut query = sqlx::query(&query);

        // Bind the values dynamically
        for value in values {
            query = query.bind(value);
        }

        // Execute the query
        query.execute(&table.pool).await.map_err(|e| e).unwrap();

        Ok(())
    }

    /// find one by filter.
    /// `value`: value to filter by, unique value in a table column
    async fn find_one_by<'a, 'b>(&'a self, value: String) -> Result<T, RepositoryError> {
        let table = self.get_table();
        let query_string = format!(
            "SELECT * FROM {} WHERE {} SIMILAR TO $1 LIMIT 1",
            table.table_name, table.column
        );
        let result: T = sqlx::query_as(&query_string)
            .bind(format!("%{}%", value))
            .fetch_one(&table.pool)
            .await
            .map_err(|e| e)
            .unwrap();

        Ok(result)
    }

    /// delete by value, where value is unique in a table column
    async fn delete_by(&self, value: String) -> Result<bool, RepositoryError> {
        let table = self.get_table();

        // First, attempt to delete related entries in status_list_tokens (no effect if empty)
        let delete_status_list_tokens_query = "DELETE FROM status_list_tokens WHERE issuer = $1";
        let _ = sqlx::query(delete_status_list_tokens_query)
            .bind(&value)
            .execute(&table.pool)
            .await
            .map_err(|_| RepositoryError::DeleteError)?;

        // Now, delete from credentials
        let delete_credentials_query = format!(
            "DELETE FROM {} WHERE {} = $1",
            table.table_name, table.column
        );

        let result = sqlx::query(&delete_credentials_query)
            .bind(value)
            .execute(&table.pool)
            .await
            .map_err(|_| RepositoryError::DeleteError)?;

        Ok(result.rows_affected() > 0)
    }

    /// update by value, where value is unique in a table column
    async fn update_one(&self, issuer: String, entity: T) -> Result<bool, RepositoryError> {
        let table = self.get_table();

        let mut columns = vec![];
        let mut values = vec![];
        let obj = to_map(json!(entity));
        for (key, value) in obj.iter() {
            if key != "issuer" {
                // Don't update the issuer field itself
                columns.push(format!("{} = ${}", key, values.len() + 1));
                values.push(value);
            }
        }

        if columns.is_empty() {
            return Err(RepositoryError::UpdateError); // No valid update fields
        }

        // Ensure we update only the row with the given issuer
        let query = format!(
            "UPDATE {} SET {} WHERE issuer = ${}",
            table.table_name,
            columns.join(", "),
            values.len() + 1 // Placeholder for the issuer at the end
        );

        let mut query = sqlx::query(&query);

        // Bind new values dynamically
        for value in values {
            query = query.bind(value);
        }

        // Bind the issuer at the end
        query = query.bind(issuer);

        let result = query
            .execute(&table.pool)
            .await
            .map_err(|_| RepositoryError::UpdateError)?;

        Ok(result.rows_affected() > 0)
    }
}
