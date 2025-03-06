use std::{collections::HashMap, fmt::Error};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::error::Error;
use sqlx::{postgres::PgRow, FromRow, PgPool};

use super::error::RepositoryError;

#[derive(Debug, Clone)]
/// Describes a table instance
pub struct Table<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    pub pool: PgPool,
    pub table_name: String,
    // column serving as query field to table
    pub column: String,
    _phantom: std::marker::PhantomData<T>,
}

/// wrapper type on Table of T
/// creates a new instance of Table with configurable information on table

#[derive(Clone)]
pub struct Store<T>
where
    T: Sized + Clone + Send + Sync + 'static,
    T: Unpin,
    T: Serialize + for<'de> Deserialize<'de>,
{
    pub table: Table<T>,
}

impl<T> Table<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    /// Creates a new `Table` instance.
    pub fn new(pool: PgPool, table_name: String, column: String) -> Self {
        Self {
            pool,
            table_name,
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

#[allow(unused)]
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
        query.execute(&table.pool).await?;

        Ok(())
    }

    /// find one by filter.
    /// `value`: value to filter by, unique value in a table column
    async fn find_one_by(&self, value: String) -> Result<T, RepositoryError> {
        let table = self.get_table();
        let query_string = format!(
            "SELECT * FROM {} WHERE {} SIMILAR TO $1 LIMIT 1",
            table.table_name, table.column
        );

        // Wrap value in double quotes
        let wrapped_value = format!("\"{}\"", value);

        let result: T = sqlx::query_as(&query_string)
            .bind(wrapped_value)
            .fetch_one(&table.pool)
            .await?;

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
            .await?;

        // Now, delete from credentials
        let delete_credentials_query = format!(
            "DELETE FROM {} WHERE {} LIKE $1",
            table.table_name, table.column
        );

        let result = sqlx::query(&delete_credentials_query)
            .bind(format!("%{}%", value))
            .execute(&table.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn update_one(&self, issuer: String, entity: T) -> Result<bool, RepositoryError> {
        let table = self.get_table();

        let mut columns = vec![];
        let mut values = vec![];
        let obj = to_map(json!(entity));

        let wrapped_value = format!("\"{}\"", issuer);

        // Filter out the `id` field if it's auto-incrementing
        for (key, val) in obj {
            if key != "id" {
                columns.push(format!("{} = ${}", key, values.len() + 2));
                values.push(val);
            }
        }

        // Construct the query
        let query = format!(
            "UPDATE {} SET {} WHERE {} = $1",
            table.table_name,
            columns.join(", "),
            table.column
        );

        // Prepare the query
        let mut query = sqlx::query(&query);

        // Bind the issuer first (this is for the WHERE clause)
        query = query.bind(wrapped_value);

        // Bind the values dynamically for the SET clause in the correct order
        for value in values {
            query = query.bind(value);
        }

        // Execute the query
        let result = query.execute(&table.pool).await?;
        Ok(result.rows_affected() > 0)
    }
}

impl From<Error> for RepositoryError {
    fn from(err: Error) -> Self {
        RepositoryError::Generic(err.to_string())
    }
}
