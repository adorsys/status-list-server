use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, FromRow, PgPool, Postgres};

use super::error::RepositoryError;

#[derive(Debug, Clone)]
pub struct Table<T>
where
    T: for<'a> FromRow<'a, PgRow> + Send + Sync + Unpin + 'static,
    T: Serialize + for<'de> Deserialize<'de>,
{
    pool: PgPool,
    table_name: String,
    // column serving as unique id to table
    column: String,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Table<T>
where
    T: for<'a> FromRow<'a, PgRow> + Send + Sync + Unpin + 'static,
    T: Serialize + for<'de> Deserialize<'de>,
{
    /// Creates a new `Table` instance.
    fn new(pool: PgPool, table_name: impl Into<String>, column: String) -> Self {
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
        if let Some(obj) = json!(entity).as_object() {
            columns = obj.keys().cloned().collect();
        }

        let values: Vec<String> = (1..=columns.len()).map(|i| format!("${}", i)).collect();
        let table = self.get_table();
        // Build dynamic query
        let query = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            table.table_name,
            columns.join(", "),
            values.join(", ")
        );
        let mut query = sqlx::query(&query);
        let value = json!(entity);
        let map = to_map(value);

        // Bind all values dynamically
        for value in map.values() {
            query = query.bind(value)
        }

        // Execute
        query
            .execute(&table.pool)
            .await
            .map_err(|_| RepositoryError::StoreError)?;

        Ok(())
    }

    /// find one by filter.
    /// `value`: value to filter by, unique value in a table column
    async fn find_one_by<'a, 'b>(&'a self, value: String) -> Result<Option<T>, RepositoryError> {
        let table = self.get_table();
        let query_string = format!(
            "SELECT * FROM {} WHERE {} = $1 LIMIT 1",
            table.table_name, table.column
        );
        let result: Option<T> = sqlx::query_as(&query_string)
            .bind(value)
            .fetch_optional(&table.pool)
            .await
            .map_err(|_| RepositoryError::FetchError)?;

        return Ok(result);
    }

    /// delete by value, where value is unique in a table column
    async fn delete_by(&self, value: String) -> Result<bool, RepositoryError> {
        let table = self.get_table();
        let query = format!(
            "DELETE FROM {} WHERE {} = $1",
            table.table_name, table.column
        );

        let result = sqlx::query(&query)
            .bind(value)
            .execute(&table.pool)
            .await
            .map_err(|_| RepositoryError::DeleteError)?;

        Ok(result.rows_affected() > 0)
    }

    /// update by value, where value is unique in a table column
    async fn update_by(&self, entity: T) -> Result<bool, RepositoryError> {
        let table = self.get_table();

        let obj = to_map(json!(entity));
        let set_clause: Vec<String> = obj
            .keys()
            .enumerate()
            .map(|(i, col)| format!("{} = ${}", col, i + 2))
            .collect();

        let query = format!(
            "UPDATE {} SET {} WHERE {} = $1",
            table.table_name,
            set_clause.join(", "),
            table.column
        );

        // Prepare the query and bind values
        let mut sql_query = sqlx::query(&query).bind(table.column);
        for value in obj.values() {
            sql_query = sql_query.bind(value);
        }

        // Execute the query
        let result = sql_query
            .execute(&table.pool)
            .await
            .map_err(|_| RepositoryError::UpdateError)?;
        Ok(result.rows_affected() > 0)
    }
}
