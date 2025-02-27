use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::{postgres::PgRow, FromRow, PgPool};

use super::error::RepositoryError;

#[derive(Debug, Clone)]
pub struct Table<T>
where
    T: for<'a> FromRow<'a, PgRow> + Send + Sync + Unpin + 'static,
    T: Serialize + for<'de> Deserialize<'de>,
    T: Identifiable,
{
    pool: PgPool,
    table_name: String,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Table<T>
where
    T: for<'a> FromRow<'a, PgRow> + Send + Sync + Unpin + 'static,
    T: Serialize + for<'de> Deserialize<'de>,
    T: Identifiable,
{
    /// Creates a new `Table` instance.
    pub fn new(pool: PgPool, table_name: impl Into<String>) -> Self {
        Self {
            pool,
            table_name: table_name.into(),
            _phantom: std::marker::PhantomData,
        }
    }
    pub async fn insert_one(&self, entity: T) -> Result<(), RepositoryError> {
        let query = format!(
            r#"
            INSERT INTO {}
            VALUES ($1)
            "#,
            self.table_name
        );
        let mut query = sqlx::query(&query);
        let a = json!(entity);
        let a = a.as_object().unwrap();
        for value in a.values() {
            query = query.bind(value)
        }

        Ok(())
    }
}

/// trait which holds identiable data for table
pub trait Identifiable {
    fn table_name(&self) -> Option<String>;
    fn connection(&self) -> PgPool;
}
