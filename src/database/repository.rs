use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::error::RepositoryError;

#[derive(Debug, Clone)]
pub struct Table<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    pub pool: Arc<DatabaseConnection>,
    pub table_name: String,
    pub column: String,
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Clone)]
#[allow(dead_code)]
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
    pub fn new(pool: Arc<DatabaseConnection>, table_name: String, column: String) -> Self {
        Self {
            pool,
            table_name,
            column,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
pub trait Repository<T>: Send + Sync
where
    T: Send + Sync + Unpin + 'static + Sized + Clone,
    T: Serialize + for<'de> Deserialize<'de>,
{
    fn get_table(&self) -> Table<T>;
    async fn insert_one(&self, entity: T) -> Result<(), RepositoryError>;
    async fn find_one_by(&self, value: String) -> Result<Option<T>, RepositoryError>;
    async fn update_one(&self, issuer: String, entity: T) -> Result<bool, RepositoryError>;
    async fn delete_by(&self, value: String) -> Result<bool, RepositoryError>;
}
