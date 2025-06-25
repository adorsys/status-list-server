use crate::{database::error::RepositoryError, models::StatusListToken};
use async_trait::async_trait;

#[async_trait]
pub trait Repository<T>: Send + Sync {
    async fn find_all(&self) -> Result<Vec<T>, RepositoryError>;
    async fn find_one_by(&self, id: String) -> Result<Option<T>, RepositoryError>;
    async fn update_one(&self, id: String, entity: T) -> Result<bool, RepositoryError>;
    async fn insert_one(&self, entity: StatusListToken) -> Result<(), RepositoryError>;
} 