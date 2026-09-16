//! Status-list cache port.

use async_trait::async_trait;

use crate::domain::models::status_list::{StatusListError, StatusListRecord};

/// Pluggable cache interface for recently used status-list records.
#[async_trait]
pub trait Cache: Send + Sync + 'static {
    /// Retrieve a cached status-list record by list identifier.
    async fn get(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError>;

    /// Store a status-list record in the cache.
    async fn put(&self, status_list: StatusListRecord) -> Result<(), StatusListError>;

    /// Invalidate a cached status-list entry upon mutation.
    async fn invalidate(&self, list_id: &str) -> Result<(), StatusListError>;
}
