use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use async_trait::async_trait;
use tracing::{debug, info};

use crate::cert_manager::storage::{Storage, StorageError};

/// In-memory storage implementation using a HashMap.
///
/// This is suitable for local development and testing where persistence
/// across restarts is not required.
#[derive(Clone)]
pub struct MemoryStorage {
    data: Arc<RwLock<HashMap<String, String>>>,
    name: String,
}

impl MemoryStorage {
    /// Create a new in-memory storage instance
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            name: name.into(),
        }
    }

    /// Create a new in-memory storage instance for certificates
    pub fn cert_storage() -> Self {
        Self::new("cert_storage")
    }

    /// Create a new in-memory storage instance for secrets
    pub fn secrets_storage() -> Self {
        Self::new("secrets_storage")
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        debug!("MemoryStorage[{}]: storing key '{}'", self.name, key);
        let mut data = self.data.write().await;
        data.insert(key.to_string(), value.to_string());
        info!(
            "MemoryStorage[{}]: successfully stored key '{}'",
            self.name, key
        );
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        debug!("MemoryStorage[{}]: loading key '{}'", self.name, key);
        let data = self.data.read().await;
        let value = data.get(key).cloned();
        if value.is_some() {
            debug!("MemoryStorage[{}]: found key '{}'", self.name, key);
        } else {
            debug!("MemoryStorage[{}]: key '{}' not found", self.name, key);
        }
        Ok(value)
    }

    async fn update(&self, key: &str, value: &str) -> Result<(), StorageError> {
        debug!("MemoryStorage[{}]: updating key '{}'", self.name, key);
        let mut data = self.data.write().await;
        data.insert(key.to_string(), value.to_string());
        debug!(
            "MemoryStorage[{}]: successfully updated key '{}'",
            self.name, key
        );
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        debug!("MemoryStorage[{}]: deleting key '{}'", self.name, key);
        let mut data = self.data.write().await;
        data.remove(key);
        debug!(
            "MemoryStorage[{}]: successfully deleted key '{}'",
            self.name, key
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_storage_store_and_load() {
        let storage = MemoryStorage::new("test");

        // Store a value
        storage.store("key1", "value1").await.unwrap();

        // Load the value
        let loaded = storage.load("key1").await.unwrap();
        assert_eq!(loaded, Some("value1".to_string()));

        // Load a non-existent key
        let missing = storage.load("nonexistent").await.unwrap();
        assert_eq!(missing, None);
    }

    #[tokio::test]
    async fn test_memory_storage_update() {
        let storage = MemoryStorage::new("test");

        // Store and update
        storage.store("key1", "value1").await.unwrap();
        storage.update("key1", "value2").await.unwrap();

        let loaded = storage.load("key1").await.unwrap();
        assert_eq!(loaded, Some("value2".to_string()));
    }

    #[tokio::test]
    async fn test_memory_storage_delete() {
        let storage = MemoryStorage::new("test");

        storage.store("key1", "value1").await.unwrap();
        storage.delete("key1").await.unwrap();

        let loaded = storage.load("key1").await.unwrap();
        assert_eq!(loaded, None);
    }

    #[tokio::test]
    async fn test_memory_storage_isolation() {
        let storage1 = MemoryStorage::new("storage1");
        let storage2 = MemoryStorage::new("storage2");

        storage1.store("key1", "value1").await.unwrap();
        storage2.store("key1", "value2").await.unwrap();

        // Each storage should have its own data
        let loaded1 = storage1.load("key1").await.unwrap();
        let loaded2 = storage2.load("key1").await.unwrap();

        assert_eq!(loaded1, Some("value1".to_string()));
        assert_eq!(loaded2, Some("value2".to_string()));
    }

    #[tokio::test]
    async fn test_memory_storage_clone_shares_data() {
        let storage1 = MemoryStorage::new("test");
        let storage2 = storage1.clone();

        // Store in one clone
        storage1.store("key1", "value1").await.unwrap();

        // Should be visible in the other clone
        let loaded = storage2.load("key1").await.unwrap();
        assert_eq!(loaded, Some("value1".to_string()));
    }
}
