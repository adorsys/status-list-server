use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;

use crate::cert_manager::storage::{Storage, StorageError};

#[derive(Clone, Default)]
pub struct MemoryStorage {
    values: Arc<RwLock<HashMap<String, String>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_values(values: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            values: Arc::new(RwLock::new(values.into_iter().collect())),
        }
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.values
            .write()
            .map_err(|_| StorageError::InvalidData("memory storage lock poisoned".into()))?
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        Ok(self
            .values
            .read()
            .map_err(|_| StorageError::InvalidData("memory storage lock poisoned".into()))?
            .get(key)
            .cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.values
            .write()
            .map_err(|_| StorageError::InvalidData("memory storage lock poisoned".into()))?
            .remove(key);
        Ok(())
    }
}
