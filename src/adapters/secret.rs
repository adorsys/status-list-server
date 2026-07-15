//! Secret-store adapters.
use async_trait::async_trait;
use std::sync::Arc;

use crate::{
    cert_manager::storage::Storage,
    ports::{PortError, SecretStore},
};

#[derive(Clone)]
pub struct StorageSecretStore {
    storage: Arc<dyn Storage>,
}

impl StorageSecretStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl SecretStore for StorageSecretStore {
    async fn get(&self, name: &str) -> Result<Option<String>, PortError> {
        self.storage
            .load(name)
            .await
            .map_err(|err| PortError::Dependency(err.to_string()))
    }

    async fn put(&self, name: &str, value: &str) -> Result<(), PortError> {
        self.storage
            .store(name, value)
            .await
            .map_err(|err| PortError::Dependency(err.to_string()))
    }
}
