use async_trait::async_trait;
use redis::{aio::ConnectionManager, AsyncCommands};

use crate::cert_manager::storage::{Storage, StorageError};

/// Struct representing Redis storage
#[derive(Clone)]
pub struct Redis {
    conn: ConnectionManager,
    ttl: u64, // 0 means disabled
}

impl Redis {
    /// Create a new instance of [RedisStorage]
    /// with the given Redis connection manager
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn, ttl: 0 }
    }

    /// Set the time-to-live (TTL) for the stored data
    pub fn with_ttl(self, ttl: u64) -> Self {
        Self { ttl, ..self }
    }
}

#[async_trait]
impl Storage for Redis {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        if self.ttl == 0 {
            return Ok(());
        }
        let mut conn = self.conn.clone();
        Ok(conn.set_ex(key, value, self.ttl).await?)
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        if self.ttl == 0 {
            return Ok(None);
        }
        let mut conn = self.conn.clone();
        Ok(conn.get(key).await?)
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let mut conn = self.conn.clone();
        let _: () = conn.del(key).await?;
        Ok(())
    }
}
