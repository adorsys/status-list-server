#[cfg(test)]
pub mod test {
    use crate::utils::errors::SecretCacheError;
    use crate::utils::state::{AppState, SecretCache, SecretManager};
    use async_trait::async_trait;
    use std::sync::Arc;

    // Mock implementation for testing
    pub struct MockSecretCache {
        pub value: Option<String>,
    }

    #[async_trait]
    impl SecretCache for MockSecretCache {
        async fn get_secret_string(
            &self,
            _secret_id: String,
        ) -> Result<Option<String>, SecretCacheError> {
            Ok(self.value.clone())
        }
    }

    pub fn test_app_state(db_conn: Arc<sea_orm::DatabaseConnection>) -> AppState {
        use crate::database::queries::SeaOrmStore;

        let pem = include_str!("../test_resources/ec-private.pem").to_string();
        let secret_manager = SecretManager::new(
            Arc::new(MockSecretCache { value: Some(pem) }),
            "test-server-key".to_string(),
        );

        AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            secret_manager: Arc::new(secret_manager),
        }
    }
}
