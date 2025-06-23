use crate::{
    cert_manager::storage::StorageError,
    utils::{
        cert_manager::{storage::Storage, CertManager},
        state::AppState,
    },
};
use async_trait::async_trait;
use sea_orm::{DbBackend, MockDatabase};
use std::{collections::HashMap, sync::Arc};

pub struct MockStorage {
    pub key_value: HashMap<String, String>,
}

#[async_trait]
impl Storage for MockStorage {
    async fn store(&self, _key: &str, _value: &str) -> Result<(), StorageError> {
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        if let Some(value) = self.key_value.get(key) {
            Ok(Some(value.clone()))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, _key: &str) -> Result<(), StorageError> {
        Ok(())
    }
}

pub async fn test_app_state(db_conn: Option<Arc<sea_orm::DatabaseConnection>>) -> AppState {
    use crate::database::queries::SeaOrmStore;

    // Install the crypto provider for the tests
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let db = db_conn
        .unwrap_or_else(|| Arc::new(MockDatabase::new(DbBackend::Postgres).into_connection()));

    let key_pem = include_str!("test_resources/ec-private.pem").to_string();
    let secrets_storage = MockStorage {
        key_value: HashMap::from([("keys/test.com".to_string(), key_pem)]),
    };

    let cert_data = include_str!("test_resources/cert_data.json").to_string();
    let cert_storage = MockStorage {
        key_value: HashMap::from([("certs/test.com/cert_data.json".to_string(), cert_data)]),
    };

    let certificate_manager = CertManager::new(
        ["test.com"],
        "test@example.com",
        None::<String>,
        "http://example.com/dir",
    )
    .unwrap()
    .with_cert_storage(cert_storage)
    .with_secrets_storage(secrets_storage);

    AppState {
        credential_repo: SeaOrmStore::new(db.clone()),
        status_list_token_repo: Arc::new(SeaOrmStore::new(db)),
        server_domain: "example.com".to_string(),
        cert_manager: Arc::new(certificate_manager),
    }
}
