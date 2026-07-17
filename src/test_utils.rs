use crate::{
    cert_manager::storage::StorageError,
    utils::{
        cache::StatusListCache,
        cert_manager::{CertManager, storage::Storage},
        state::AppState,
    },
};
use async_trait::async_trait;
use sea_orm::{DbBackend, MockDatabase};
use std::{collections::HashMap, sync::Arc};

pub(crate) struct MockStorage {
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

pub(crate) async fn test_app_state(db_conn: Option<Arc<sea_orm::DatabaseConnection>>) -> AppState {
    test_app_state_with(db_conn, None).await
}

pub(crate) async fn test_app_state_with(
    db_conn: Option<Arc<sea_orm::DatabaseConnection>>,
    aggregation_uri: Option<String>,
) -> AppState {
    use crate::database::queries::SeaOrmStore;

    // Install the crypto provider for the tests
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let db = db_conn.unwrap_or(Arc::new(
        MockDatabase::new(DbBackend::Postgres).into_connection(),
    ));

    let key_pem = include_str!("../test_data/ec-private.pem").to_string();
    let secrets_storage = MockStorage {
        key_value: HashMap::from([("keys-test.com".to_string(), key_pem)]),
    };

    let cert_data = include_str!("../test_data/cert_data.json").to_string();
    let cert_storage = MockStorage {
        key_value: HashMap::from([("certs-test.com-cert_data.json".to_string(), cert_data)]),
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
        status_list_repo: SeaOrmStore::new(db),
        server_domain: "example.com".to_string(),
        cert_manager: Arc::new(certificate_manager),
        cache: StatusListCache::new(5 * 60, 100),
        aggregation_uri,
        token_exp_secs: 900,
        token_ttl_secs: 300,
        max_status_index: 100_000,
        max_statuses_per_request: 5_000,
        max_serialized_list_size: 1_048_576,
    }
}
