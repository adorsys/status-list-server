use crate::domain::ports::StatusListHistoryRepo;
use crate::domain::service::Service;
use crate::outbound::cache::MokaStatusListCache;
use crate::outbound::cert::AcmeCertificateProvider;
use crate::outbound::sql::{
    SeaOrmStore, SqlCredentialRepo, SqlStatusListHistoryRepo, SqlStatusListRepo,
};
use crate::{
    cert_manager::storage::StorageError,
    server::AppState,
    utils::cert_manager::{CertManager, storage::Storage},
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
    build_test_app_state(db_conn, None, 1_048_576).await
}

async fn build_test_app_state(
    db_conn: Option<Arc<sea_orm::DatabaseConnection>>,
    aggregation_uri: Option<String>,
    max_serialized_list_size: usize,
) -> AppState {
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

    let cert_manager = Arc::new(certificate_manager);
    let status_lists = SqlStatusListRepo::new(SeaOrmStore::new(db.clone()));
    let credentials = SqlCredentialRepo::new(SeaOrmStore::new(db.clone()));
    let status_list_history: Arc<dyn StatusListHistoryRepo> =
        Arc::new(SqlStatusListHistoryRepo::new(SeaOrmStore::new(db.clone())));
    let status_list_cache = MokaStatusListCache::new(5 * 60, 100);
    let cert_provider = AcmeCertificateProvider::new(cert_manager);

    let service = Arc::new(Service::new(
        status_lists,
        credentials,
        status_list_cache,
        Some(status_list_history),
        cert_provider,
    ));

    AppState {
        service,
        server_domain: "example.com".to_string(),
        aggregation_uri,
        token_exp_secs: 900,
        token_ttl_secs: 300,
        max_status_index: 100_000,
        max_statuses_per_request: 5_000,
        max_serialized_list_size,
        history_retention_secs: 7776000,
    }
}
