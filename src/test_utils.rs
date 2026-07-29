use crate::domain::ports::{CredentialRepo, StatusListHistoryRepo, StatusListRepo};
use crate::domain::service::Service;
use crate::outbound::cache::MokaStatusListCache;
use crate::outbound::cert::AcmeCertificateProvider;
use crate::outbound::memory::{MemoryCredentials, MemoryStatusListHistory, MemoryStatusLists};
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use crate::outbound::sql::{
    SeaOrmStore, SqlCredentialRepo, SqlStatusListHistoryRepo, SqlStatusListRepo,
};
use crate::{
    cert_manager::storage::StorageError,
    server::AppState,
    utils::cert_manager::{CertManager, storage::Storage},
};
use async_trait::async_trait;
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

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) async fn test_app_state(db_conn: Option<Arc<sea_orm::DatabaseConnection>>) -> AppState {
    build_test_app_state(db_conn, None, 1_048_576).await
}

#[cfg(not(any(feature = "sqlite", feature = "postgres", feature = "mysql")))]
pub(crate) async fn test_app_state(_db_conn: Option<Arc<()>>) -> AppState {
    build_test_app_state(None, 1_048_576).await
}

pub(crate) struct TestCertProvider {
    pub key_pem: String,
    pub cert_chain: Vec<String>,
}

#[async_trait]
impl crate::domain::ports::CertificateProvider for TestCertProvider {
    async fn certificate_chain(
        &self,
    ) -> Result<Option<Vec<String>>, crate::domain::models::status_list::StatusListError> {
        Ok(Some(self.cert_chain.clone()))
    }

    async fn signing_key_pem(
        &self,
    ) -> Result<String, crate::domain::models::status_list::StatusListError> {
        Ok(self.key_pem.clone())
    }
}

async fn build_test_app_state(
    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))] db_conn: Option<
        Arc<sea_orm::DatabaseConnection>,
    >,
    aggregation_uri: Option<String>,
    max_serialized_list_size: usize,
) -> AppState {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let key_pem = include_str!("../test_data/ec-private.pem").to_string();

    let memory_history = MemoryStatusListHistory::default();
    let memory_lists = MemoryStatusLists::default().with_history(&memory_history);

    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    let (status_lists, credentials, status_list_history): (
        Arc<dyn StatusListRepo>,
        Arc<dyn CredentialRepo>,
        Arc<dyn StatusListHistoryRepo>,
    ) = if let Some(db) = db_conn {
        (
            Arc::new(SqlStatusListRepo::new(SeaOrmStore::new(db.clone()))),
            Arc::new(SqlCredentialRepo::new(SeaOrmStore::new(db.clone()))),
            Arc::new(SqlStatusListHistoryRepo::new(SeaOrmStore::new(db.clone()))),
        )
    } else {
        (
            Arc::new(memory_lists),
            Arc::new(MemoryCredentials::default()),
            Arc::new(memory_history),
        )
    };

    #[cfg(not(any(feature = "sqlite", feature = "postgres", feature = "mysql")))]
    let (status_lists, credentials, status_list_history): (
        Arc<dyn StatusListRepo>,
        Arc<dyn CredentialRepo>,
        Arc<dyn StatusListHistoryRepo>,
    ) = (
        Arc::new(memory_lists),
        Arc::new(MemoryCredentials::default()),
        Arc::new(memory_history),
    );

    let status_list_cache = Arc::new(MokaStatusListCache::new(5 * 60, 100));
    let cert_provider = Arc::new(TestCertProvider {
        key_pem,
        cert_chain: vec!["ZHVtbXlfY2VydA==".into()],
    });

    let service = Arc::new(Service::from_arcs(
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
