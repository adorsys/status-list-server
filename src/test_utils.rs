//! Test harness: builds a wired [`AppState`] over the memory or SQL adapters.
//!
//! Shared test *data* does not belong here. This module pulls in the adapters,
//! so anything defined in it is unreachable from a test module compiled without
//! them. Put plain literals in [`crate::test_fixtures`], which is dependency-
//! free precisely so that any test module can reach it whatever its own gate.

use crate::domain::ports::{CredentialRepo, StatusListRepo, StatusListSnapshotRepo};
use crate::domain::service::Service;
use crate::outbound::cache::MokaStatusListCache;
#[cfg(feature = "memory")]
use crate::outbound::memory::{MemoryCredentials, MemoryStatusListSnapshotRepo, MemoryStatusLists};
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use crate::outbound::sql::{
    SeaOrmStore, SqlCredentialRepo, SqlStatusListRepo, SqlStatusListSnapshotRepo,
};
use crate::server::AppState;
use crate::server::health::Readiness;
#[cfg(feature = "acme")]
use crate::{cert_manager::storage::StorageError, utils::cert_manager::storage::Storage};
use async_trait::async_trait;
#[cfg(feature = "acme")]
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "acme")]
#[allow(dead_code)]
pub(crate) struct MockStorage {
    pub key_value: HashMap<String, String>,
}

#[cfg(feature = "acme")]
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

#[cfg(feature = "history")]
pub(crate) async fn test_app_state(db_conn: Option<Arc<sea_orm::DatabaseConnection>>) -> AppState {
    build_test_app_state(db_conn, None, 1_048_576).await
}

#[cfg(not(feature = "history"))]
pub(crate) async fn test_app_state(_db_conn: Option<Arc<()>>) -> AppState {
    build_test_app_state(None, 1_048_576).await
}

/// An [`AppState`] whose `Service` has **no** snapshot repo, as built when an
/// operator sets `snapshot_retention_secs = 0`.
///
/// That configuration routes publishes down `Service::publish_status_list`'s
/// `None` branch to the plain, non-transactional `insert`, which is a different
/// duplicate-classification call site from `insert_with_snapshot`. Memory-backed
/// because the branch being exercised is in the service, not the adapter.
pub(crate) async fn test_app_state_without_snapshots() -> AppState {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let service = Arc::new(Service::from_arcs(
        Arc::new(MemoryStatusLists::default()),
        Arc::new(MemoryCredentials::default()),
        Arc::new(MokaStatusListCache::new(5 * 60, 100)),
        None,
        Arc::new(TestCertProvider {
            key_pem: include_str!("../test_data/ec-private.pem").to_string(),
            cert_chain: vec!["ZHVtbXlfY2VydA==".into()],
        }),
    ));

    AppState {
        service,
        server_domain: "example.com".to_string(),
        aggregation_uri: None,
        token_exp_secs: 900,
        token_ttl_secs: 300,
        max_status_index: 100_000,
        max_statuses_per_request: 5_000,
        max_serialized_list_size: 1_048_576,
        snapshot_retention_secs: 0,
        readiness: crate::server::health::Readiness::new(Vec::new()),
    }
}

pub(crate) struct TestCertProvider {
    pub key_pem: String,
    pub cert_chain: Vec<String>,
}

#[async_trait]
impl crate::domain::ports::CertificateProvider for TestCertProvider {
    async fn signing_material(
        &self,
    ) -> Result<
        crate::domain::ports::SigningMaterial,
        crate::domain::models::status_list::StatusListError,
    > {
        Ok(crate::domain::ports::SigningMaterial {
            certificate_chain: Some(self.cert_chain.clone()),
            signing_key_pem: self.key_pem.clone(),
        })
    }
}

async fn build_test_app_state(
    #[cfg(feature = "history")] db_conn: Option<Arc<sea_orm::DatabaseConnection>>,
    aggregation_uri: Option<String>,
    max_serialized_list_size: usize,
) -> AppState {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let key_pem = include_str!("../test_data/ec-private.pem").to_string();

    let memory_snapshot = MemoryStatusListSnapshotRepo::default();
    let memory_lists = MemoryStatusLists::default().with_snapshot(&memory_snapshot);

    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    let (status_lists, credentials, status_list_history): (
        Arc<dyn StatusListRepo>,
        Arc<dyn CredentialRepo>,
        Arc<dyn StatusListSnapshotRepo>,
    ) = if let Some(db) = db_conn {
        (
            Arc::new(SqlStatusListRepo::new(SeaOrmStore::new(db.clone()))),
            Arc::new(SqlCredentialRepo::new(SeaOrmStore::new(db.clone()))),
            Arc::new(SqlStatusListSnapshotRepo::new(SeaOrmStore::new(db.clone()))),
        )
    } else {
        (
            Arc::new(memory_lists),
            Arc::new(MemoryCredentials::default()),
            Arc::new(memory_snapshot),
        )
    };

    #[cfg(not(any(feature = "sqlite", feature = "postgres", feature = "mysql")))]
    let (status_lists, credentials, status_list_history): (
        Arc<dyn StatusListRepo>,
        Arc<dyn CredentialRepo>,
        Arc<dyn StatusListSnapshotRepo>,
    ) = (
        Arc::new(memory_lists),
        Arc::new(MemoryCredentials::default()),
        Arc::new(memory_snapshot),
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
        snapshot_retention_secs: 7776000,
        readiness: Readiness::default(),
    }
}
