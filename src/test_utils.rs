//! Test harness: builds a wired [`AppState`] over the memory or SQL adapters.
//!
//! Shared test *data* does not belong here. This module pulls in the adapters,
//! so anything defined in it is unreachable from a test module compiled without
//! them. Put plain literals in [`crate::test_fixtures`], which is dependency-
//! free precisely so that any test module can reach it whatever its own gate.

use crate::domain::models::credential::{AggregationId, Credential, Issuer, PublicJwk};
use crate::domain::models::status_list::{StatusListError, StatusListRecord};
use crate::domain::ports::{
    CredentialRepo, StatusListCache, StatusListRepo, StatusListSnapshotRepo,
};
use crate::domain::service::Service;
#[cfg(feature = "memory")]
use crate::outbound::memory::{MemoryCredentials, MemoryStatusListSnapshotRepo, MemoryStatusLists};
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use crate::outbound::sql::{
    SeaOrmStore, SqlCredentialRepo, SqlStatusListRepo, SqlStatusListSnapshotRepo,
};
use crate::server::AppState;
use crate::server::auth::AuthenticatedIssuer;
use crate::server::health::Readiness;
#[cfg(feature = "acme")]
use crate::{cert_manager::storage::StorageError, utils::cert_manager::storage::Storage};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) fn authenticated_issuer(issuer: impl Into<String>) -> AuthenticatedIssuer {
    AuthenticatedIssuer::new(Issuer(issuer.into()))
}

/// Runs `test` behind a fresh Prometheus registry and returns what it exported.
/// Creates its own runtime, so call it from a plain `#[test]`.
pub(crate) fn metrics_after(test: impl std::future::Future<Output = ()>) -> String {
    use crate::config::{TelemetryConfig, TelemetryEnvironment};
    use crate::utils::metrics::{metrics_handler, metrics_test_lock, setup_metrics};

    let _guard = metrics_test_lock();
    let registry = prometheus::Registry::new();
    let config = TelemetryConfig {
        environment: TelemetryEnvironment::Development,
        otlp_endpoint: "http://localhost:4317".to_string(),
        sampler_ratio: 1.0,
        enabled: false,
    };
    let _meter_provider = setup_metrics(
        &registry,
        &config,
        opentelemetry_sdk::Resource::builder()
            .with_service_name("status-list-server-test")
            .build(),
    )
    .expect("metrics setup");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            test.await;
            metrics_handler(registry).await
        })
}

/// Registers `issuer` and returns the aggregation ID it was given.
pub(crate) async fn register_issuer(service: &Service, issuer: &str) -> AggregationId {
    service
        .publish_credential(Credential {
            issuer: Issuer(issuer.into()),
            public_key: PublicJwk::try_new(
                crate::test_fixtures::TEST_EC_PUBLIC_JWK.as_bytes().to_vec(),
            )
            .unwrap(),
        })
        .await
        .unwrap()
}

/// Publishes an empty list for `issuer` and returns its `sub`.
pub(crate) async fn publish_list(service: &Service, issuer: &str, list_id: &str) -> String {
    publish_list_under_quota(service, issuer, list_id, u64::MAX)
        .await
        .unwrap()
}

pub(crate) async fn publish_list_under_quota(
    service: &Service,
    issuer: &str,
    list_id: &str,
    max_lists_per_issuer: u64,
) -> Result<String, StatusListError> {
    let sub = format!("https://example.com/api/v1/status-lists/{list_id}");
    service
        .publish_status_list(
            list_id.into(),
            Issuer(issuer.into()),
            sub.clone(),
            vec![],
            900,
            100_000,
            5_000,
            1_048_576,
            max_lists_per_issuer,
        )
        .await?;
    Ok(sub)
}

/// In-memory SQLite with foreign keys on and the first `steps` migrations
/// applied (`None` applies all). One connection: each is its own database.
#[cfg(feature = "sqlite")]
pub(crate) async fn sqlite_test_db(steps: Option<u32>) -> Arc<sea_orm::DatabaseConnection> {
    use sea_orm_migration::MigratorTrait;

    let mut opt = sea_orm::ConnectOptions::new("sqlite::memory:");
    opt.max_connections(1);
    opt.map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
    let db = sea_orm::Database::connect(opt)
        .await
        .expect("Failed to connect to SQLite");
    crate::outbound::sql::Migrator::up(&db, steps)
        .await
        .expect("Failed to run migrations on SQLite");
    Arc::new(db)
}

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
        Arc::new(TestStatusListCache::default()),
        None,
        Arc::new(TestCertProvider {
            key_pem: include_str!("../test_data/ec-private.pem").to_string(),
            cert_chain: Some(vec!["ZHVtbXlfY2VydA==".into()]),
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
        max_lists_per_issuer: 1_000,
        snapshot_retention_secs: 0,
        management_auth: crate::server::ManagementAuthConfig::default(),
        readiness: crate::server::health::Readiness::new(Vec::new()),
    }
}

/// An [`AppState`] whose `CertificateProvider` returns material with no
/// certificate chain, so token generation surfaces a missing-chain 500.
pub(crate) async fn test_app_state_without_cert_chain() -> AppState {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let service = Arc::new(Service::from_arcs(
        Arc::new(MemoryStatusLists::default()),
        Arc::new(MemoryCredentials::default()),
        Arc::new(TestStatusListCache::default()),
        None,
        Arc::new(TestCertProvider {
            key_pem: include_str!("../test_data/ec-private.pem").to_string(),
            cert_chain: None,
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
        max_lists_per_issuer: 1_000,
        snapshot_retention_secs: 0,
        management_auth: crate::server::ManagementAuthConfig::default(),
        readiness: crate::server::health::Readiness::new(Vec::new()),
    }
}

pub(crate) struct TestCertProvider {
    pub key_pem: String,
    pub cert_chain: Option<Vec<String>>,
}

#[async_trait]
impl crate::domain::ports::CertificateProvider for TestCertProvider {
    async fn signing_material(
        &self,
    ) -> Result<
        std::sync::Arc<crate::domain::ports::SigningMaterial>,
        crate::domain::models::status_list::StatusListError,
    > {
        let signing_key =
            crate::utils::crypto::SigningKey::from_pem(&self.key_pem).map_err(|err| {
                crate::domain::models::status_list::StatusListError::Backend(Box::new(err))
            })?;
        Ok(std::sync::Arc::new(
            crate::domain::ports::SigningMaterial::new(
                self.cert_chain.clone(),
                Arc::new(signing_key),
            )?,
        ))
    }
}

#[derive(Default)]
struct TestStatusListCache {
    // Keep general HTTP/service tests independent of the real cache adapters.
    // Adapter behavior is covered in `outbound::cache`; this helper avoids
    // coupling unrelated tests to cache metrics, TTLs, or Redis/Docker setup.
    records: RwLock<HashMap<String, StatusListRecord>>,
}

#[async_trait]
impl StatusListCache for TestStatusListCache {
    async fn get(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError> {
        Ok(self.records.read().await.get(list_id).cloned())
    }

    async fn put(&self, status_list: StatusListRecord) -> Result<(), StatusListError> {
        self.records
            .write()
            .await
            .insert(status_list.list_id.clone(), status_list);
        Ok(())
    }

    async fn invalidate(&self, list_id: &str) -> Result<(), StatusListError> {
        self.records.write().await.remove(list_id);
        Ok(())
    }
}

async fn build_test_app_state(
    #[cfg(feature = "history")] db_conn: Option<Arc<sea_orm::DatabaseConnection>>,
    aggregation_uri: Option<url::Url>,
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

    let status_list_cache = Arc::new(TestStatusListCache::default());
    let cert_provider = Arc::new(TestCertProvider {
        key_pem,
        cert_chain: Some(vec!["ZHVtbXlfY2VydA==".into()]),
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
        max_lists_per_issuer: 1_000,
        snapshot_retention_secs: 7776000,
        management_auth: crate::server::ManagementAuthConfig::default(),
        readiness: Readiness::default(),
    }
}
