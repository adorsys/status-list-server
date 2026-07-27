use crate::{
    adapters::{
        certificate::AcmeCertificateProvider,
        sea_orm::{
            SeaOrmCredentialRepository, SeaOrmStatusListHistoryRepository,
            SeaOrmStatusListRepository,
        },
    },
    application::{CredentialApplicationService, StatusListApplicationServiceWithHistory},
    cert_manager::storage::StorageError,
    ports::{
        CredentialRepository, StatusListCache, StatusListHistoryRepository, StatusListRepository,
    },
    state::AppState,
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

/// A minimal valid status list record, for tests that need a record rather
/// than a database.
pub(crate) fn test_status_list_record(
    issuer: &str,
    list_id: &str,
) -> crate::domain::StatusListRecord {
    crate::domain::StatusListRecord {
        list_id: list_id.to_string(),
        issuer: crate::domain::Issuer(issuer.to_string()),
        status_list: crate::domain::StatusList {
            bits: 1,
            lst: "initial".to_string(),
        },
        sub: format!("https://example.com/statuslists/{list_id}"),
        updated_at: 1000,
    }
}

/// A migrated in-memory SQLite connection, for tests that need real database
/// behavior (transactions, constraints, rollback) rather than `MockDatabase`.
///
/// `max_connections(1)` mirrors the production SQLite setup in
/// [`crate::state::build_state`]: an open transaction holds the only
/// connection, so any query routed to the pool instead of the transaction
/// handle deadlocks. Tests using this should bound themselves with a timeout so
/// that failure mode surfaces as a named assertion rather than a hang.
#[cfg(feature = "sqlite")]
#[allow(dead_code)] // scaffolding for upcoming transactional snapshot tests
pub(crate) async fn sqlite_connection() -> Arc<sea_orm::DatabaseConnection> {
    use sea_orm_migration::MigratorTrait;

    let mut opt = sea_orm::ConnectOptions::new("sqlite::memory:");
    opt.max_connections(1);
    opt.map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
    let db = sea_orm::Database::connect(opt)
        .await
        .expect("Failed to connect to SQLite");
    crate::adapters::sea_orm::Migrator::up(&db, None)
        .await
        .expect("Failed to run migrations on SQLite");
    Arc::new(db)
}

pub(crate) async fn test_app_state(db_conn: Option<Arc<sea_orm::DatabaseConnection>>) -> AppState {
    build_test_app_state(db_conn, None, 1_048_576).await
}

pub(crate) async fn test_app_state_with(
    db_conn: Option<Arc<sea_orm::DatabaseConnection>>,
    aggregation_uri: Option<String>,
) -> AppState {
    build_test_app_state(db_conn, aggregation_uri, 1_048_576).await
}

/// Build a test `AppState` whose status-list service enforces a specific
/// serialized-list size limit. Used by the 422 handler tests, which previously
/// mutated a now-removed `AppState` field; the limit lives in the service, so
/// tests must configure it there.
pub(crate) async fn test_app_state_with_max_serialized_list_size(
    db_conn: Option<Arc<sea_orm::DatabaseConnection>>,
    max_serialized_list_size: usize,
) -> AppState {
    build_test_app_state(db_conn, None, max_serialized_list_size).await
}

async fn build_test_app_state(
    db_conn: Option<Arc<sea_orm::DatabaseConnection>>,
    aggregation_uri: Option<String>,
    max_serialized_list_size: usize,
) -> AppState {
    use crate::adapters::sea_orm::store::SeaOrmStore;

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

    let cert_manager = Arc::new(certificate_manager);
    let status_lists: Arc<dyn StatusListRepository> = Arc::new(SeaOrmStatusListRepository::new(
        SeaOrmStore::new(db.clone()),
    ));
    let credentials: Arc<dyn CredentialRepository> = Arc::new(SeaOrmCredentialRepository::new(
        SeaOrmStore::new(db.clone()),
    ));
    let status_list_history: Arc<dyn StatusListHistoryRepository> = Arc::new(
        SeaOrmStatusListHistoryRepository::new(SeaOrmStore::new(db.clone())),
    );
    let status_list_cache: Arc<dyn StatusListCache> = Arc::new(
        crate::adapters::cache::MokaStatusListCache::new(5 * 60, 100),
    );
    let token_exp_secs = 900u64;

    AppState {
        status_lists: Arc::new(
            StatusListApplicationServiceWithHistory::new(
                status_lists,
                status_list_cache,
                status_list_history,
                token_exp_secs,
            )
            .with_max_serialized_list_size(max_serialized_list_size),
        ),
        credentials: Arc::new(CredentialApplicationService::new(credentials)),
        certificate_provider: Arc::new(AcmeCertificateProvider::new(cert_manager.clone())),
        server_domain: "example.com".to_string(),
        aggregation_uri,
        token_exp_secs: 900,
        token_ttl_secs: 300,
        max_status_index: 100_000,
        max_statuses_per_request: 5_000,
        history_retention_secs: 7776000, // 90 days default for tests
    }
}
