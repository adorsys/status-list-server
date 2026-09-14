use sea_orm::DatabaseConnection;
use std::sync::Arc;

use jsonwebtoken::jwk::Jwk;

use crate::outbound::sql::SeaOrmStore;
use crate::outbound::sql::models::{
    Credentials, StatusList, StatusListHistoryRecord, StatusListRecord,
};
#[cfg(feature = "sqlite")]
use sea_orm_migration::MigratorTrait;

pub(super) const TEST_EC_JWK: &str = crate::test_fixtures::TEST_EC_PUBLIC_JWK;

#[cfg(feature = "sqlite")]
pub(super) async fn sqlite_connection() -> Arc<DatabaseConnection> {
    let mut opt = sea_orm::ConnectOptions::new("sqlite::memory:");
    opt.max_connections(1);
    opt.map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
    let db = sea_orm::Database::connect(opt)
        .await
        .expect("Failed to connect to SQLite");
    crate::outbound::sql::Migrator::up(&db, None)
        .await
        .expect("Failed to run migrations on SQLite");
    Arc::new(db)
}

/// Seeds a credential whose `issuer` backs the `status_lists.issuer` foreign
/// key and returns the JWK it was seeded with.
pub(super) async fn seed_credential(db: &Arc<DatabaseConnection>, issuer: &str) -> Jwk {
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let key: Jwk = serde_json::from_str(TEST_EC_JWK).unwrap();
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key.clone()))
        .await
        .unwrap();
    key
}

pub(super) fn record(
    list_id: &str,
    issuer: &str,
    lst: &str,
    sub: &str,
    updated_at: i64,
) -> StatusListRecord {
    StatusListRecord {
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: lst.to_string(),
        },
        sub: sub.to_string(),
        updated_at,
    }
}

pub(super) fn snapshot(
    snapshot_id: &str,
    list_id: &str,
    issuer: &str,
    lst: &str,
    sub: &str,
    iat: i64,
    exp: i64,
) -> StatusListHistoryRecord {
    StatusListHistoryRecord {
        snapshot_id: snapshot_id.to_string(),
        list_id: list_id.to_string(),
        issuer: issuer.to_string(),
        status_list: StatusList {
            bits: 1,
            lst: lst.to_string(),
        },
        sub: sub.to_string(),
        iat,
        exp,
    }
}
