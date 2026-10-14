use std::sync::Arc;

use jsonwebtoken::jwk::Jwk;
use sea_orm::DatabaseConnection;

use super::super::fixtures;
use crate::outbound::sql::models::{Credentials, StatusListRecord};
use crate::outbound::sql::{RepositoryError, SeaOrmStore};

pub(super) async fn assert_credentials_round_trip(db: Arc<DatabaseConnection>, issuer: &str) {
    let store = SeaOrmStore::<Credentials>::new(db);

    let public_key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();

    let entity = Credentials::new(issuer.to_string(), public_key.clone());

    store.insert_one(entity.clone()).await.unwrap();

    let found = store.find_one_by(issuer).await.unwrap().unwrap();
    assert_eq!(found.issuer, issuer);
    assert_eq!(found.public_key, public_key);

    let deleted = store.delete_by(issuer).await.unwrap();
    assert!(deleted);

    let gone = store.find_one_by(issuer).await.unwrap();
    assert!(gone.is_none());
}

/// A duplicate primary key must surface as `DuplicateEntry`, not a generic
/// insert error — the one property a mock cannot verify, since it depends on
/// the real driver's error parsing into `SqlErr::UniqueConstraintViolation`.
pub(super) async fn assert_duplicate_insert_maps_to_duplicate_entry(
    db: Arc<DatabaseConnection>,
    issuer: &str,
    list_id: &str,
) {
    let cred_store = SeaOrmStore::<Credentials>::new(db.clone());
    let store = SeaOrmStore::<StatusListRecord>::new(db);

    let key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
    cred_store
        .insert_one(Credentials::new(issuer.to_string(), key.clone()))
        .await
        .unwrap();

    // Duplicate credential (same issuer primary key).
    let dup_cred = cred_store
        .insert_one(Credentials::new(issuer.to_string(), key))
        .await;
    assert!(
        matches!(dup_cred, Err(RepositoryError::DuplicateEntry)),
        "duplicate credential insert must map to DuplicateEntry, got {dup_cred:?}"
    );

    // Duplicate status list (same list_id primary key).
    let record = fixtures::record(list_id, issuer, "initial", &format!("sub-{list_id}"), 0);
    store
        .insert_one(record.clone(), fixtures::NO_LIST_QUOTA)
        .await
        .unwrap();
    let dup_list = store.insert_one(record, fixtures::NO_LIST_QUOTA).await;
    assert!(
        matches!(dup_list, Err(RepositoryError::DuplicateEntry)),
        "duplicate status list insert must map to DuplicateEntry, got {dup_list:?}"
    );
}
