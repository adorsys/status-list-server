//! SeaORM implementations of the repository ports, together with the
//! driver-facing internals they wrap: the generic store, the repository
//! error type, and the schema migrations.
pub(crate) mod error;
#[cfg(feature = "server")]
pub(crate) mod migrations;
// Persistence models are private to the adapters so the compiler rejects any
// handler or use case that tries to import them. Unit tests are the one
// exception: they seed MockDatabase rows with entity models, so test builds
// widen the visibility to the crate.
#[cfg(not(test))]
pub(super) mod models;
#[cfg(test)]
pub(crate) mod models;
pub(crate) mod store;

#[cfg(feature = "server")]
pub(crate) use migrations::Migrator;

use crate::{
    domain,
    ports::{
        CredentialRepository, InvalidDataKind, PortError, PortOperation,
        StatusListHistoryRepository, StatusListRepository,
    },
};
use async_trait::async_trait;
use error::RepositoryError;
use std::sync::Arc;
use store::SeaOrmStore;

/// Maps an insert failure to its port-level meaning: a duplicate key is a
/// [`PortError::Conflict`] (a concurrent writer won the check-then-insert
/// race), everything else is the storage being unavailable.
fn map_insert_err(
    resource: &'static str,
    operation: PortOperation,
) -> impl Fn(RepositoryError) -> PortError {
    move |e| match e {
        RepositoryError::DuplicateEntry => PortError::Conflict {
            resource,
            reason: "already exists".to_string(),
        },
        e => PortError::StorageUnavailable {
            operation,
            detail: e.to_string(),
        },
    }
}

#[derive(Clone)]
pub struct SeaOrmStatusListRepository {
    store: SeaOrmStore<models::StatusListRecord>,
}
impl SeaOrmStatusListRepository {
    pub fn new(store: SeaOrmStore<models::StatusListRecord>) -> Self {
        Self { store }
    }
}

#[derive(Clone)]
pub struct SeaOrmCredentialRepository {
    store: SeaOrmStore<models::Credentials>,
}
impl SeaOrmCredentialRepository {
    pub fn new(store: SeaOrmStore<models::Credentials>) -> Self {
        Self { store }
    }
}

#[derive(Clone)]
pub struct SeaOrmStatusListHistoryRepository {
    store: SeaOrmStore<models::StatusListHistoryRecord>,
}
impl SeaOrmStatusListHistoryRepository {
    pub fn new(store: SeaOrmStore<models::StatusListHistoryRecord>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl CredentialRepository for SeaOrmCredentialRepository {
    async fn find(&self, issuer: &str) -> Result<Option<domain::Credential>, PortError> {
        self.store
            .find_one_by(issuer)
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::FindCredential,
                detail: e.to_string(),
            })?
            .map(|record| {
                let public_key =
                    serde_json::to_vec(&record.public_key).map_err(|e| PortError::InvalidData {
                        resource: "stored JWK",
                        kind: InvalidDataKind::Serialization,
                        reason: format!("serialization failed: {e}"),
                    })?;
                Ok(domain::Credential {
                    issuer: domain::Issuer(record.issuer),
                    public_key: domain::PublicJwk::try_new(public_key).map_err(|e| {
                        PortError::InvalidData {
                            resource: "stored JWK",
                            kind: InvalidDataKind::Parse,
                            reason: e.to_string(),
                        }
                    })?,
                })
            })
            .transpose()
    }
    async fn insert(&self, credential: domain::Credential) -> Result<(), PortError> {
        let public_key = serde_json::from_slice(credential.public_key.as_bytes()).map_err(|e| {
            PortError::InvalidData {
                resource: "public JWK",
                kind: InvalidDataKind::Parse,
                reason: e.to_string(),
            }
        })?;
        self.store
            .insert_one(models::Credentials::new(credential.issuer.0, public_key))
            .await
            .map_err(map_insert_err(
                "credential",
                PortOperation::InsertCredential,
            ))
    }
}

fn from_persistence(record: models::StatusListRecord) -> domain::StatusListRecord {
    domain::StatusListRecord {
        list_id: record.list_id,
        issuer: domain::Issuer(record.issuer),
        sub: record.sub,
        status_list: domain::StatusList {
            bits: record.status_list.bits,
            lst: record.status_list.lst,
        },
        updated_at: record.updated_at,
    }
}
fn to_persistence(record: domain::StatusListRecord) -> models::StatusListRecord {
    models::StatusListRecord {
        list_id: record.list_id,
        issuer: record.issuer.0,
        sub: record.sub,
        status_list: models::StatusList {
            bits: record.status_list.bits,
            lst: record.status_list.lst,
        },
        updated_at: record.updated_at,
    }
}

fn snapshot_from_persistence(
    record: models::StatusListHistoryRecord,
) -> domain::StatusListSnapshot {
    domain::StatusListSnapshot {
        snapshot_id: record.snapshot_id,
        list_id: record.list_id,
        issuer: domain::Issuer(record.issuer),
        status_list: domain::StatusList {
            bits: record.status_list.bits,
            lst: record.status_list.lst,
        },
        sub: record.sub,
        iat: record.iat,
        exp: record.exp,
    }
}

fn snapshot_to_persistence(record: domain::StatusListSnapshot) -> models::StatusListHistoryRecord {
    models::StatusListHistoryRecord {
        snapshot_id: record.snapshot_id,
        list_id: record.list_id,
        issuer: record.issuer.0,
        status_list: models::StatusList {
            bits: record.status_list.bits,
            lst: record.status_list.lst,
        },
        sub: record.sub,
        iat: record.iat,
        exp: record.exp,
    }
}

#[async_trait]
impl StatusListRepository for SeaOrmStatusListRepository {
    async fn find(
        &self,
        list_id: &str,
    ) -> Result<Option<Arc<domain::StatusListRecord>>, PortError> {
        self.store
            .find_one_by(list_id)
            .await
            .map(|value| value.map(from_persistence).map(Arc::new))
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::FindStatusList,
                detail: e.to_string(),
            })
    }
    async fn insert(&self, record: domain::StatusListRecord) -> Result<(), PortError> {
        self.store
            .insert_one(to_persistence(record))
            .await
            .map_err(map_insert_err(
                "status list",
                PortOperation::InsertStatusList,
            ))
    }
    async fn update(
        &self,
        record: domain::StatusListRecord,
        expected_updated_at: i64,
    ) -> Result<bool, PortError> {
        let id = record.list_id.clone();
        self.store
            .update_one(&id, to_persistence(record), expected_updated_at)
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::UpdateStatusList,
                detail: e.to_string(),
            })
    }
    async fn update_with_snapshot(
        &self,
        record: domain::StatusListRecord,
        expected_updated_at: i64,
        snapshot: domain::StatusListSnapshot,
    ) -> Result<bool, PortError> {
        // The guarded row update and the snapshot insert run in one transaction
        // inside the store; either both commit or neither does.
        let id = record.list_id.clone();
        self.store
            .update_one_with_snapshot(
                &id,
                to_persistence(record),
                expected_updated_at,
                snapshot_to_persistence(snapshot),
            )
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::UpdateStatusList,
                detail: e.to_string(),
            })
    }
    async fn list_uris(&self) -> Result<Vec<String>, PortError> {
        self.store
            .find_all_status_list_uris()
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::ListStatusListUris,
                detail: e.to_string(),
            })
    }
}

#[async_trait]
impl StatusListHistoryRepository for SeaOrmStatusListHistoryRepository {
    async fn insert(&self, record: domain::StatusListSnapshot) -> Result<(), PortError> {
        self.store
            .insert_one(snapshot_to_persistence(record))
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::InsertStatusListHistory,
                detail: e.to_string(),
            })
    }

    async fn find_valid_at(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<Option<domain::StatusListSnapshot>, PortError> {
        self.store
            .find_valid_at(list_id, time)
            .await
            .map(|value| value.map(snapshot_from_persistence))
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::FindStatusListHistory,
                detail: e.to_string(),
            })
    }

    async fn delete_older_than(&self, cutoff: i64) -> Result<u64, PortError> {
        self.store
            .delete_older_than(cutoff)
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::DeleteOldStatusListHistory,
                detail: e.to_string(),
            })
    }
}
