//! SeaORM implementations of the repository ports.
use crate::{
    database::queries::SeaOrmStore,
    domain, models,
    ports::{
        CredentialRepository, InvalidDataKind, PortError, PortOperation,
        StatusListHistoryRepository, StatusListRepository,
    },
};
use async_trait::async_trait;

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
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::InsertCredential,
                detail: e.to_string(),
            })
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

#[async_trait]
impl StatusListRepository for SeaOrmStatusListRepository {
    async fn find(&self, list_id: &str) -> Result<Option<domain::StatusListRecord>, PortError> {
        self.store
            .find_one_by(list_id)
            .await
            .map(|value| value.map(from_persistence))
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::FindStatusList,
                detail: e.to_string(),
            })
    }
    async fn insert(&self, record: domain::StatusListRecord) -> Result<(), PortError> {
        self.store
            .insert_one(to_persistence(record))
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: PortOperation::InsertStatusList,
                detail: e.to_string(),
            })
    }
    async fn update(&self, record: domain::StatusListRecord) -> Result<bool, PortError> {
        let id = record.list_id.clone();
        self.store
            .update_one(&id, to_persistence(record))
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
    async fn insert(&self, record: models::StatusListHistoryRecord) -> Result<(), PortError> {
        self.store
            .insert_one(record)
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
    ) -> Result<Option<models::StatusListHistoryRecord>, PortError> {
        self.store
            .find_valid_at(list_id, time)
            .await
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
