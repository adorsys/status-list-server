//! SeaORM implementations of the repository ports.
use crate::{
    database::queries::SeaOrmStore,
    domain, models,
    ports::{CredentialRepository, PortError, StatusListHistoryRepository, StatusListRepository},
};
use async_trait::async_trait;

#[derive(Clone)]
pub struct PostgresStatusListRepository {
    store: SeaOrmStore<models::StatusListRecord>,
}
impl PostgresStatusListRepository {
    pub fn new(store: SeaOrmStore<models::StatusListRecord>) -> Self {
        Self { store }
    }
}

#[derive(Clone)]
pub struct PostgresCredentialRepository {
    store: SeaOrmStore<models::Credentials>,
}
impl PostgresCredentialRepository {
    pub fn new(store: SeaOrmStore<models::Credentials>) -> Self {
        Self { store }
    }
}

#[derive(Clone)]
pub struct PostgresStatusListHistoryRepository {
    store: SeaOrmStore<models::StatusListHistoryRecord>,
}
impl PostgresStatusListHistoryRepository {
    pub fn new(store: SeaOrmStore<models::StatusListHistoryRecord>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl CredentialRepository for PostgresCredentialRepository {
    async fn find(&self, issuer: &str) -> Result<Option<domain::Credential>, PortError> {
        self.store
            .find_one_by(issuer)
            .await
            .map(|record| {
                record.map(|record| domain::Credential {
                    issuer: domain::Issuer(record.issuer),
                    public_key: domain::PublicJwk::new(
                        serde_json::to_vec(&record.public_key).expect("JWK is serializable"),
                    ),
                })
            })
            .map_err(|e| PortError::StorageUnavailable {
                operation: "find credential",
                detail: e.to_string(),
            })
    }
    async fn insert(&self, credential: domain::Credential) -> Result<(), PortError> {
        let public_key = serde_json::from_slice(credential.public_key.as_bytes()).map_err(|e| {
            PortError::InvalidData {
                resource: "public JWK",
                reason: e.to_string(),
            }
        })?;
        self.store
            .insert_one(models::Credentials::new(credential.issuer.0, public_key))
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: "insert credential",
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
        updated_at: 0, // Domain model doesn't track updated_at; set to default
    }
}

#[async_trait]
impl StatusListRepository for PostgresStatusListRepository {
    async fn find(&self, list_id: &str) -> Result<Option<domain::StatusListRecord>, PortError> {
        self.store
            .find_one_by(list_id)
            .await
            .map(|value| value.map(from_persistence))
            .map_err(|e| PortError::StorageUnavailable {
                operation: "find status list",
                detail: e.to_string(),
            })
    }
    async fn insert(&self, record: domain::StatusListRecord) -> Result<(), PortError> {
        self.store
            .insert_one(to_persistence(record))
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: "insert status list",
                detail: e.to_string(),
            })
    }
    async fn update(&self, record: domain::StatusListRecord) -> Result<bool, PortError> {
        let id = record.list_id.clone();
        self.store
            .update_one(&id, to_persistence(record))
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: "update status list",
                detail: e.to_string(),
            })
    }
    async fn list_uris(&self) -> Result<Vec<String>, PortError> {
        self.store
            .find_all_status_list_uris()
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: "list status list URIs",
                detail: e.to_string(),
            })
    }
}

#[async_trait]
impl StatusListHistoryRepository for PostgresStatusListHistoryRepository {
    async fn insert(&self, record: models::StatusListHistoryRecord) -> Result<(), PortError> {
        self.store
            .insert_one(record)
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: "insert status list history",
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
                operation: "find valid status list history",
                detail: e.to_string(),
            })
    }

    async fn delete_older_than(&self, cutoff: i64) -> Result<u64, PortError> {
        self.store
            .delete_older_than(cutoff)
            .await
            .map_err(|e| PortError::StorageUnavailable {
                operation: "delete old status list history",
                detail: e.to_string(),
            })
    }
}
