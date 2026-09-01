//! Relational database outbound adapters implementing domain ports via SeaORM.

mod error;
mod migrations;
mod models;
mod store;
// Real-backend container fixtures, shared by the store's own backend proofs and
// by the HTTP-layer publish test.
#[cfg(test)]
pub(crate) mod test_containers;

pub use error::RepositoryError;
pub use migrations::Migrator;
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) use migrations::{verify_binlog_format, verify_innodb_engines};
pub use models::*;
pub use store::{SeaOrmStore, SwappableDatabaseConnection};

use async_trait::async_trait;

use crate::domain::models::credential::{Credential, CredentialError, Issuer, PublicJwk};
use crate::domain::models::status_list::{StatusListError, StatusListRecord, StatusListSnapshot};
use crate::domain::ports::{CredentialRepo, StatusListRepo, StatusListSnapshotRepo};

/// SQL relational adapter implementing `StatusListRepo`.
#[derive(Clone)]
pub struct SqlStatusListRepo {
    store: SeaOrmStore<models::StatusListRecord>,
}

impl SqlStatusListRepo {
    pub fn new(store: SeaOrmStore<models::StatusListRecord>) -> Self {
        Self { store }
    }
}

/// SQL relational adapter implementing `CredentialRepo`.
#[derive(Clone)]
pub struct SqlCredentialRepo {
    store: SeaOrmStore<models::Credentials>,
}

impl SqlCredentialRepo {
    pub fn new(store: SeaOrmStore<models::Credentials>) -> Self {
        Self { store }
    }
}

/// SQL relational adapter implementing `StatusListSnapshotRepo`.
#[derive(Clone)]
pub struct SqlStatusListSnapshotRepo {
    store: SeaOrmStore<models::StatusListHistoryRecord>,
}

impl SqlStatusListSnapshotRepo {
    pub fn new(store: SeaOrmStore<models::StatusListHistoryRecord>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl CredentialRepo for SqlCredentialRepo {
    async fn find(&self, issuer: &str) -> Result<Option<Credential>, CredentialError> {
        let record = self.store.find_one_by(issuer).await?;
        let Some(record) = record else {
            return Ok(None);
        };
        let public_key_bytes = serde_json::to_vec(&record.public_key)
            .map_err(|e| CredentialError::InvalidPublicJwk(format!("serialization failed: {e}")))?;
        let public_key = PublicJwk::try_new(public_key_bytes)?;
        Ok(Some(Credential {
            issuer: Issuer(record.issuer),
            public_key,
        }))
    }

    async fn insert(&self, credential: Credential) -> Result<(), CredentialError> {
        let public_key = serde_json::from_slice(credential.public_key.as_bytes())
            .map_err(|e| CredentialError::InvalidPublicJwk(format!("parse failed: {e}")))?;
        self.store
            .insert_one(models::Credentials::new(credential.issuer.0, public_key))
            .await
            .map_err(Into::into)
    }
}

#[async_trait]
impl StatusListRepo for SqlStatusListRepo {
    async fn find(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError> {
        self.store
            .find_one_by(list_id)
            .await
            .map(|value| value.map(From::from))
            .map_err(Into::into)
    }

    async fn insert(&self, record: StatusListRecord) -> Result<(), StatusListError> {
        self.store
            .insert_one(record.into())
            .await
            .map_err(Into::into)
    }

    async fn update(
        &self,
        record: StatusListRecord,
        expected_updated_at: i64,
    ) -> Result<bool, StatusListError> {
        let id = record.list_id.clone();
        self.store
            .update_one(&id, record.into(), expected_updated_at)
            .await
            .map_err(Into::into)
    }

    async fn update_with_snapshot(
        &self,
        record: StatusListRecord,
        expected_updated_at: i64,
        snapshot: StatusListSnapshot,
    ) -> Result<bool, StatusListError> {
        let id = record.list_id.clone();
        self.store
            .update_one_with_snapshot(&id, record.into(), expected_updated_at, snapshot.into())
            .await
            .map_err(Into::into)
    }

    async fn insert_with_snapshot(
        &self,
        record: StatusListRecord,
        snapshot: StatusListSnapshot,
    ) -> Result<(), StatusListError> {
        self.store
            .insert_one_with_snapshot(record.into(), snapshot.into())
            .await
            .map_err(Into::into)
    }

    async fn list_uris(&self) -> Result<Vec<String>, StatusListError> {
        self.store
            .find_all_status_list_uris()
            .await
            .map_err(Into::into)
    }
}

#[async_trait]
impl StatusListSnapshotRepo for SqlStatusListSnapshotRepo {
    async fn insert(&self, record: StatusListSnapshot) -> Result<(), StatusListError> {
        self.store
            .insert_one(record.into())
            .await
            .map_err(Into::into)
    }

    async fn find_valid_at(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<Option<StatusListSnapshot>, StatusListError> {
        self.store
            .find_valid_at(list_id, time)
            .await
            .map(|value| value.map(Into::into))
            .map_err(Into::into)
    }

    async fn delete_older_than(&self, cutoff: i64) -> Result<u64, StatusListError> {
        self.store
            .delete_older_than(cutoff)
            .await
            .map_err(Into::into)
    }
}

impl From<models::StatusListRecord> for StatusListRecord {
    fn from(record: models::StatusListRecord) -> Self {
        Self {
            list_id: record.list_id,
            issuer: Issuer(record.issuer),
            sub: record.sub,
            status_list: crate::domain::models::status_list::StatusList {
                bits: record.status_list.bits,
                lst: record.status_list.lst,
            },
            updated_at: record.updated_at,
        }
    }
}

impl From<StatusListRecord> for models::StatusListRecord {
    fn from(record: StatusListRecord) -> Self {
        Self {
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
}

impl From<models::StatusListHistoryRecord> for StatusListSnapshot {
    fn from(record: models::StatusListHistoryRecord) -> Self {
        Self {
            snapshot_id: record.snapshot_id,
            list_id: record.list_id,
            issuer: Issuer(record.issuer),
            status_list: crate::domain::models::status_list::StatusList {
                bits: record.status_list.bits,
                lst: record.status_list.lst,
            },
            sub: record.sub,
            iat: record.iat,
            exp: record.exp,
        }
    }
}

impl From<StatusListSnapshot> for models::StatusListHistoryRecord {
    fn from(record: StatusListSnapshot) -> Self {
        Self {
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
}

impl From<RepositoryError> for CredentialError {
    fn from(value: RepositoryError) -> Self {
        match value {
            RepositoryError::DuplicateEntry => CredentialError::AlreadyExists,
            RepositoryError::Contention { code } => CredentialError::Contention { code },
            other => CredentialError::Backend(Box::new(other)),
        }
    }
}

impl From<RepositoryError> for StatusListError {
    fn from(value: RepositoryError) -> Self {
        match value {
            RepositoryError::DuplicateEntry => StatusListError::AlreadyExists,
            RepositoryError::Contention { code } => StatusListError::Contention { code },
            other => StatusListError::Backend(Box::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::error::{ApiError, IntoApiError};
    use axum::http::StatusCode;

    /// Spans the chain the other tests only cover in halves: adapter error →
    /// domain conversion → status and code the client receives. A broken `From`
    /// here would pass both halves while shipping a 500.
    #[test]
    fn contention_reaches_the_client_as_409_write_contention() {
        let status_list: StatusListError = RepositoryError::Contention { code: "40P01" }.into();
        let api = status_list.into_api_error();
        assert_eq!(api.status, StatusCode::CONFLICT);
        assert_eq!(api.error, "write_contention");
        assert_eq!(
            api.retry_after_secs,
            Some(1),
            "the retry hint must survive the conversion chain"
        );

        let credential: CredentialError = RepositoryError::Contention { code: "1205" }.into();
        let api: ApiError = credential.into_api_error();
        assert_eq!(api.status, StatusCode::CONFLICT);
        assert_eq!(api.error, "write_contention");
    }

    /// A duplicate key must stay a duplicate; routed through `Contention` it
    /// would tell the client to retry a write that can never succeed.
    #[test]
    fn duplicate_entry_is_not_reported_as_contention() {
        let status_list: StatusListError = RepositoryError::DuplicateEntry.into();
        assert_eq!(
            status_list.into_api_error().error,
            "status_list_already_exists"
        );

        let credential: CredentialError = RepositoryError::DuplicateEntry.into();
        assert_eq!(
            credential.into_api_error().error,
            "credentials_already_exist"
        );
    }

    /// The classification carves out contention; it must not soften every
    /// storage failure into something a client is told to retry.
    #[test]
    fn unclassified_storage_errors_remain_500() {
        for err in [
            RepositoryError::InsertError("boom".into()),
            RepositoryError::UpdateError("boom".into()),
            RepositoryError::FindError("boom".into()),
        ] {
            let api = StatusListError::from(err).into_api_error();
            assert_eq!(api.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(api.retry_after_secs.is_none());
        }
    }
}
