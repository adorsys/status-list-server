#[cfg(feature = "postgres")]
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, Set,
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use super::error::RepositoryError;
use crate::models::{Credentials, StatusListRecord};
#[cfg(feature = "postgres")]
use crate::models::{credentials, status_lists};

#[async_trait::async_trait]
#[allow(dead_code)]
pub(crate) trait CredentialRepository: Send + Sync {
    async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError>;
    async fn find_one_by(&self, value: &str) -> Result<Option<Credentials>, RepositoryError>;
    async fn update_one(&self, issuer: &str, entity: Credentials) -> Result<bool, RepositoryError>;
    async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError>;
}

#[async_trait::async_trait]
#[allow(dead_code)]
pub(crate) trait StatusListRepository: Send + Sync {
    async fn insert_one(&self, entity: StatusListRecord) -> Result<(), RepositoryError>;
    async fn find_one_by(&self, value: &str) -> Result<Option<StatusListRecord>, RepositoryError>;
    async fn find_all_by(&self, issuer: &str) -> Result<Vec<StatusListRecord>, RepositoryError>;
    async fn update_one(
        &self,
        list_id: &str,
        entity: StatusListRecord,
    ) -> Result<bool, RepositoryError>;
    async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError>;
    async fn find_by_issuer(&self, issuer: &str) -> Result<Vec<StatusListRecord>, RepositoryError>;
    async fn find_all(&self) -> Result<Vec<StatusListRecord>, RepositoryError>;
    async fn find_all_status_list_uris(&self) -> Result<Vec<String>, RepositoryError>;
}

#[derive(Clone)]
#[cfg(feature = "postgres")]
pub(crate) struct SeaOrmStore<T> {
    db: Arc<DatabaseConnection>,
    _phantom: std::marker::PhantomData<T>,
}

#[cfg(feature = "postgres")]
impl<T> SeaOrmStore<T> {
    pub(crate) fn new(db: Arc<DatabaseConnection>) -> Self {
        Self {
            db,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct MemoryCredentialRepository {
    values: Arc<RwLock<HashMap<String, Credentials>>>,
}

impl MemoryCredentialRepository {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone, Default)]
pub(crate) struct MemoryStatusListRepository {
    values: Arc<RwLock<HashMap<String, StatusListRecord>>>,
}

impl MemoryStatusListRepository {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "postgres")]
impl SeaOrmStore<StatusListRecord> {
    pub(crate) async fn insert_one(&self, entity: StatusListRecord) -> Result<(), RepositoryError> {
        let active = status_lists::ActiveModel {
            list_id: Set(entity.list_id),
            issuer: Set(entity.issuer),
            status_list: Set(entity.status_list),
            sub: Set(entity.sub),
        };
        active
            .insert(&*self.db)
            .await
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;
        Ok(())
    }

    pub(crate) async fn find_one_by(
        &self,
        value: &str,
    ) -> Result<Option<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub(crate) async fn find_all_by(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .filter(status_lists::Column::Issuer.eq(issuer))
            .all(&*self.db)
            .await
            .map(|tokens| tokens.into_iter().collect())
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub(crate) async fn update_one(
        &self,
        list_id: &str,
        entity: StatusListRecord,
    ) -> Result<bool, RepositoryError> {
        let existing = status_lists::Entity::find_by_id(list_id)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))?;
        if existing.is_none() {
            return Ok(false);
        }
        let active = status_lists::ActiveModel {
            list_id: Set(entity.list_id),
            issuer: Set(entity.issuer),
            status_list: Set(entity.status_list),
            sub: Set(entity.sub),
        };
        active
            .update(&*self.db)
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
        Ok(true)
    }

    pub(crate) async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        let result = status_lists::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }

    pub(crate) async fn find_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .filter(status_lists::Column::Sub.eq(issuer))
            .all(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub(crate) async fn find_all(&self) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .all(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub(crate) async fn find_all_status_list_uris(&self) -> Result<Vec<String>, RepositoryError> {
        status_lists::Entity::find()
            .select_only()
            .column(status_lists::Column::Sub)
            .group_by(status_lists::Column::Sub)
            .order_by_asc(status_lists::Column::Sub)
            .into_tuple::<String>()
            .all(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }
}

#[async_trait::async_trait]
#[cfg(feature = "postgres")]
impl StatusListRepository for SeaOrmStore<StatusListRecord> {
    async fn insert_one(&self, entity: StatusListRecord) -> Result<(), RepositoryError> {
        Self::insert_one(self, entity).await
    }

    async fn find_one_by(&self, value: &str) -> Result<Option<StatusListRecord>, RepositoryError> {
        Self::find_one_by(self, value).await
    }

    async fn find_all_by(&self, issuer: &str) -> Result<Vec<StatusListRecord>, RepositoryError> {
        Self::find_all_by(self, issuer).await
    }

    async fn update_one(
        &self,
        list_id: &str,
        entity: StatusListRecord,
    ) -> Result<bool, RepositoryError> {
        Self::update_one(self, list_id, entity).await
    }

    async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        Self::delete_by(self, value).await
    }

    async fn find_by_issuer(&self, issuer: &str) -> Result<Vec<StatusListRecord>, RepositoryError> {
        Self::find_by_issuer(self, issuer).await
    }

    async fn find_all(&self) -> Result<Vec<StatusListRecord>, RepositoryError> {
        Self::find_all(self).await
    }

    async fn find_all_status_list_uris(&self) -> Result<Vec<String>, RepositoryError> {
        Self::find_all_status_list_uris(self).await
    }
}

#[cfg(feature = "postgres")]
impl SeaOrmStore<Credentials> {
    pub(crate) async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        let active: credentials::ActiveModel = entity.into();
        active
            .insert(&*self.db)
            .await
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;
        Ok(())
    }

    pub(crate) async fn find_one_by(
        &self,
        value: &str,
    ) -> Result<Option<Credentials>, RepositoryError> {
        credentials::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map(|opt| opt.map(Credentials::from))
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub(crate) async fn update_one(
        &self,
        issuer: &str,
        entity: Credentials,
    ) -> Result<bool, RepositoryError> {
        let existing = credentials::Entity::find_by_id(issuer)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))?;
        if existing.is_none() {
            return Ok(false);
        }
        let active: credentials::ActiveModel = entity.into();
        active
            .update(&*self.db)
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
        Ok(true)
    }

    pub(crate) async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        let result = credentials::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }
}

#[async_trait::async_trait]
#[cfg(feature = "postgres")]
impl CredentialRepository for SeaOrmStore<Credentials> {
    async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        Self::insert_one(self, entity).await
    }

    async fn find_one_by(&self, value: &str) -> Result<Option<Credentials>, RepositoryError> {
        Self::find_one_by(self, value).await
    }

    async fn update_one(&self, issuer: &str, entity: Credentials) -> Result<bool, RepositoryError> {
        Self::update_one(self, issuer, entity).await
    }

    async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        Self::delete_by(self, value).await
    }
}

#[async_trait::async_trait]
impl CredentialRepository for MemoryCredentialRepository {
    async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        self.values
            .write()
            .map_err(|_| {
                RepositoryError::Generic("memory credential repository lock poisoned".into())
            })?
            .insert(entity.issuer.clone(), entity);
        Ok(())
    }

    async fn find_one_by(&self, value: &str) -> Result<Option<Credentials>, RepositoryError> {
        Ok(self
            .values
            .read()
            .map_err(|_| {
                RepositoryError::Generic("memory credential repository lock poisoned".into())
            })?
            .get(value)
            .cloned())
    }

    async fn update_one(&self, issuer: &str, entity: Credentials) -> Result<bool, RepositoryError> {
        let mut values = self.values.write().map_err(|_| {
            RepositoryError::Generic("memory credential repository lock poisoned".into())
        })?;
        if !values.contains_key(issuer) {
            return Ok(false);
        }
        values.insert(entity.issuer.clone(), entity);
        Ok(true)
    }

    async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        Ok(self
            .values
            .write()
            .map_err(|_| {
                RepositoryError::Generic("memory credential repository lock poisoned".into())
            })?
            .remove(value)
            .is_some())
    }
}

#[async_trait::async_trait]
impl StatusListRepository for MemoryStatusListRepository {
    async fn insert_one(&self, entity: StatusListRecord) -> Result<(), RepositoryError> {
        self.values
            .write()
            .map_err(|_| {
                RepositoryError::Generic("memory status-list repository lock poisoned".into())
            })?
            .insert(entity.list_id.clone(), entity);
        Ok(())
    }

    async fn find_one_by(&self, value: &str) -> Result<Option<StatusListRecord>, RepositoryError> {
        Ok(self
            .values
            .read()
            .map_err(|_| {
                RepositoryError::Generic("memory status-list repository lock poisoned".into())
            })?
            .get(value)
            .cloned())
    }

    async fn find_all_by(&self, issuer: &str) -> Result<Vec<StatusListRecord>, RepositoryError> {
        Ok(self
            .values
            .read()
            .map_err(|_| {
                RepositoryError::Generic("memory status-list repository lock poisoned".into())
            })?
            .values()
            .filter(|record| record.issuer == issuer)
            .cloned()
            .collect())
    }

    async fn update_one(
        &self,
        list_id: &str,
        entity: StatusListRecord,
    ) -> Result<bool, RepositoryError> {
        let mut values = self.values.write().map_err(|_| {
            RepositoryError::Generic("memory status-list repository lock poisoned".into())
        })?;
        if !values.contains_key(list_id) {
            return Ok(false);
        }
        values.insert(entity.list_id.clone(), entity);
        Ok(true)
    }

    async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        Ok(self
            .values
            .write()
            .map_err(|_| {
                RepositoryError::Generic("memory status-list repository lock poisoned".into())
            })?
            .remove(value)
            .is_some())
    }

    async fn find_by_issuer(&self, issuer: &str) -> Result<Vec<StatusListRecord>, RepositoryError> {
        Ok(self
            .values
            .read()
            .map_err(|_| {
                RepositoryError::Generic("memory status-list repository lock poisoned".into())
            })?
            .values()
            .filter(|record| record.sub == issuer)
            .cloned()
            .collect())
    }

    async fn find_all(&self) -> Result<Vec<StatusListRecord>, RepositoryError> {
        Ok(self
            .values
            .read()
            .map_err(|_| {
                RepositoryError::Generic("memory status-list repository lock poisoned".into())
            })?
            .values()
            .cloned()
            .collect())
    }

    async fn find_all_status_list_uris(&self) -> Result<Vec<String>, RepositoryError> {
        let mut uris: Vec<_> = self
            .values
            .read()
            .map_err(|_| {
                RepositoryError::Generic("memory status-list repository lock poisoned".into())
            })?
            .values()
            .map(|record| record.sub.clone())
            .collect();
        uris.sort();
        uris.dedup();
        Ok(uris)
    }
}

#[cfg(all(test, feature = "postgres"))]
mod test {
    use super::*;
    use crate::models::StatusList;
    use jsonwebtoken::jwk::Jwk;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    #[tokio::test]
    async fn test_status_list_find_all() {
        let models = vec![
            status_lists::Model {
                list_id: "list1".to_string(),
                issuer: "issuer1".to_string(),
                status_list: StatusList {
                    bits: 1,
                    lst: "abc".to_string(),
                },
                sub: "https://example.com/statuslists/list1".to_string(),
            },
            status_lists::Model {
                list_id: "list2".to_string(),
                issuer: "issuer2".to_string(),
                status_list: StatusList {
                    bits: 8,
                    lst: "xyz".to_string(),
                },
                sub: "https://example.com/statuslists/list2".to_string(),
            },
        ];

        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![models.clone()])
                .into_connection(),
        );

        let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

        let records = store.find_all().await.unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].list_id, "list1");
        assert_eq!(records[0].sub, "https://example.com/statuslists/list1");
        assert_eq!(records[0].status_list.bits, 1);
        assert_eq!(records[0].status_list.lst, "abc");

        assert_eq!(records[1].list_id, "list2");
        assert_eq!(records[1].sub, "https://example.com/statuslists/list2");
        assert_eq!(records[1].status_list.bits, 8);
        assert_eq!(records[1].status_list.lst, "xyz");
    }

    #[tokio::test]
    async fn test_status_list_find_all_status_list_uris() {
        let rows = vec![
            std::collections::BTreeMap::from([(
                "sub".to_string(),
                sea_orm::Value::from("https://example.com/statuslists/a"),
            )]),
            std::collections::BTreeMap::from([(
                "sub".to_string(),
                sea_orm::Value::from("https://example.com/statuslists/b"),
            )]),
        ];

        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<std::collections::BTreeMap<String, sea_orm::Value>, Vec<_>, _>(
                    vec![rows],
                )
                .into_connection(),
        );

        let store = SeaOrmStore::<StatusListRecord>::new(db_conn);

        let subs = store.find_all_status_list_uris().await.unwrap();

        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0], "https://example.com/statuslists/a");
        assert_eq!(subs[1], "https://example.com/statuslists/b");
    }

    #[tokio::test]
    async fn test_seaorm_store() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);

        let public_key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();

        let entity = Credentials::new("issuer1".to_string(), public_key.clone());
        let updated_entity = Credentials::new("issuer1".to_string(), public_key.clone());

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<credentials::Model, Vec<_>, _>(vec![
                    vec![credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone().into(),
                    }], // Insert return
                    vec![credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone().into(),
                    }], // Find after insert
                    vec![credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone().into(),
                    }], // Find before update
                    vec![credentials::Model {
                        issuer: updated_entity.issuer.clone(),
                        public_key: updated_entity.public_key.clone().into(),
                    }], // Update return
                ])
                .append_exec_results(vec![
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // Delete
                ])
                .into_connection(),
        );

        let store = SeaOrmStore::<Credentials>::new(db_conn);

        // Insert
        store.insert_one(entity.clone()).await.unwrap();

        // Find
        let credential = store.find_one_by("issuer1").await.unwrap().unwrap();
        assert_eq!(credential.issuer, "issuer1");
        assert_eq!(credential.public_key, public_key);

        // Update
        let updated = store
            .update_one("issuer1", updated_entity.clone())
            .await
            .unwrap();
        assert!(updated);

        // Delete
        let deleted = store.delete_by("issuer1").await.unwrap();
        assert!(deleted);
    }
}
