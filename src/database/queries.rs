use async_trait::async_trait;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::model::{credentials, status_list_tokens, Credentials, StatusListToken};

use super::{
    error::RepositoryError,
    repository::{Repository, Table},
};

pub struct SeaOrmStore<T> {
    db: Arc<DatabaseConnection>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> SeaOrmStore<T> {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self {
            db,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl Repository<StatusListToken> for SeaOrmStore<StatusListToken> {
    fn get_table(&self) -> Table<StatusListToken> {
        Table::new(
            Arc::clone(&self.db),
            "status_list_tokens".to_string(),
            "list_id".to_string(),
        )
    }

    async fn insert_one(&self, entity: StatusListToken) -> Result<(), RepositoryError> {
        let active = status_list_tokens::ActiveModel {
            list_id: Set(entity.list_id),
            exp: Set(entity.exp),
            iat: Set(entity.iat),
            status_list: Set(serde_json::to_string(&entity.status_list)
                .map_err(|e| RepositoryError::InsertError(e.to_string()))?),
            sub: Set(entity.sub),
            ttl: Set(entity.ttl),
        };
        active
            .insert(&*self.db)
            .await
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;
        Ok(())
    }

    async fn find_one_by(&self, value: String) -> Result<Option<StatusListToken>, RepositoryError> {
        status_list_tokens::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map(|opt| opt.map(StatusListToken::from))
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    async fn update_one(
        &self,
        issuer: String,
        entity: StatusListToken,
    ) -> Result<bool, RepositoryError> {
        let existing = status_list_tokens::Entity::find_by_id(&issuer)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))?;
        if existing.is_none() {
            return Ok(false);
        }
        let active = status_list_tokens::ActiveModel {
            list_id: Set(entity.list_id),
            exp: Set(entity.exp),
            iat: Set(entity.iat),
            status_list: Set(serde_json::to_string(&entity.status_list)
                .map_err(|e| RepositoryError::UpdateError(e.to_string()))?),
            sub: Set(entity.sub),
            ttl: Set(entity.ttl),
        };
        active
            .update(&*self.db)
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
        Ok(true)
    }

    async fn delete_by(&self, value: String) -> Result<bool, RepositoryError> {
        let result = status_list_tokens::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }
}

#[async_trait]
impl Repository<Credentials> for SeaOrmStore<Credentials> {
    fn get_table(&self) -> Table<Credentials> {
        Table::new(
            Arc::clone(&self.db),
            "credentials".to_string(),
            "issuer".to_string(),
        )
    }

    async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        let active = credentials::ActiveModel {
            issuer: Set(entity.issuer),
            public_key: Set(entity.public_key),
            alg: Set(format!("{:?}", entity.alg)),
        };
        active
            .insert(&*self.db)
            .await
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;
        Ok(())
    }

    async fn find_one_by(&self, value: String) -> Result<Option<Credentials>, RepositoryError> {
        credentials::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map(|opt| opt.map(Credentials::from))
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    async fn update_one(
        &self,
        issuer: String,
        entity: Credentials,
    ) -> Result<bool, RepositoryError> {
        let existing = credentials::Entity::find_by_id(&issuer)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))?;
        if existing.is_none() {
            return Ok(false);
        }
        let active = credentials::ActiveModel {
            issuer: Set(entity.issuer),
            public_key: Set(entity.public_key),
            alg: Set(format!("{:?}", entity.alg)),
        };
        active
            .update(&*self.db)
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
        Ok(true)
    }

    async fn delete_by(&self, value: String) -> Result<bool, RepositoryError> {
        let result = credentials::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }
}

// MockStore remains unchanged
pub struct MockStore<T> {
    pub(crate) repository: Arc<RwLock<HashMap<String, T>>>,
}

#[async_trait]
impl Repository<StatusListToken> for MockStore<StatusListToken> {
    fn get_table(&self) -> Table<StatusListToken> {
        unimplemented!("this is not real db")
    }
    async fn insert_one(&self, entity: StatusListToken) -> Result<(), RepositoryError> {
        self.repository
            .write()
            .unwrap()
            .insert(entity.list_id.clone(), entity);
        Ok(())
    }
    async fn find_one_by(&self, value: String) -> Result<Option<StatusListToken>, RepositoryError> {
        Ok(self.repository.read().unwrap().get(&value).cloned())
    }
    async fn update_one(
        &self,
        issuer: String,
        entity: StatusListToken,
    ) -> Result<bool, RepositoryError> {
        let mut repo = self.repository.write().unwrap();
        if let std::collections::hash_map::Entry::Occupied(mut e) = repo.entry(issuer) {
            e.insert(entity);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    async fn delete_by(&self, value: String) -> Result<bool, RepositoryError> {
        Ok(self.repository.write().unwrap().remove(&value).is_some())
    }
}

#[async_trait]
impl Repository<Credentials> for MockStore<Credentials> {
    fn get_table(&self) -> Table<Credentials> {
        unimplemented!("this is not real db")
    }
    async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        self.repository
            .write()
            .unwrap()
            .insert(entity.issuer.clone(), entity);
        Ok(())
    }
    async fn find_one_by(&self, value: String) -> Result<Option<Credentials>, RepositoryError> {
        Ok(self.repository.read().unwrap().get(&value).cloned())
    }
    async fn update_one(
        &self,
        issuer: String,
        entity: Credentials,
    ) -> Result<bool, RepositoryError> {
        if self.repository.read().unwrap().contains_key(&issuer) {
            self.repository.write().unwrap().insert(issuer, entity);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    async fn delete_by(&self, value: String) -> Result<bool, RepositoryError> {
        Ok(self.repository.write().unwrap().remove(&value).is_some())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::credentials::Model as CredentialsModel;
    use jsonwebtoken::Algorithm;
    use sea_orm::{MockDatabase, MockExecResult};

    #[tokio::test]
    async fn test_sea_orm_store() {
        let db = MockDatabase::new(sea_orm::DatabaseBackend::Postgres)
            .append_query_results(vec![
                vec![CredentialsModel {
                    // Result for insert
                    issuer: "issuer1".to_string(),
                    public_key: "test_public_key".to_string(),
                    alg: format!("{:?}", Algorithm::HS256),
                }],
                vec![CredentialsModel {
                    // Result for find_one_by
                    issuer: "issuer1".to_string(),
                    public_key: "test_public_key".to_string(),
                    alg: format!("{:?}", Algorithm::HS256),
                }],
                vec![CredentialsModel {
                    // Result for update_one's find_by_id
                    issuer: "issuer1".to_string(),
                    public_key: "test_public_key".to_string(),
                    alg: format!("{:?}", Algorithm::HS256),
                }],
                vec![CredentialsModel {
                    // Result for update_one's update
                    issuer: "issuer1".to_string(),
                    public_key: "new_public_key".to_string(),
                    alg: format!("{:?}", Algorithm::RS256),
                }],
            ])
            .append_exec_results(vec![
                MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                }, // Insert
                MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                }, // Update
                MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                }, // Delete
            ])
            .into_connection();

        let store = SeaOrmStore::new(Arc::new(db));

        let entity = Credentials::new(
            "issuer1".to_string(),
            "test_public_key".to_string(),
            Algorithm::HS256, // Now an Algorithm enum
        );
        store.insert_one(entity.clone()).await.unwrap();

        let credential = store
            .find_one_by("issuer1".to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(credential.issuer, "issuer1");
        assert_eq!(credential.public_key, "test_public_key");
        assert_eq!(credential.alg, Algorithm::HS256);

        let new_entity = Credentials::new(
            "issuer1".to_string(),
            "new_public_key".to_string(),
            Algorithm::RS256, // Now an Algorithm enum
        );
        let updated = store
            .update_one("issuer1".to_string(), new_entity.clone())
            .await
            .unwrap();
        assert!(updated);

        let deleted = store.delete_by("issuer1".to_string()).await.unwrap();
        assert!(deleted);
    }
}
