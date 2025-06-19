use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::sync::Arc;

use super::error::RepositoryError;
use crate::models::{credentials, status_list_tokens, Credentials, StatusListToken};

#[derive(Clone)]
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

impl SeaOrmStore<StatusListToken> {
    pub async fn insert_one(&self, entity: StatusListToken) -> Result<(), RepositoryError> {
        let active = status_list_tokens::ActiveModel {
            list_id: Set(entity.list_id),
            issuer: Set(entity.issuer),
            exp: Set(entity.exp),
            iat: Set(entity.iat),
            status_list: Set(entity.status_list),
            sub: Set(entity.sub),
            ttl: Set(entity.ttl),
        };
        active
            .insert(&*self.db)
            .await
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;
        Ok(())
    }

    pub async fn find_one_by(
        &self,
        value: String,
    ) -> Result<Option<StatusListToken>, RepositoryError> {
        status_list_tokens::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub async fn update_one(
        &self,
        list_id: String,
        entity: StatusListToken,
    ) -> Result<bool, RepositoryError> {
        let existing = status_list_tokens::Entity::find_by_id(&list_id)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))?;
        if existing.is_none() {
            return Ok(false);
        }
        let active = status_list_tokens::ActiveModel {
            list_id: Set(entity.list_id),
            issuer: Set(entity.issuer),
            exp: Set(entity.exp),
            iat: Set(entity.iat),
            status_list: Set(entity.status_list),
            sub: Set(entity.sub),
            ttl: Set(entity.ttl),
        };
        active
            .update(&*self.db)
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
        Ok(true)
    }

    pub async fn delete_by(&self, value: String) -> Result<bool, RepositoryError> {
        let result = status_list_tokens::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }

    pub async fn find_all_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListToken>, RepositoryError> {
        status_list_tokens::Entity::find()
            .filter(status_list_tokens::Column::Sub.eq(issuer))
            .all(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }
}

impl SeaOrmStore<Credentials> {
    pub async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        let active: credentials::ActiveModel = entity.into();
        active
            .insert(&*self.db)
            .await
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;
        Ok(())
    }

    pub async fn find_one_by(&self, value: String) -> Result<Option<Credentials>, RepositoryError> {
        credentials::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map(|opt| opt.map(Credentials::from))
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub async fn update_one(
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
        let active: credentials::ActiveModel = entity.into();
        active
            .update(&*self.db)
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
        Ok(true)
    }

    pub async fn delete_by(&self, value: String) -> Result<bool, RepositoryError> {
        let result = credentials::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }
}

#[cfg(test)]
mod test {
    use crate::models;

    use super::*;
    use jsonwebtoken::Algorithm;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    #[tokio::test]
    async fn test_seaorm_store() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);

        let entity = Credentials::new(
            "issuer1".to_string(),
            "test_public_key".to_string(),
            Algorithm::HS256,
        );
        let updated_entity = Credentials::new(
            "issuer1".to_string(),
            "new_public_key".to_string(),
            Algorithm::RS256,
        );

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<credentials::Model, Vec<_>, _>(vec![
                    vec![credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone(),
                        alg: models::Alg(entity.alg),
                    }], // Insert return
                    vec![credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone(),
                        alg: models::Alg(entity.alg),
                    }], // Find after insert
                    vec![credentials::Model {
                        issuer: entity.issuer.clone(),
                        public_key: entity.public_key.clone(),
                        alg: models::Alg(entity.alg),
                    }], // Find before update
                    vec![credentials::Model {
                        issuer: updated_entity.issuer.clone(),
                        public_key: updated_entity.public_key.clone(),
                        alg: models::Alg(updated_entity.alg),
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
        let credential = store
            .find_one_by("issuer1".to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(credential.issuer, "issuer1");
        assert_eq!(credential.public_key, "test_public_key");
        assert_eq!(credential.alg, Algorithm::HS256);

        // Update
        let updated = store
            .update_one("issuer1".to_string(), updated_entity.clone())
            .await
            .unwrap();
        assert!(updated);

        // Delete
        let deleted = store.delete_by("issuer1".to_string()).await.unwrap();
        assert!(deleted);
    }
}
