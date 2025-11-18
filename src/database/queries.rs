use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::sync::Arc;

use super::error::RepositoryError;
use crate::models::{credentials, status_lists, Credentials, StatusListRecord};

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

impl SeaOrmStore<StatusListRecord> {
    pub async fn insert_one(&self, entity: StatusListRecord) -> Result<(), RepositoryError> {
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

    pub async fn find_one_by(
        &self,
        value: &str,
    ) -> Result<Option<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub async fn find_all_by(
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

    pub async fn update_one(
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

    pub async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        let result = status_lists::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }

    pub async fn find_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .filter(status_lists::Column::Sub.eq(issuer))
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

    pub async fn find_one_by(&self, value: &str) -> Result<Option<Credentials>, RepositoryError> {
        credentials::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map(|opt| opt.map(Credentials::from))
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub async fn update_one(
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

    pub async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        let result = credentials::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use jsonwebtoken::jwk::Jwk;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

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
