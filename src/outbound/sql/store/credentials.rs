use sea_orm::ActiveModelTrait;
use sea_orm::EntityTrait;

use super::super::error::RepositoryError;
use super::super::models::{Credentials, credentials};
use super::SeaOrmStore;
use super::helpers::{
    find_err, map_delete_err, map_insert_err, map_update_err, rollback_and_map_err,
};

impl SeaOrmStore<Credentials> {
    /// Pinned so registration cannot inherit a raised server default.
    pub async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        let active: credentials::ActiveModel = entity.into();
        let txn = self.begin_read_committed().await.map_err(map_insert_err)?;
        if let Err(insert_err) = credentials::Entity::insert(active)
            .exec_without_returning(&txn)
            .await
        {
            return Err(
                rollback_and_map_err(txn, insert_err, "credential insert", map_insert_err).await,
            );
        }
        txn.commit().await.map_err(map_insert_err)?;
        Ok(())
    }

    pub async fn find_one_by(&self, value: &str) -> Result<Option<Credentials>, RepositoryError> {
        credentials::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map(|opt| opt.map(Credentials::from))
            .map_err(find_err)
    }

    pub async fn update_one(
        &self,
        issuer: &str,
        entity: Credentials,
    ) -> Result<bool, RepositoryError> {
        let existing = credentials::Entity::find_by_id(issuer)
            .one(&*self.db)
            .await
            .map_err(find_err)?;
        if existing.is_none() {
            return Ok(false);
        }
        let active: credentials::ActiveModel = entity.into();
        active.update(&*self.db).await.map_err(map_update_err)?;
        Ok(true)
    }

    pub async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        let result = credentials::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(map_delete_err)?;
        Ok(result.rows_affected > 0)
    }
}
