use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, sea_query::Expr,
};

use super::super::error::RepositoryError;
use super::super::models::{
    StatusListHistoryRecord, StatusListRecord, status_list_history, status_lists,
};
use super::SeaOrmStore;
use super::helpers::{
    find_err, map_delete_err, map_insert_err, map_snapshot_insert_err, map_update_err,
    rollback_and_map_err, validate_advancing_stamp,
};

#[cfg(test)]
use super::hooks::snapshot_txn_test_hook;

impl From<&StatusListRecord> for status_lists::ActiveModel {
    fn from(entity: &StatusListRecord) -> Self {
        status_lists::ActiveModel {
            list_id: Set(entity.list_id.clone()),
            issuer: Set(entity.issuer.clone()),
            status_list: Set(entity.status_list.clone()),
            sub: Set(entity.sub.clone()),
            updated_at: Set(entity.updated_at),
        }
    }
}

async fn execute_guarded_update(
    txn: &sea_orm::DatabaseTransaction,
    list_id: &str,
    entity: &StatusListRecord,
    expected_updated_at: i64,
) -> Result<sea_orm::UpdateResult, sea_orm::DbErr> {
    status_lists::Entity::update_many()
        .col_expr(
            status_lists::Column::Issuer,
            Expr::value(entity.issuer.clone()),
        )
        .col_expr(
            status_lists::Column::StatusList,
            Expr::value(entity.status_list.clone()),
        )
        .col_expr(status_lists::Column::Sub, Expr::value(entity.sub.clone()))
        .col_expr(
            status_lists::Column::UpdatedAt,
            Expr::value(entity.updated_at),
        )
        .filter(status_lists::Column::ListId.eq(list_id))
        .filter(status_lists::Column::UpdatedAt.eq(expected_updated_at))
        .exec(txn)
        .await
}

impl SeaOrmStore<StatusListRecord> {
    /// Pinned like `insert_one_with_snapshot`, so a racing publish reports the
    /// same error whichever path `history_retention_secs` selects.
    #[tracing::instrument(skip(self, entity), fields(db.system = "sea-orm"))]
    pub async fn insert_one(&self, entity: StatusListRecord) -> Result<(), RepositoryError> {
        let active: status_lists::ActiveModel = (&entity).into();
        let txn = self.begin_read_committed().await.map_err(map_insert_err)?;
        if let Err(insert_err) = status_lists::Entity::insert(active)
            .exec_without_returning(&txn)
            .await
        {
            return Err(rollback_and_map_err(
                txn,
                insert_err,
                "status list insert",
                map_insert_err,
            )
            .await);
        }
        txn.commit().await.map_err(map_insert_err)?;
        Ok(())
    }

    /// Like [`insert_one`](Self::insert_one), but the row `INSERT` and the
    /// `status_list_history` `INSERT` covering its initial state run in one
    /// transaction: both commit or neither does.
    #[tracing::instrument(skip(self, entity, snapshot))]
    pub async fn insert_one_with_snapshot(
        &self,
        entity: StatusListRecord,
        snapshot: StatusListHistoryRecord,
    ) -> Result<(), RepositoryError> {
        #[cfg(test)]
        let probed_list_id = entity.list_id.clone();

        if snapshot.list_id != entity.list_id {
            return Err(RepositoryError::InsertError(format!(
                "snapshot list_id ({}) does not match entity list_id ({})",
                snapshot.list_id, entity.list_id
            )));
        }

        let txn = self.begin_read_committed().await.map_err(map_insert_err)?;

        let active: status_lists::ActiveModel = (&entity).into();
        if let Err(insert_err) = status_lists::Entity::insert(active)
            .exec_without_returning(&txn)
            .await
        {
            return Err(rollback_and_map_err(
                txn,
                insert_err,
                "status list insert",
                map_insert_err,
            )
            .await);
        }

        let history_active: status_list_history::ActiveModel = snapshot.into();
        if let Err(insert_err) = status_list_history::Entity::insert(history_active)
            .exec_without_returning(&txn)
            .await
        {
            return Err(rollback_and_map_err(
                txn,
                insert_err,
                "history snapshot insert",
                map_snapshot_insert_err,
            )
            .await);
        }

        #[cfg(test)]
        snapshot_txn_test_hook::INSERT_BEFORE_COMMIT
            .pause(&probed_list_id)
            .await;

        txn.commit().await.map_err(map_insert_err)?;
        Ok(())
    }

    pub async fn find_one_by(
        &self,
        value: &str,
    ) -> Result<Option<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find_by_id(value)
            .one(&*self.db)
            .await
            .map_err(find_err)
    }

    #[tracing::instrument(skip(self), fields(issuer))]
    pub async fn find_all_by(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .filter(status_lists::Column::Issuer.eq(issuer))
            .all(&*self.db)
            .await
            .map(|tokens| tokens.into_iter().collect())
            .map_err(find_err)
    }

    /// Optimistic-concurrency update guarded on `updated_at`:
    /// `UPDATE ... WHERE list_id = ? AND updated_at = ?`.
    #[tracing::instrument(skip(self, entity), fields(db.system = "sea-orm"))]
    pub async fn update_one(
        &self,
        list_id: &str,
        entity: StatusListRecord,
        expected_updated_at: i64,
    ) -> Result<bool, RepositoryError> {
        validate_advancing_stamp(entity.updated_at, expected_updated_at)?;
        let txn = self.begin_read_committed().await.map_err(map_update_err)?;

        let result = match execute_guarded_update(&txn, list_id, &entity, expected_updated_at).await
        {
            Ok(result) => result,
            Err(update_err) => {
                return Err(rollback_and_map_err(
                    txn,
                    update_err,
                    "guarded update",
                    map_update_err,
                )
                .await);
            }
        };

        txn.commit().await.map_err(map_update_err)?;
        Ok(result.rows_affected > 0)
    }

    /// Like [`update_one`](Self::update_one), but the guarded `UPDATE` and the
    /// `status_list_history` `INSERT` run in one transaction.
    #[tracing::instrument(skip(self, entity, snapshot), fields(db.system = "sea-orm"))]
    pub async fn update_one_with_snapshot(
        &self,
        list_id: &str,
        entity: StatusListRecord,
        expected_updated_at: i64,
        snapshot: StatusListHistoryRecord,
    ) -> Result<bool, RepositoryError> {
        if snapshot.list_id != list_id || entity.list_id != list_id {
            return Err(RepositoryError::UpdateError(format!(
                "snapshot list_id ({}) or entity list_id ({}) does not match list_id ({})",
                snapshot.list_id, entity.list_id, list_id
            )));
        }

        validate_advancing_stamp(entity.updated_at, expected_updated_at)?;
        let txn = self.begin_read_committed().await.map_err(map_update_err)?;

        let result = match execute_guarded_update(&txn, list_id, &entity, expected_updated_at).await
        {
            Ok(result) => result,
            Err(update_err) => {
                return Err(rollback_and_map_err(
                    txn,
                    update_err,
                    "guarded update",
                    map_update_err,
                )
                .await);
            }
        };

        if result.rows_affected == 0 {
            if let Err(e) = txn.rollback().await {
                tracing::warn!(error = ?e, "rollback of empty conflict transaction failed");
            }
            return Ok(false);
        }

        let history_active: status_list_history::ActiveModel = snapshot.into();
        if let Err(insert_err) = status_list_history::Entity::insert(history_active)
            .exec_without_returning(&txn)
            .await
        {
            return Err(rollback_and_map_err(
                txn,
                insert_err,
                "history snapshot insert",
                map_snapshot_insert_err,
            )
            .await);
        }

        #[cfg(test)]
        snapshot_txn_test_hook::UPDATE_BEFORE_COMMIT
            .pause(list_id)
            .await;

        txn.commit().await.map_err(map_update_err)?;
        Ok(true)
    }

    pub async fn delete_by(&self, value: &str) -> Result<bool, RepositoryError> {
        let result = status_lists::Entity::delete_by_id(value)
            .exec(&*self.db)
            .await
            .map_err(map_delete_err)?;
        Ok(result.rows_affected > 0)
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .filter(status_lists::Column::Sub.eq(issuer))
            .all(&*self.db)
            .await
            .map_err(find_err)
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_all(&self) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .all(&*self.db)
            .await
            .map_err(find_err)
    }

    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_all_status_list_uris(&self) -> Result<Vec<String>, RepositoryError> {
        status_lists::Entity::find()
            .select_only()
            .column(status_lists::Column::Sub)
            .group_by(status_lists::Column::Sub)
            .order_by_asc(status_lists::Column::Sub)
            .into_tuple::<String>()
            .all(&*self.db)
            .await
            .map_err(find_err)
    }
}
