use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, QueryFilter, QueryOrder, Statement,
    Value,
};
use tracing::warn;

use super::super::error::RepositoryError;
use super::super::models::{StatusListHistoryRecord, status_list_history};
use super::SeaOrmStore;
use super::helpers::{find_err, map_delete_err, map_snapshot_insert_err};

impl SeaOrmStore<StatusListHistoryRecord> {
    #[tracing::instrument(skip(self, entity), fields(db.system = "sea-orm"))]
    pub async fn insert_one(&self, entity: StatusListHistoryRecord) -> Result<(), RepositoryError> {
        let active: status_list_history::ActiveModel = entity.into();
        status_list_history::Entity::insert(active)
            .exec_without_returning(&*self.db)
            .await
            .map_err(map_snapshot_insert_err)?;
        Ok(())
    }

    /// Finds the snapshot whose half-open validity interval contains `time`.
    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn find_valid_at(
        &self,
        list_id: &str,
        time: i64,
    ) -> Result<Option<StatusListHistoryRecord>, RepositoryError> {
        status_list_history::Entity::find()
            .filter(status_list_history::Column::ListId.eq(list_id))
            .filter(status_list_history::Column::Iat.lte(time))
            .filter(status_list_history::Column::Exp.gt(time))
            .order_by_desc(status_list_history::Column::Iat)
            .one(&*self.db)
            .await
            .map_err(find_err)
    }

    /// Deletes snapshots older than the given cutoff timestamp.
    #[tracing::instrument(skip(self), fields(db.system = "sea-orm"))]
    pub async fn delete_older_than(&self, cutoff: i64) -> Result<u64, RepositoryError> {
        const BATCH_SIZE: u64 = 500;
        let mut total_deleted: u64 = 0;

        loop {
            let backend = self.db.get_database_backend();
            let sql = match backend {
                DatabaseBackend::Postgres => {
                    "DELETE FROM status_list_history \
                     WHERE snapshot_id IN \
                     (SELECT snapshot_id FROM status_list_history WHERE exp < $1 LIMIT $2)"
                }
                DatabaseBackend::MySql => "DELETE FROM status_list_history WHERE exp < ? LIMIT ?",
                _ => {
                    "DELETE FROM status_list_history \
                     WHERE snapshot_id IN \
                     (SELECT snapshot_id FROM status_list_history WHERE exp < ? LIMIT ?)"
                }
            };

            let count = (*self.db)
                .execute(Statement::from_sql_and_values(
                    backend,
                    sql,
                    vec![Value::from(cutoff), Value::from(BATCH_SIZE)],
                ))
                .await
                .map_err(map_delete_err)?
                .rows_affected();

            total_deleted += count;

            if count < BATCH_SIZE {
                break;
            }
        }

        if total_deleted > 0 {
            warn!(
                deleted = total_deleted,
                cutoff, "Deleted expired status list history snapshots"
            );
        }

        Ok(total_deleted)
    }
}
