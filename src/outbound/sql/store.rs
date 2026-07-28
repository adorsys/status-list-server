use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, TransactionTrait, sea_query::Expr,
};
use std::sync::Arc;

use super::error::RepositoryError;
use super::models::{
    Credentials, StatusListHistoryRecord, StatusListRecord, credentials, status_list_history,
    status_lists,
};

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
            updated_at: Set(entity.updated_at),
        };
        status_lists::Entity::insert(active)
            .exec_without_returning(&*self.db)
            .await
            .map_err(map_insert_err)?;
        Ok(())
    }

    pub async fn insert_one_with_snapshot(
        &self,
        entity: StatusListRecord,
        snapshot: StatusListHistoryRecord,
    ) -> Result<(), RepositoryError> {
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;

        let active = status_lists::ActiveModel {
            list_id: Set(entity.list_id),
            issuer: Set(entity.issuer),
            status_list: Set(entity.status_list),
            sub: Set(entity.sub),
            updated_at: Set(entity.updated_at),
        };
        if let Err(insert_err) = status_lists::Entity::insert(active)
            .exec_without_returning(&txn)
            .await
        {
            txn.rollback().await.map_err(|rollback_err| {
                RepositoryError::InsertError(format!(
                    "status list insert failed ({insert_err}); \
                     rolling the transaction back also failed: {rollback_err}"
                ))
            })?;
            return Err(map_insert_err(insert_err));
        }

        let history_active: status_list_history::ActiveModel = snapshot.into();
        if let Err(insert_err) = status_list_history::Entity::insert(history_active)
            .exec_without_returning(&txn)
            .await
        {
            txn.rollback().await.map_err(|rollback_err| {
                RepositoryError::InsertError(format!(
                    "history snapshot insert failed ({insert_err}); \
                     rolling back the status list insert also failed: {rollback_err}"
                ))
            })?;
            return Err(RepositoryError::InsertError(insert_err.to_string()));
        }

        txn.commit()
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
        expected_updated_at: i64,
    ) -> Result<bool, RepositoryError> {
        if entity.updated_at <= expected_updated_at {
            return Err(RepositoryError::UpdateError(format!(
                "guarded update requires a strictly newer updated_at \
                 (new={}, expected-guard={}); a non-advancing stamp would \
                 silently reintroduce the same-second lost update",
                entity.updated_at, expected_updated_at
            )));
        }
        let result = status_lists::Entity::update_many()
            .col_expr(status_lists::Column::Issuer, Expr::value(entity.issuer))
            .col_expr(
                status_lists::Column::StatusList,
                Expr::value(entity.status_list),
            )
            .col_expr(status_lists::Column::Sub, Expr::value(entity.sub))
            .col_expr(
                status_lists::Column::UpdatedAt,
                Expr::value(entity.updated_at),
            )
            .filter(status_lists::Column::ListId.eq(list_id))
            .filter(status_lists::Column::UpdatedAt.eq(expected_updated_at))
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
        Ok(result.rows_affected > 0)
    }

    pub async fn update_one_with_snapshot(
        &self,
        list_id: &str,
        entity: StatusListRecord,
        expected_updated_at: i64,
        snapshot: StatusListHistoryRecord,
    ) -> Result<bool, RepositoryError> {
        if entity.updated_at <= expected_updated_at {
            return Err(RepositoryError::UpdateError(format!(
                "guarded update requires a strictly newer updated_at \
                 (new={}, expected-guard={}); a non-advancing stamp would \
                 silently reintroduce the same-second lost update",
                entity.updated_at, expected_updated_at
            )));
        }

        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;

        let result = status_lists::Entity::update_many()
            .col_expr(status_lists::Column::Issuer, Expr::value(entity.issuer))
            .col_expr(
                status_lists::Column::StatusList,
                Expr::value(entity.status_list),
            )
            .col_expr(status_lists::Column::Sub, Expr::value(entity.sub))
            .col_expr(
                status_lists::Column::UpdatedAt,
                Expr::value(entity.updated_at),
            )
            .filter(status_lists::Column::ListId.eq(list_id))
            .filter(status_lists::Column::UpdatedAt.eq(expected_updated_at))
            .exec(&txn)
            .await
            .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;

        if result.rows_affected == 0 {
            txn.rollback()
                .await
                .map_err(|e| RepositoryError::UpdateError(e.to_string()))?;
            return Ok(false);
        }

        let history_active: status_list_history::ActiveModel = snapshot.into();
        if let Err(insert_err) = status_list_history::Entity::insert(history_active)
            .exec(&txn)
            .await
        {
            txn.rollback().await.map_err(|rollback_err| {
                RepositoryError::InsertError(format!(
                    "history snapshot insert failed ({insert_err}); \
                     rolling back the row update also failed: {rollback_err}"
                ))
            })?;
            return Err(RepositoryError::InsertError(insert_err.to_string()));
        }

        txn.commit()
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

    pub async fn find_all(&self) -> Result<Vec<StatusListRecord>, RepositoryError> {
        status_lists::Entity::find()
            .all(&*self.db)
            .await
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub async fn find_all_status_list_uris(&self) -> Result<Vec<String>, RepositoryError> {
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

impl SeaOrmStore<StatusListHistoryRecord> {
    pub async fn insert_one(&self, entity: StatusListHistoryRecord) -> Result<(), RepositoryError> {
        let active: status_list_history::ActiveModel = entity.into();
        status_list_history::Entity::insert(active)
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::InsertError(e.to_string()))?;
        Ok(())
    }

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
            .map_err(|e| RepositoryError::FindError(e.to_string()))
    }

    pub async fn delete_older_than(&self, cutoff: i64) -> Result<u64, RepositoryError> {
        let result = status_list_history::Entity::delete_many()
            .filter(status_list_history::Column::Exp.lt(cutoff))
            .exec(&*self.db)
            .await
            .map_err(|e| RepositoryError::DeleteError(e.to_string()))?;
        Ok(result.rows_affected)
    }
}

impl SeaOrmStore<Credentials> {
    pub async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        let active: credentials::ActiveModel = entity.into();
        credentials::Entity::insert(active)
            .exec_without_returning(&*self.db)
            .await
            .map_err(map_insert_err)?;
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

fn map_insert_err(e: sea_orm::DbErr) -> RepositoryError {
    match e.sql_err() {
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_)) => RepositoryError::DuplicateEntry,
        _ => RepositoryError::InsertError(e.to_string()),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::outbound::sql::models::StatusList;
    use sea_orm::{DatabaseBackend, MockDatabase};

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
                updated_at: 0,
            },
            status_lists::Model {
                list_id: "list2".to_string(),
                issuer: "issuer2".to_string(),
                status_list: StatusList {
                    bits: 8,
                    lst: "xyz".to_string(),
                },
                sub: "https://example.com/statuslists/list2".to_string(),
                updated_at: 0,
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
    }
}
