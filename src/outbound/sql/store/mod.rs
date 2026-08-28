use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr,
    IsolationLevel, TransactionTrait,
};
use std::sync::Arc;

mod credentials;
mod helpers;
mod history;
mod status_list;

#[cfg(test)]
pub(crate) mod hooks;

#[cfg(test)]
mod tests;

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

    /// Begins a transaction pinned to READ COMMITTED, so PostgreSQL and MySQL
    /// run at the same level rather than at their differing defaults (READ
    /// COMMITTED and REPEATABLE READ).
    async fn begin_read_committed(&self) -> Result<DatabaseTransaction, DbErr> {
        match self.db.get_database_backend() {
            DatabaseBackend::Postgres | DatabaseBackend::MySql => {
                self.db
                    .begin_with_config(Some(IsolationLevel::ReadCommitted), None)
                    .await
            }
            _ => self.db.begin().await,
        }
    }
}
