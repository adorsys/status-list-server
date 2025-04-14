use crate::{
    database::queries::SeaOrmStore,
    model::{Credentials, StatusListToken},
};
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub credential_repository: Arc<SeaOrmStore<Credentials>>,
    pub status_list_token_repository: Arc<SeaOrmStore<StatusListToken>>,
}

pub async fn setup() -> AppState {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL env not set");
    let db: DatabaseConnection = Database::connect(&url)
        .await
        .expect("Failed to connect to database");

    crate::database::Migrator::up(&db, None)
        .await
        .expect("Failed to apply migrations");

    let db = Arc::new(db);
    AppState {
        credential_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        status_list_token_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
    }
}
