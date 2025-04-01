use crate::{
    database::queries::SeaOrmStore,
    model::{Credentials, StatusListToken},
};
use sea_orm::Database;
use sea_orm::DatabaseConnection;
use sea_orm_migration::MigratorTrait;
use std::env;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub repository: Option<AppStateRepository>,
}

#[derive(Clone)]
pub struct AppStateRepository {
    pub credential_repository: Arc<dyn crate::database::repository::Repository<Credentials>>,
    pub status_list_token_repository:
        Arc<dyn crate::database::repository::Repository<StatusListToken>>,
}

impl AppStateRepository {
    pub fn from(
        credential_repository: Arc<SeaOrmStore<Credentials>>,
        status_list_token_repository: Arc<SeaOrmStore<StatusListToken>>,
    ) -> Self {
        Self {
            credential_repository,
            status_list_token_repository,
        }
    }
}

pub async fn setup() -> AppState {
    let url = env::var("DATABASE_URL").expect("DATABASE_URL env not set");
    let db: DatabaseConnection = Database::connect(&url)
        .await
        .expect("Failed to connect to database");

    crate::database::Migrator::up(&db, None)
        .await
        .expect("Failed to apply migrations");

    let db = Arc::new(db);
    let credential_repo = SeaOrmStore::new(Arc::clone(&db));
    let status_list_repo = SeaOrmStore::new(Arc::clone(&db));

    AppState {
        repository: Some(AppStateRepository {
            credential_repository: Arc::new(credential_repo),
            status_list_token_repository: Arc::new(status_list_repo),
        }),
    }
}
