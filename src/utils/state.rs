use crate::{
    database::queries::SeaOrmStore,
    model::{Credentials, StatusListToken},
};
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use std::sync::Arc;

use super::keygen::Keypair;

#[derive(Clone)]
pub struct AppState {
    pub credential_repository: Arc<SeaOrmStore<Credentials>>,
    pub status_list_token_repository: Arc<SeaOrmStore<StatusListToken>>,
    pub server_key: Arc<Keypair>,
    pub server_public_domain: String,
}

pub async fn setup() -> AppState {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL env not set");
    let db: DatabaseConnection = Database::connect(&url)
        .await
        .expect("Failed to connect to database");

    crate::database::Migrator::up(&db, None)
        .await
        .expect("Failed to apply migrations");

    // TODO : Not secure. We should find a way to store this key in a secure way
    // TODO : For example, using a vault or pkcs#8 encrypted pem
    let server_key = Keypair::from_pkcs8_pem(include_str!("../test_resources/ec-private.pem"))
        .expect("Failed to load server key");

    let server_public_domain =
        std::env::var("SERVER_PUBLIC_DOMAIN").expect("SERVER_PUBLIC_DOMAIN env not set");

    let db = Arc::new(db);
    AppState {
        credential_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        status_list_token_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        server_key: Arc::new(server_key),
        server_public_domain,
    }
}
