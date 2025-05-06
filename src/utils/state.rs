use crate::{
    database::queries::SeaOrmStore,
    model::{Credentials, StatusListToken},
};
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use std::sync::Arc;

use super::keygen::Keypair;
use super::secretmanager::{AwsSecret, Operations, Secret};
use aws_config::Region;

#[derive(Clone)]
pub struct AppState {
    pub credential_repository: Arc<SeaOrmStore<Credentials>>,
    pub status_list_token_repository: Arc<SeaOrmStore<StatusListToken>>,
    pub server_key: Arc<Keypair>,
}

pub async fn setup() -> AppState {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL env not set");
    let db: DatabaseConnection = Database::connect(&url)
        .await
        .expect("Failed to connect to database");

    crate::database::Migrator::up(&db, None)
        .await
        .expect("Failed to apply migrations");

    // --- AWS Keypair Logic ---
    let secret_name = std::env::var("SERVER_KEY_SECRET_NAME").expect("SERVER_KEY_SECRET_NAME env not set");
    let region = std::env::var("AWS_REGION").expect("AWS_REGION env not set");
    let region = Region::new(region);
    let aws_secret = AwsSecret::new(secret_name.clone(), region).await;

    let server_key = match aws_secret.get_key().await {
        Ok(Some(pem)) => {
            match Keypair::from_pkcs8_pem(&pem) {
                Ok(keypair) => {
                    tracing::info!("Server key loaded from AWS SecretManager");
                    keypair
                },
                Err(_) => {
                    tracing::warn!("Invalid key in AWS, generating new keypair");
                    let keypair = Keypair::generate().expect("Failed to generate keypair");
                    let pem = keypair.to_pkcs8_pem().expect("Failed to serialize keypair");
                    let secret = Secret::new(secret_name.clone(), pem.clone());
                    let _ = aws_secret.store_key(secret).await;
                    keypair
                }
            } 
        },
        Ok(None) => {
            tracing::info!("No key found in AWS, generating new keypair");
            let keypair = Keypair::generate().expect("Failed to generate keypair");
            let pem = keypair.to_pkcs8_pem().expect("Failed to serialize keypair");
            let secret = Secret::new(secret_name.clone(), pem.clone());
            let _ = aws_secret.store_key(secret).await;
            keypair
        },
        Err(e) => {
            tracing::error!("Error accessing AWS SecretManager: {:?}", e);
            panic!("Failed to access AWS SecretManager");
        }
    };

    let db = Arc::new(db);
    AppState {
        credential_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        status_list_token_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        server_key: Arc::new(server_key),
    }
}

/// Ensures a server key exists in AWS SecretManager. If not, generates and stores a new one.
pub async fn ensure_server_key_exists() {
    let secret_name = std::env::var("SERVER_KEY_SECRET_NAME").expect("SERVER_KEY_SECRET_NAME env not set");
    let region = std::env::var("AWS_REGION").expect("AWS_REGION env not set");
    let region = Region::new(region);
    let aws_secret = AwsSecret::new(secret_name.clone(), region).await;

    match aws_secret.get_key().await {
        Ok(Some(_)) => {
            tracing::info!("Server key already exists in AWS SecretManager");
            // Do nothing else
        },
        Ok(None) => {
            tracing::info!("No key found in AWS, generating and storing new keypair");
            let keypair = Keypair::generate().expect("Failed to generate keypair");
            let pem = keypair.to_pkcs8_pem().expect("Failed to serialize keypair");
            let secret = Secret::new(secret_name.clone(), pem.clone());
            let _ = aws_secret.store_key(secret).await;
        },
        Err(e) => {
            tracing::error!("Error accessing AWS SecretManager: {:?}", e);
            panic!("Failed to access AWS SecretManager");
        }
    }
}
