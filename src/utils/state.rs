use crate::{
    database::queries::SeaOrmStore,
    model::{Credentials, StatusListToken},
    utils::errors::Error,
};
use async_trait::async_trait;
use aws_sdk_secretsmanager::config::Region;
use aws_sdk_secretsmanager::error::ProvideErrorMetadata;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_secretsmanager_cache::{CacheConfig, SecretCache};
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use std::sync::Arc;

use super::keygen::Keypair;

#[async_trait]
pub trait SecretCacheTrait: Send + Sync {
    async fn get_secret_string(&self, secret_id: String) -> Result<Option<String>, String>;
}

#[async_trait]
impl SecretCacheTrait for SecretCache {
    async fn get_secret_string(&self, secret_id: String) -> Result<Option<String>, String> {
        match self.get_secret_string(secret_id).await {
            Ok(val) => Ok(val),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub struct MockSecretCache {
    pub value: Option<String>,
}

#[async_trait]
impl SecretCacheTrait for MockSecretCache {
    async fn get_secret_string(&self, _secret_id: String) -> Result<Option<String>, String> {
        Ok(self.value.clone())
    }
}

#[derive(Clone)]
pub struct AppState {
    pub credential_repository: Arc<SeaOrmStore<Credentials>>,
    pub status_list_token_repository: Arc<SeaOrmStore<StatusListToken>>,
    pub secret_cache: Arc<dyn SecretCacheTrait>,
    pub server_secret_name: String,
}

pub async fn setup() -> AppState {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL env not set");
    let db: DatabaseConnection = Database::connect(&url)
        .await
        .expect("Failed to connect to database");

    crate::database::Migrator::up(&db, None)
        .await
        .expect("Failed to apply migrations");

    let secret_name =
        std::env::var("SERVER_KEY_SECRET_NAME").expect("SERVER_KEY_SECRET_NAME env not set");
    let region = std::env::var("AWS_REGION").expect("AWS_REGION env not set");
    let aws_config = aws_config::from_env()
        .region(Region::new(region))
        .load()
        .await;
    let client = SecretsManagerClient::new(&aws_config);

    // Ensure secret exists
    match client
        .describe_secret()
        .secret_id(secret_name.clone())
        .send()
        .await
    {
        Ok(_) => {
            tracing::info!("Server key secret already exists in AWS Secrets Manager");
        }
        Err(e) => {
            let error_message = e.to_string();
            let service_error = e.into_service_error();
            if service_error.code() == Some("ResourceNotFoundException") {
                tracing::info!(
                    "No server key secret found in AWS, generating and storing new keypair"
                );
                let keypair = Keypair::generate()
                    .map_err(|_| Error::KeyGenFailed)
                    .expect("Failed to generate keypair");
                let pem = keypair
                    .to_pkcs8_pem()
                    .map_err(|_| Error::PemGenFailed)
                    .expect("Failed to serialize keypair");
                client
                    .create_secret()
                    .name(secret_name.clone())
                    .secret_string(pem)
                    .send()
                    .await
                    .map_err(|e| Error::Generic(e.to_string()))
                    .expect("Failed to create secret");
            } else {
                tracing::error!("Error describing secret: {:?}", error_message);
                panic!(
                    "Failed to access AWS Secrets Manager: {}",
                    Error::Generic(error_message)
                );
            }
        }
    }

    // Create secret cache with TTL
    let config = CacheConfig {
        cache_item_ttl: 3600 * 1_000_000_000, // 1 hour in nanoseconds
        ..CacheConfig::default()
    };
    let cache = SecretCache::new_with_config(client, config);

    let db = Arc::new(db);
    AppState {
        credential_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        status_list_token_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        secret_cache: Arc::new(cache),
        server_secret_name: secret_name,
    }
}
