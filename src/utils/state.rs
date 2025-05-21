use super::keygen::Keypair;
use crate::{
    database::queries::SeaOrmStore,
    model::{Credentials, StatusListToken},
    utils::errors::{Error, SecretCacheError},
};
use async_trait::async_trait;
use aws_sdk_secretsmanager::{
    config::Region, error::ProvideErrorMetadata, Client as SecretsManagerClient,
};
use aws_secretsmanager_caching::SecretsManagerCachingClient;
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tracing::info;

// Define the SecretCache
#[async_trait]
pub trait SecretCache: Send + Sync {
    async fn get_secret_string(
        &self,
        secret_id: String,
    ) -> Result<Option<String>, SecretCacheError>;
}

// Define a wrapper struct for SecretsManagerCachingClient
pub struct AwsSecretCache {
    inner: SecretsManagerCachingClient,
}

// Implement SecretCache for AwsSecretCache
#[async_trait]
impl SecretCache for AwsSecretCache {
    async fn get_secret_string(
        &self,
        secret_id: String,
    ) -> Result<Option<String>, SecretCacheError> {
        match self
            .inner
            .get_secret_value(&secret_id, None, None, false)
            .await
        {
            Ok(output) => Ok(output.secret_string),
            Err(e) => Err(SecretCacheError::AwsSdkError(e.to_string())),
        }
    }
}

/// A type that manages server secrets and their caching
#[derive(Clone)]
pub struct SecretManager {
    cache: Arc<dyn SecretCache>,
    server_secret_name: String,
}

impl SecretManager {
    pub fn new(cache: Arc<dyn SecretCache>, server_secret_name: String) -> Self {
        Self {
            cache,
            server_secret_name,
        }
    }

    pub async fn get_server_secret(&self) -> Result<Option<String>, SecretCacheError> {
        self.cache
            .get_secret_string(self.server_secret_name.clone())
            .await
    }

    /// Creates a new SecretManager instance and ensures the server secret exists
    pub async fn setup(secret_name: String, region: String) -> Result<Self, Error> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest())
            .await
            .into_builder()
            .region(Region::new(region))
            .build();
        let client = SecretsManagerClient::new(&config);

        // Ensure secret exists
        match client
            .describe_secret()
            .secret_id(secret_name.clone())
            .send()
            .await
        {
            Ok(e) => {
                tracing::info!("Server key secret already exists in AWS Secrets Manager");
                info!("{}", e.name().unwrap_or_default());
            }
            Err(e) => {
                let error_message = e.to_string();
                let service_error = e.into_service_error();
                if service_error.code() == Some("ResourceNotFoundException") {
                    tracing::info!(
                        "No server key secret found in AWS, generating and storing new keypair"
                    );
                    let keypair = Keypair::generate().map_err(|_| Error::KeyGenFailed)?;
                    let pem = keypair.to_pkcs8_pem().map_err(|_| Error::PemGenFailed)?;
                    client
                        .create_secret()
                        .name(secret_name.clone())
                        .secret_string(pem)
                        .send()
                        .await
                        .map_err(|e| Error::Generic(e.to_string()))?;
                } else {
                    tracing::error!("Error describing secret: {:?}", error_message);
                    return Err(Error::Generic(error_message));
                }
            }
        }

        let asm_builder = aws_sdk_secretsmanager::config::Builder::from(&config);
        let caching_client = SecretsManagerCachingClient::from_builder(
            asm_builder,
            NonZeroUsize::new(1024).unwrap(),
            Duration::from_secs(3600),
            false,
        )
        .await
        .map_err(|e| Error::Generic(e.to_string()))?;

        let cache = AwsSecretCache {
            inner: caching_client,
        };

        Ok(Self::new(Arc::new(cache), secret_name))
    }
}

#[derive(Clone)]
pub struct AppState {
    pub credential_repository: Arc<SeaOrmStore<Credentials>>,
    pub status_list_token_repository: Arc<SeaOrmStore<StatusListToken>>,
    pub secret_manager: Arc<SecretManager>,
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

    let secret_manager = SecretManager::setup(secret_name, region)
        .await
        .expect("Failed to setup secret manager");

    let db = Arc::new(db);
    AppState {
        credential_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        status_list_token_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        secret_manager: Arc::new(secret_manager),
    }
}
