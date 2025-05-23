use super::keygen::Keypair;
use crate::{
    database::queries::SeaOrmStore,
    model::{Credentials, StatusListToken},
    utils::errors::{Error, SecretCacheError},
};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
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

/// Configuration for secret caching
#[derive(Clone)]
pub struct CacheConfig {
    pub enabled: bool,
    pub cache_size: NonZeroUsize,
    pub ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_size: NonZeroUsize::new(1024).unwrap(),
            ttl: Duration::from_secs(3600),
        }
    }
}

/// A type that manages server secrets and their caching
#[derive(Clone)]
pub struct SecretManager {
    cache: Arc<dyn SecretCache>,
    client: Arc<SecretsManagerClient>,
    server_secret_name: String,
    cache_config: CacheConfig,
}

impl SecretManager {
    pub fn new(
        cache: impl SecretCache + 'static,
        client: SecretsManagerClient,
        server_secret_name: String,
        cache_config: CacheConfig,
    ) -> Self {
        Self {
            cache: Arc::new(cache),
            client: Arc::new(client),
            server_secret_name,
            cache_config,
        }
    }

    pub async fn get_secret_from_cache_or_aws(
        &self,
        secret_name: String,
        use_cache: bool,
    ) -> Result<Option<String>, SecretCacheError> {
        if use_cache && self.cache_config.enabled {
            self.cache.get_secret_string(secret_name).await
        } else {
            let result = self
                .client
                .get_secret_value()
                .secret_id(secret_name)
                .send()
                .await;
            match result {
                Ok(output) => Ok(output.secret_string().map(String::from)),
                Err(e) => Err(SecretCacheError::AwsSdkError(e.to_string())),
            }
        }
    }

    pub async fn get_server_secret(&self) -> Result<Option<String>, SecretCacheError> {
        if self.cache_config.enabled {
            self.cache
                .get_secret_string(self.server_secret_name.clone())
                .await
        } else {
            let result = self
                .client
                .get_secret_value()
                .secret_id(self.server_secret_name.clone())
                .send()
                .await;
            match result {
                Ok(output) => Ok(output.secret_string().map(String::from)),
                Err(e) => Err(SecretCacheError::AwsSdkError(e.to_string())),
            }
        }
    }

    /// Creates a new secret with the given name and value
    pub async fn create_secret(&self, name: String, value: String) -> Result<(), Error> {
        self.client
            .create_secret()
            .name(name)
            .secret_string(value)
            .send()
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;
        Ok(())
    }

    /// Deletes a secret by name
    pub async fn delete_secret(&self, name: String) -> Result<(), Error> {
        self.client
            .delete_secret()
            .secret_id(name)
            .force_delete_without_recovery(true)
            .send()
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;
        Ok(())
    }

    /// Updates the cache configuration
    pub fn update_cache_config(&mut self, config: CacheConfig) {
        self.cache_config = config;
    }

    /// Creates a new SecretManager instance and ensures the server secret exists
    pub async fn setup(
        secret_name: String,
        region: String,
        cache_config: Option<CacheConfig>,
    ) -> Result<Self, Error> {
        let config = aws_config::load_defaults(BehaviorVersion::latest())
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

        let cache_config = cache_config.unwrap_or_default();
        let asm_builder = aws_sdk_secretsmanager::config::Builder::from(&config);
        let caching_client = SecretsManagerCachingClient::from_builder(
            asm_builder,
            if cache_config.enabled {
                cache_config.cache_size
            } else {
                NonZeroUsize::new(1).unwrap() // Minimal cache size when disabled
            },
            if cache_config.enabled {
                cache_config.ttl
            } else {
                Duration::from_secs(1) // Minimal TTL when disabled
            },
            false,
        )
        .await
        .map_err(|e| Error::Generic(e.to_string()))?;

        let cache = AwsSecretCache {
            inner: caching_client,
        };

        Ok(Self::new(cache, client, secret_name, cache_config))
    }
}

#[derive(Clone)]
pub struct AppState {
    pub credential_repository: Arc<SeaOrmStore<Credentials>>,
    pub status_list_token_repository: Arc<SeaOrmStore<StatusListToken>>,
    pub secret_manager: Arc<SecretManager>,
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

    let secret_name =
        std::env::var("SERVER_KEY_SECRET_NAME").expect("SERVER_KEY_SECRET_NAME env not set");
    let region = std::env::var("AWS_REGION").expect("AWS_REGION env not set");

    let secret_manager = SecretManager::setup(secret_name, region, None)
        .await
        .expect("Failed to setup secret manager");

    let server_public_domain =
        std::env::var("SERVER_PUBLIC_DOMAIN").expect("SERVER_PUBLIC_DOMAIN env not set");

    let db = Arc::new(db);
    AppState {
        credential_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        status_list_token_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        secret_manager: Arc::new(secret_manager),
        server_public_domain,
    }
}
