use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_secretsmanager::Client as awsClient;

use super::errors::Error;
pub struct Client {
    secret_name: String,
    region: Region,
}

pub struct Secret {
    secret_name: String,
    secret_value: String,
}

#[async_trait]
pub trait Operations {
    async fn get_key(&self) -> Result<Option<String>, Error>;

    async fn store_key(&self, secret: Secret) -> Result<(), Error>;
}

impl Client {
    pub fn new(secret_name: String, region: Region) -> Self {
        Self {
            secret_name,
            region,
        }
    }

    async fn configs(region: Region) -> awsClient {
        let config = aws_config::defaults(BehaviorVersion::v2025_01_17())
            .region(region)
            .load()
            .await;
        aws_sdk_secretsmanager::Client::new(&config)
    }
}

#[async_trait]
impl Operations for Client {
    async fn get_key(&self) -> Result<Option<String>, Error> {
        let asm = self::Client::configs(self.region.clone()).await;
        let response = asm
            .get_secret_value()
            .secret_id(self.secret_name.clone())
            .send()
            .await
            .map_err(|_| Error::Generic("Failed to get key".to_string()))?;
        Ok(response.secret_string().map(|s| s.to_string()))
    }

    async fn store_key(&self, secret: Secret) -> Result<(), Error> {
        let asm = self::Client::configs(self.region.clone()).await;
        asm.create_secret()
            .name(secret.secret_name)
            .secret_string(secret.secret_value)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("error: {}", e.to_string());
                Error::Generic("Failed to store secret".to_string())
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use async_trait::async_trait;
    use mockall::automock;

    #[automock]
    #[async_trait]
    pub trait SecretsManager {
        async fn get_secret(&self, secret_name: &str) -> Result<Option<String>, Error>;
        async fn store_secret(&self, secret_name: &str, secret_value: &str) -> Result<(), Error>;
    }

    use mockall::predicate::*;

    use crate::utils::errors::Error;
    use crate::utils::secretmanager::Secret;

    #[tokio::test]
    async fn test_get_secret() {
        let mut mock = MockSecretsManager::new();
        mock.expect_get_secret()
            .with(eq("my_secret"))
            .returning(|_| Ok(Some("secret_value".to_string())));

        let result = mock.get_secret("my_secret").await;
        assert_eq!(result.unwrap(), Some("secret_value".to_string()));
    }

    #[tokio::test]
    async fn test_store_key_success() {
        let mut mock = MockSecretsManager::new();
        let secret = Secret {
            secret_name: "test/secret".to_string(),
            secret_value: "super-secret-value".to_string(),
        };

        mock.expect_store_secret()
            .withf(|secret_name, _| secret_name == "test/secret")
            .returning(|_, _| Ok(()));

        let result = mock.store_secret(&secret.secret_name, &secret.secret_value).await;
        assert!(result.is_ok());
    }
}
