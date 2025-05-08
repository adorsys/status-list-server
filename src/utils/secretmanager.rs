use super::errors::Error;
use async_trait::async_trait;
use aws_sdk_secretsmanager::config::Region;
use aws_sdk_secretsmanager::Client as AwsClient;

pub struct AwsSecret {
    secret_name: String,
    _region: Region,
    aws_client: AwsClient,
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

impl AwsSecret {
    pub async fn new(secret_name: String, _region: Region) -> Self {
        let config = aws_config::from_env().region(_region.clone()).load().await;
        let aws_client = AwsClient::new(&config);

        Self {
            secret_name,
            _region,
            aws_client,
        }
    }
}

impl Secret {
    pub fn new(secret_name: String, secret_value: String) -> Self {
        Self {
            secret_name,
            secret_value,
        }
    }
}

#[async_trait]
impl Operations for AwsSecret {
    async fn get_key(&self) -> Result<Option<String>, Error> {
        let asm = self.aws_client.clone();
        let response = asm
            .get_secret_value()
            .secret_id(self.secret_name.clone())
            .send()
            .await
            .map_err(|e| {
                tracing::error!(" error getting key: {}", e.to_string());
                Error::Generic("Failed to get key".to_string())
            })?;
        Ok(response.secret_string().map(|s| s.to_string()))
    }

    async fn store_key(&self, secret: Secret) -> Result<(), Error> {
        let asm = self.aws_client.clone();
        asm.create_secret()
            .name(secret.secret_name)
            .secret_string(secret.secret_value)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("error storing key: {}", e.to_string());
                Error::Generic("Failed to store secret".to_string())
            })?;
        Ok(())
    }
}
