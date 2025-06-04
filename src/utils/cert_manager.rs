use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_elasticache::Client as CacheClient;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_secretsmanager::{
    operation::get_secret_value::GetSecretValueError, Client as SecretsClient,
};
use aws_secretsmanager_caching::{
    secret_store::SecretStoreError, SecretsManagerCachingClient as SecretsCacheClient,
};
use chrono::{DateTime, Utc};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyUsagePurpose,
};
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use std::{error::Error, io::Read, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::sleep};
use tokio_cron_scheduler::{Job, JobScheduler, JobSchedulerError};
use tracing::{error, info, instrument, warn};
use x509_parser::pem::Pem;

use crate::{model::certificate, utils::keygen::Keypair};

#[derive(thiserror::Error, Debug)]
pub enum CertError {
    #[error("ACME error: {0}")]
    Acme(#[from] instant_acme::Error),
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("AWS error: {0}")]
    Aws(String),
    #[error("Certificate parsing error: {0}")]
    CertParsing(String),
    #[error("Cron error: {0}")]
    Cron(#[from] JobSchedulerError),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Key operation error: {0}")]
    KeyOp(String),
    #[error("{0}")]
    Other(String),
}

// Struct that hold the certificate and its metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateData {
    pub certificate: String,
    pub valid_from: i64,
    pub expires_at: i64,
    pub updated_at: i64,
}

#[async_trait]
pub trait Storage: Send + Sync {
    /// Store the data with the given key
    async fn store(&self, key: &str, value: &str) -> Result<(), CertError>;
    /// Get the data specified by the given key
    async fn load(&self, key: &str) -> Result<Option<String>, CertError>;
    /// Update the data with the given key
    async fn update(&self, key: &str, value: &str) -> Result<(), CertError> {
        self.store(key, value).await
    }
    /// Delete the data with the given key
    async fn delete(&self, key: &str) -> Result<(), CertError>;
}

/// AWS Secrets Manager
pub struct AwsSecretsManager {
    client: SecretsClient,
    cache: SecretsCacheClient,
}

impl AwsSecretsManager {
    /// Create a new instance of [AwsSecretsManager]
    /// with the given AWS SDK config
    pub fn new(config: &SdkConfig) -> Self {
        let client = SecretsClient::new(config);
        // Cache size: 100 and a TTL of 5 minutes
        let cache =
            SecretsCacheClient::from_builder(client, 100.into(), Duration::from_secs(300), true);
        Self { client, cache }
    }
}

#[async_trait]
impl Storage for AwsSecretsManager {
    async fn store(&self, name: &str, data: &str) -> Result<(), CertError> {
        match self.client.describe_secret().secret_id(name).send().await {
            Ok(_) => (),
            Err(e) if e.into_service_error().is_resource_not_found_exception() => {
                // Secret does not exist, we create it
                self.client
                    .create_secret()
                    .name(name)
                    .secret_string(data)
                    .send()
                    .await
                    .map_err(|e| CertError::Aws(e.to_string()))?;
            }
            Err(e) => return Err(CertError::Aws(e.to_string())),
        }
        Ok(())
    }

    async fn load(&self, name: &str) -> Result<Option<String>, CertError> {
        let resp = self.cache.get_secret_value(name, None, None, false).await;
        match resp {
            Ok(value) => value.secret_string.map_or(Ok(None), |v| Ok(Some(v))),
            Err(GetSecretValueError::ResourceNotFoundException(_)) => Ok(None),
            Err(e) => Err(CertError::Aws(e.to_string())),
        }
    }

    async fn update(&self, name: &str, data: &str) -> Result<(), CertError> {
        self.client
            .put_secret_value()
            .secret_id(name)
            .secret_string(data)
            .send()
            .await
            .map_err(|e| CertError::Aws(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<(), CertError> {
        self.client
            .delete_secret()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| CertError::Aws(e.to_string()))?;
        Ok(())
    }
}

pub struct AwsS3Storage {
    client: S3Client,
    bucket: String,
    cache: Option<Box<dyn Storage>>,
}

impl AwsS3Storage {
    /// Create a new instance of [AwsS3Storage]
    /// with the given AWS SDK config and bucket name
    pub fn new(config: &SdkConfig, bucket_name: impl Into<String>) -> Self {
        Self {
            client: S3Client::new(config),
            bucket: bucket_name.into(),
            cache: None,
        }
    }

    /// Set the cache for caching the data stored in S3.
    /// This is useful to avoid unnecessary S3 requests.
    pub fn with_cache(mut self, cache: impl Storage + 'static) -> Self {
        self.cache = Some(Box::new(cache));
        self
    }
}

#[async_trait]
#[async_trait]
impl Storage for AwsS3Storage {
    async fn store(&self, key: &str, data: &str) -> Result<(), CertError> {
        // Create bucket if needed
        match self
            .client
            .create_bucket()
            .bucket(&self.bucket)
            .send()
            .await
        {
            Ok(_) => info!("Bucket {} created successfully.", self.bucket),
            Err(e) if e.into_service_error().is_bucket_already_owned_by_you() => (),
            Err(e) => return Err(CertError::Aws(e.to_string())),
        }

        // Clear cache if it exists to prevent serving old data
        if let Some(cache) = &self.cache {
            cache.delete(key).await?;
        }

        // Store the object in the bucket
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(data.as_bytes().into())
            .send()
            .await
            .map_err(|e| CertError::Aws(e.to_string()))?;

        info!(
            "Object {} stored successfully in bucket {}.",
            key, self.bucket
        );
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, CertError> {
        // Check the cache first if it exists
        if let Some(cache) = &self.cache {
            if let Some(data) = cache.load(key).await? {
                return Ok(Some(data));
            }
        }

        // If not, try to get directly from S3
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;
        match resp {
            Ok(output) => {
                let data = String::from_utf8(
                    output
                        .body
                        .collect()
                        .await
                        .map_err(|e| CertError::Aws(e.to_string()))?
                        .into_bytes(),
                )
                .map_err(|e| CertError::Other(e.to_string()))?;
                // Update cache if it exists
                if let Some(cache) = &self.cache {
                    cache.store(key, &data).await?;
                }
                Ok(Some(data))
            }
            Err(e) if e.into_service_error().is_no_such_key() => Ok(None),
            Err(e) => Err(CertError::Aws(e.to_string())),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), CertError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| CertError::Aws(e.to_string()))?;

        // Invalidate cache if it exists
        if let Some(cache) = &self.cache {
            cache.delete(key).await?;
        }
        Ok(())
    }
}

/// Struct representing Redis storage
pub struct RedisStorage {
    conn: ConnectionManager,
    ttl: Option<u64>,
}

impl RedisStorage {
    /// Create a new instance of [RedisStorage]
    /// with the given Redis connection manager
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn, ttl: None }
    }

    /// Set the time-to-live (TTL) for the stored data
    pub fn with_ttl(self, ttl: u64) -> Self {
        Self {
            ttl: Some(ttl),
            ..self
        }
    }
}

#[async_trait]
impl Storage for RedisStorage {
    async fn store(&self, key: &str, value: &str) -> Result<(), CertError> {
        let mut conn = self.conn.clone();
        if let Some(ttl) = self.ttl {
            let _: () = conn.set_ex(key, value, ttl).await?;
        } else {
            let _: () = conn.set(key, value).await?;
        }
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, CertError> {
        let mut conn = self.conn.clone();
        Ok(conn.get(key).await?)
    }

    async fn delete(&self, key: &str) -> Result<(), CertError> {
        let mut conn = self.conn.clone();
        let _: () = conn.del(key).await?;
        Ok(())
    }
}

/// Struct representing the certificate renewal strategy
#[derive(Debug, Clone)]
pub struct RenewalStrategy {
    /// The type of renewal strategy to use
    /// - **FixedInterval**: Renew the certificate at a fixed interval
    /// - **DaysBeforeExpiry**: Renew the certificate a certain number of days before it expires
    /// - **PercentageOfLifetime**: Renew the certificate a certain percentage of its lifetime
    pub strategy_type: RenewalType,
    /// The number of days before expiry to renew the certificate
    /// (used for [`RenewalStrategy::DaysBeforeExpiry`] strategy)
    pub threshold_days: Option<u32>,
    /// The percentage of the certificate's lifetime to renew before expiry
    /// (used for [`RenewalStrategy::PercentageOfLifetime`] strategy)
    pub threshold_percent: Option<f32>,
    /// The number of days to trigger certificate renewal
    /// (used for [`RenewalStrategy::FixedInterval`] strategy)
    pub interval_days: Option<u32>,
}

/// Type representing the type of renewal strategy
/// - **FixedInterval**: Renew the certificate at a fixed interval
/// - **DaysBeforeExpiry**: Renew the certificate a certain number of days before it expires
/// - **PercentageOfLifetime**: Renew the certificate a certain percentage of its lifetime
#[derive(Debug, Clone)]
pub enum RenewalType {
    FixedInterval,
    DaysBeforeExpiry,
    PercentageOfLifetime,
}

/// Struct representing the certificate manager
#[derive(Clone)]
pub struct CertManager {
    // Certificate storage
    cert_storage: Option<Arc<dyn Storage>>,
    // Secrets storage
    secrets_storage: Option<Arc<dyn Storage>>,
    // ACME challenge storage
    challenge_storage: Option<Arc<dyn Storage>>,
    // ACME client
    acme_client: Arc<Mutex<Option<Account>>>,
    // Renewal strategy
    renewal_strategy: RenewalStrategy,
    // The server domain name
    domain: String,
    // The company email
    email: String,
    // The key usage extensions code
    eku: Option<Vec<u64>>,
    // The ACME directory URL
    acme_directory_url: String,
}

impl CertManager {
    /// Create a new instance of [CertManager] with required parameters
    pub fn new(
        domain: impl Into<String>,
        email: impl Into<String>,
        acme_directory_url: impl Into<String>,
    ) -> Self {
        Self {
            cert_storage: None,
            secrets_storage: None,
            challenge_storage: None,
            acme_client: Arc::new(Mutex::new(None)),
            renewal_strategy: RenewalStrategy {
                strategy_type: RenewalType::PercentageOfLifetime,
                threshold_days: None,
                threshold_percent: None,
                interval_days: None,
            },
            domain: domain.into(),
            email: email.into(),
            eku: None,
            acme_directory_url: acme_directory_url.into(),
        }
    }

    /// Set the storage for the certificate
    pub fn with_cert_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.cert_storage = Some(Arc::new(storage));
        self
    }

    /// Set the storage for the ACME challenge
    pub fn with_challenge_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.challenge_storage = Some(Arc::new(storage));
        self
    }

    /// Set the storage for the sensitive data
    pub fn with_secrets_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.secrets_storage = Some(Arc::new(storage));
        self
    }

    /// Set the certificate renewal strategy
    pub fn with_renewal_strategy(mut self, strategy: RenewalStrategy) -> Self {
        self.renewal_strategy = strategy;
        self
    }

    /// Set the key usage extensions code
    pub fn with_eku(mut self, eku: &[u64]) -> Self {
        self.eku = Some(eku.to_vec());
        self
    }

    /// Request a certificate from the certificate authority
    #[instrument(
        name = "Requesting Certificate",
        skip(self),
        fields(
            domain = %self.domain,
            acme_directory_url = %self.acme_directory_url
        )
    )]
    pub async fn request_certificate(&self) -> Result<CertificateData, CertError> {
        let cert_storage = self
            .cert_storage
            .as_ref()
            .ok_or_else(|| CertError::Other("Certificate storage not set".into()))?;

        let account = self.acme_account().await?;
        // Create the ACME order based on the given domain name(s).
        let identifier = Identifier::Dns(self.domain.clone());
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[identifier],
            })
            .await?;

        for authz in order.authorizations().await? {
            // Skip already valid authorizations
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            // Try to find the HTTP-01 challenge
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| CertError::Other("no http01 challenge found".into()))?;
            // Get the challenge token and key authorization and store it
            let token = &challenge.token;
            let key_auth = order.key_authorization(challenge);
            self.store_challenge(token, key_auth.as_str()).await?;
            // Tell the ACME server that we are ready to respond to the challenge
            order.set_challenge_ready(&challenge.url).await?;
        }

        // Poll the ACME server until the order becomes ready or invalid
        loop {
            order.refresh().await?;
            match order.state().status {
                OrderStatus::Ready => break,
                OrderStatus::Invalid => {
                    error!("Failed to get certficate. The order is invalid.");
                    return Err(CertError::Other(format!(
                        "order with url {} is invalid",
                        order.url()
                    )));
                }
                _ => sleep(Duration::from_secs(1)).await,
            }
        }

        // Generate the certificate signing request
        let server_key_pem = self.signing_key_pem().await?;
        let csr_der_bytes = self.generate_csr(&server_key_pem)?;

        // Finalize the order and try to get the certificate
        order.finalize(&csr_der_bytes).await?;
        let cert_chain_pem = loop {
            match order.certificate().await? {
                Some(cert_chain_pem) => break cert_chain_pem,
                None => sleep(Duration::from_secs(1)).await,
            }
        };

        let parsed_cert_pem = self.parse_cert_pem(&cert_chain_pem)?;
        let x509 = parsed_cert_pem.parse_x509().map_err(|e| {
            error!("Got certificate but appears to be invalid: {e}");
            CertError::CertParsing(e.to_string())
        })?;
        let not_after = x509.validity().not_after.timestamp();
        let not_before = x509.validity().not_before.timestamp();

        let cert_data = CertificateData {
            certificate: cert_chain_pem,
            valid_from: not_before,
            expires_at: not_after,
            updated_at: Utc::now().timestamp(),
        };

        // Store the certificate
        let cert_key = self.cert_key();
        let cert_data_string = serde_json::to_string(&cert_data)?;
        cert_storage.store(&cert_key, &cert_data_string).await?;

        info!("Certificate issued successfully. Valid from {not_before} to {not_after}.");
        Ok(cert_data)
    }

    /// Attempt to retrieve the signing key
    pub async fn signing_key_pem(&self) -> Result<String, CertError> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY: Duration = Duration::from_millis(500);

        let secrets_storage = self
            .secrets_storage
            .as_ref()
            .ok_or_else(|| CertError::Other("Secrets storage not set".into()))?;

        // Try to load the existing signing key
        let secret_id = self.signing_secret_id();
        if let Some(secret) = secrets_storage.load(&secret_id).await? {
            return Ok(secret);
        }

        // If the secret does not exist, try to generate and store a new one
        let keypair = Keypair::generate().map_err(|e| CertError::KeyOp(e.to_string()))?;
        let key_pem = keypair
            .to_pkcs8_pem()
            .map_err(|e| CertError::KeyOp(e.to_string()))?;
        let mut retries = 0;
        loop {
            match secrets_storage.store(&secret_id, &key_pem).await {
                Ok(_) => return Ok(key_pem),
                Err(e) => {
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        return Err(CertError::KeyOp(format!(
                            "Failed to store key after {retries} retries: {e}",
                        )));
                    }
                    warn!("Retrying key storage after failure: {}", e);
                    sleep(RETRY_DELAY).await;
                }
            }
        }
    }

    /// Attempt to get the verifying key in PEM format
    pub async fn verifying_key_pem(&self) -> Result<String, CertError> {
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        // Try to get the verifying key from the signing key
        let signing_key_pem = self.signing_key_pem().await?;

        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem)
            .map_err(|e| CertError::KeyOp(e.to_string()))?;
        let verifying_key_pem = keypair
            .verifying_key()
            .to_public_key_pem(LineEnding::default())
            .map_err(|e| CertError::KeyOp(e.to_string()))?;
        Ok(verifying_key_pem)
    }

    /// Attempt to retrieve the certificate data
    ///
    /// # Errors
    /// Returns an error if the certificate data cannot be parsed or if there was an issue when trying to retrieve the certificate data.
    pub async fn certificate(&self) -> Result<Option<CertificateData>, CertError> {
        if let Some(cert_storage) = &self.cert_storage {
            let cert_key = self.cert_key();
            if let Some(cert_data) = cert_storage.load(&cert_key).await? {
                return Ok(Some(serde_json::from_str(&cert_data)?));
            }
        } else {
            return Err(CertError::Other("Certificate storage not set".into()));
        }
        Ok(None)
    }

    /// Extract individual certificates from the certificate chain and return them as a vector of base64-encoded strings
    ///
    /// This fuction will return None if the certificate chain was not found.
    ///
    /// # Errors
    /// Returns an error if the certificate chain cannot be parsed or if there was an issue when trying to retrieve the certificate chain.
    pub async fn cert_chain_parts(&self) -> Result<Option<Vec<String>>, CertError> {
        use base64::prelude::{Engine as _, BASE64_STANDARD};

        if let Some(cert_data) = self.certificate().await? {
            let certs = Pem::iter_from_buffer(cert_data.certificate.as_bytes())
                .map(|cert| {
                    cert.map(|pem| BASE64_STANDARD.encode(pem.contents))
                        .map_err(|e| CertError::CertParsing(e.to_string()))
                })
                .collect::<Result<_, _>>()?;

            return Ok(Some(certs));
        }
        Ok(None)
    }

    /// Renew the certificate if needed
    #[instrument(
        name = "Checking Certificate Renewal",
        skip(self),
        fields(domain = %self.domain)
    )]
    pub async fn renew_cert_if_needed(&self) -> Result<(), CertError> {
        if let Some(cert_data) = self.certificate().await? {
            if self.should_renew_cert(&cert_data).await {
                self.request_certificate().await?;
                info!("Certificate renewed successfully.");
                return Ok(());
            }
        } else {
            info!("No certificate found for this domain, requesting new one");
            self.request_certificate().await?;
            info!("New certificate issued successfully.");
            return Ok(());
        }
        Ok(())
    }

    /// Get the ACME challenge for the given token
    pub async fn acme_challenge(&self, token: &str) -> Result<Option<String>, CertError> {
        if let Some(challenge_store) = &self.challenge_storage {
            challenge_store.load(token).await
        } else {
            Err(CertError::Other("Challenge storage not set".into()))
        }
    }

    // Attempt to retrieve existing or create an ACME account
    #[instrument(
        name = "Getting or Creating ACME Account",
        skip(self),
        fields(domain = %self.domain, email = %self.email)
    )]
    async fn acme_account(&self) -> Result<Account, CertError> {
        let secrets_storage = self
            .secrets_storage
            .as_ref()
            .ok_or_else(|| CertError::Other("Secrets storage not set".into()))?;

        let mut client_guard = self.acme_client.lock().await;
        if let Some(account) = client_guard.as_ref() {
            return Ok(account.clone());
        }

        let account_id = self.acme_account_id();
        if let Some(credentials) = secrets_storage.load(&account_id).await? {
            let credentials: AccountCredentials = serde_json::from_str(&credentials)?;
            match Account::from_credentials(credentials).await {
                Ok(account) => {
                    *client_guard = Some(account.clone());
                    return Ok(account);
                }
                Err(e) => {
                    warn!("Invalid credentials: {e}\nrecreating new account.");
                    secrets_storage.delete(&account_id).await?;
                }
            }
        }
        // Create a new ACME account
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", self.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            &self.acme_directory_url,
            None,
        )
        .await?;
        // Store new credentials
        secrets_storage
            .store(&account_id, &serde_json::to_string(&credentials)?)
            .await?;
        *client_guard = Some(account.clone());
        info!("Account successfully created.");
        Ok(account)
    }

    // Generate a certificate signing request with optional EKU
    fn generate_csr(&self, server_key_pem: &str) -> Result<Vec<u8>, CertError> {
        // Build certificate request parameters
        let mut params = CertificateParams::new(&[self.domain.clone()])
            .map_err(|e| CertError::CertParsing(e.to_string()))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, self.domain.clone());
        params.distinguished_name = dn;
        // Add Extended Key Usage for Status List Token signing
        // https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html#section-10.1
        if let Some(eku) = &self.eku {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(eku.to_vec())];
        }
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

        // Generate certificate signing request
        let keypair = rcgen::KeyPair::from_pem(server_key_pem)
            .map_err(|e| CertError::CertParsing(e.to_string()))?;
        let csr = params
            .serialize_request(&keypair)
            .map_err(|e| CertError::CertParsing(e.to_string()))?;
        Ok(csr.der().to_vec())
    }

    #[instrument(
        name = "Storing ACME Challenge",
        skip(self, token, key_auth),
        fields(
        token = %token,
        domain = %self.domain,
        )
    )]
    async fn store_challenge(&self, token: &str, key_auth: &str) -> Result<(), CertError> {
        if let Some(challenge_store) = &self.challenge_storage {
            challenge_store.store(token, key_auth).await?;
            tracing::info!(
                "Stored Challenge for token: {token} of domain: {}",
                self.domain
            );
        } else {
            return Err(CertError::Other("Challenge storage not set".into()));
        }
        Ok(())
    }

    async fn should_renew_cert(&self, cert_data: &CertificateData) -> bool {
        #[inline]
        fn days_to_secs(days: u32) -> i64 {
            (days as i64) * 24 * 60 * 60
        }

        match self.renewal_strategy.strategy_type {
            RenewalType::DaysBeforeExpiry => {
                // Default to 30 days if not specified
                let days_before = self.renewal_strategy.threshold_days.unwrap_or(30);
                let renewal_time = cert_data.expires_at - days_to_secs(days_before);
                Utc::now().timestamp() >= renewal_time
            }
            RenewalType::PercentageOfLifetime => {
                // Default to 2/3 of the lifetime if not specified
                let percentage = self.renewal_strategy.threshold_percent.unwrap_or(2.0 / 3.0);
                let lifetime = cert_data.expires_at - cert_data.valid_from;
                let elapsed = Utc::now().timestamp() - cert_data.valid_from;
                (elapsed as f32 / lifetime as f32) >= percentage
            }
            RenewalType::FixedInterval => {
                // Default to 60 days if not specified
                let interval = self.renewal_strategy.interval_days.unwrap_or(60);
                let renewal_time = cert_data.valid_from + days_to_secs(interval);
                Utc::now().timestamp() >= renewal_time
            }
        }
    }

    fn parse_cert_pem(&self, cert_pem: &str) -> Result<Pem, CertError> {
        use x509_parser::pem::parse_x509_pem;

        let pem = parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| CertError::CertParsing(e.to_string()))?
            .1;
        if pem.label != "CERTIFICATE" || pem.contents.is_empty() {
            return Err(CertError::CertParsing("Invalid X509 certificate".into()));
        }
        Ok(pem)
    }

    #[inline]
    fn cert_key(&self) -> String {
        format!("certs:{}:fullchain.pem", self.domain)
    }

    fn acme_account_id(&self) -> String {
        format!("acme:accounts:{}", self.domain)
    }

    fn signing_secret_id(&self) -> String {
        format!("keys:{}", self.domain)
    }
}

pub async fn setup_cert_renewal_scheduler(cert_manager: Arc<CertManager>) -> Result<(), CertError> {
    let scheduler = JobScheduler::new().await?;

    // Schedule certificate renewal check every day at midnight
    scheduler
        .add(Job::new_async("0 0 0 * * *", move |_, _| {
            let cert_manager = cert_manager.clone();
            Box::pin(async move {
                info!("Running scheduled certificate renewal check");
                if let Err(e) = cert_manager.renew_cert_if_needed().await {
                    error!("Failed to renew certificate: {e:?}");
                }
            })
        })?)
        .await?;

    scheduler.start().await?;
    Ok(())
}
