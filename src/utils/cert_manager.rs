mod errors;
#[cfg(test)]
mod tests;

pub mod challenge;
pub mod http_client;
pub mod storage;

use challenge::CleanupFuture;
pub use errors::CertError;

use chrono::Utc;
use color_eyre::eyre::eyre;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, HttpClient, Identifier, NewAccount, NewOrder,
    Order, OrderStatus,
};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::sleep};
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info, instrument, warn};
use x509_parser::pem::Pem;

use crate::{
    cert_manager::{challenge::ChallengeHandler, http_client::DefaultHttpClient, storage::Storage},
    utils::keygen::Keypair,
};

/// Struct that hold the certificate and its metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateData {
    pub certificate: String,
    pub valid_from: i64,
    pub expires_at: i64,
    pub updated_at: i64,
}

/// Type representing the certificate renewal strategy
#[derive(Debug, Clone)]
pub enum RenewalStrategy {
    /// Renew the certificate at a fixed interval.
    /// If not specified, it defaults to 60 days starting from the issue date
    FixedInterval(Option<u32>),
    /// Renew the certificate a certain number of days before it expires.
    /// Defaults to 30 days before expiry if not specified
    DaysBeforeExpiry(Option<u32>),
    /// Renew the certificate a certain percentage of its lifetime.
    /// Defaults to 2/3 of the certificate lifetime if not specified
    PercentageOfLifetime(Option<f32>),
}

type ACMEHttpClientFactory = Box<dyn Fn() -> Box<dyn HttpClient> + Send + Sync>;

/// Struct representing the certificate manager
pub struct CertManager {
    // Certificate storage backend
    cert_storage: Option<Box<dyn Storage>>,
    // Secrets storage backend
    secrets_storage: Option<Box<dyn Storage>>,
    // ACME challenge handler
    challenge_handler: Option<Box<dyn ChallengeHandler>>,
    // ACME client
    acme_client: Arc<Mutex<Option<Account>>>,
    // ACME HTTP client factory
    acme_http_client_factory: ACMEHttpClientFactory,
    // Certificate renewal strategy
    renewal_strategy: RenewalStrategy,
    // The subject alternative names
    domains: Vec<String>,
    // The company email
    email: String,
    // The company name
    organization: Option<String>,
    // The key usage extensions code
    eku: Option<Vec<u64>>,
    // The ACME directory URL
    acme_directory_url: String,
}

impl CertManager {
    /// Create a new instance of [CertManager] with required parameters
    pub fn new(
        domains: impl IntoIterator<Item = impl Into<String>>,
        email: impl Into<String>,
        organization: Option<impl Into<String>>,
        acme_directory_url: impl Into<String>,
    ) -> Result<Self, CertError> {
        let acme_client = Arc::new(Mutex::new(None));
        let http_client = DefaultHttpClient::new(None)?;
        let acme_http_client_factory =
            Box::new(move || Box::new(http_client.clone()) as Box<dyn HttpClient>);
        let renewal_strategy = RenewalStrategy::PercentageOfLifetime(None);

        Ok(Self {
            cert_storage: None,
            secrets_storage: None,
            challenge_handler: None,
            acme_client,
            acme_http_client_factory,
            renewal_strategy,
            domains: domains.into_iter().map(|d| d.into()).collect(),
            email: email.into(),
            organization: organization.map(|o| o.into()),
            eku: None,
            acme_directory_url: acme_directory_url.into(),
        })
    }

    /// Set the storage backend for the certificate
    /// <p><b>Note</b>: This method is required.
    pub fn with_cert_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.cert_storage = Some(Box::new(storage));
        self
    }

    /// Set the storage backend for the sensitive data
    /// <p><b>Note</b>: This method is required.
    pub fn with_secrets_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.secrets_storage = Some(Box::new(storage));
        self
    }

    /// Set the handler for the ACME challenge
    /// <p><b>Note</b>: This method is required.
    pub fn with_challenge_handler(mut self, handler: impl ChallengeHandler + 'static) -> Self {
        self.challenge_handler = Some(Box::new(handler));
        self
    }

    /// Override the default http client used by the ACME client
    ///
    /// Default: [`DefaultHttpClient`](http_client::DefaultHttpClient)
    pub fn with_acme_http_client(mut self, client: impl HttpClient + Clone + 'static) -> Self {
        self.acme_http_client_factory = Box::new(move || Box::new(client.clone()));
        self
    }

    /// Override the default certificate renewal strategy
    ///
    /// Default: `PercentageOfLifetime`
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
        name = "Running the ACME state machine",
        skip(self),
        fields(
            domains = ?self.domains,
            acme_directory_url = %self.acme_directory_url
        )
    )]
    pub async fn request_certificate(&self) -> Result<CertificateData, CertError> {
        use instant_acme::RetryPolicy;

        let cert_storage = self
            .cert_storage
            .as_ref()
            .ok_or_else(|| CertError::Other(eyre!("Certificate storage not set")))?;

        let challenge_handler = self
            .challenge_handler
            .as_ref()
            .ok_or_else(|| CertError::Other(eyre!("Challenge handler not set")))?;

        if self.domains.is_empty() {
            return Err(CertError::Other(eyre!(
                "No domain(s) provided to request a certificate for"
            )));
        }

        let account = self.acme_account().await?;
        let identifiers: Vec<_> = self
            .domains
            .iter()
            .map(|ident| Identifier::Dns(ident.into()))
            .collect();

        // Create the ACME order based on the given domain name(s).
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        let mut cleanup_futures = vec![];
        // Process the authorizations
        let mut authorizations = order.authorizations();
        while let Some(authz_result) = authorizations.next().await {
            let mut authz = authz_result?;

            // Skip already valid authorizations
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }

            // Handle the ACME challenge
            let cleanup_future = challenge_handler.handle_authorization(&mut authz).await?;
            cleanup_futures.push(cleanup_future);
        }

        // poll order until it is ready or an error occurs
        self.poll_order(&mut order, cleanup_futures).await?;

        // Generate the certificate signing request
        let server_key_pem = self.signing_key_pem().await?;
        let csr_der_bytes = self.generate_csr(&server_key_pem)?;

        // Finalize the order and try to get the certificate
        order.finalize_csr(&csr_der_bytes).await?;
        let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

        let parsed_cert_pem = self.parse_cert_pem(&cert_chain_pem)?;
        let x509 = parsed_cert_pem.parse_x509().map_err(|e| {
            error!("Got certificate but appears to be invalid: {e}");
            CertError::Parsing(e.to_string())
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
        let serialized_cert_data = serde_json::to_string(&cert_data)?;
        cert_storage.store(&cert_key, &serialized_cert_data).await?;

        info!(
            "Certificate obtained successfully. Valid from {} to {}",
            ts_to_utc(not_before),
            ts_to_utc(not_after)
        );
        Ok(cert_data)
    }

    async fn poll_order(
        &self,
        order: &mut Order,
        cleanup_futures: Vec<CleanupFuture>,
    ) -> Result<(), CertError> {
        use instant_acme::RetryPolicy;

        let state = order.poll_ready(&RetryPolicy::default()).await?;
        let result = if state != OrderStatus::Ready {
            Err(CertError::Other(eyre!(
                "Order with url {} for domains {:?} has been invalidated",
                order.url(),
                self.domains
            )))
        } else {
            Ok(())
        };

        // perform clean up, regardless of success or failure
        for cleanup_future in cleanup_futures {
            if let Err(e) = cleanup_future.run().await {
                warn!("Failed to clean up challenge: {e}");
            }
        }
        result
    }

    /// Attempt to get the signing key
    #[instrument(
        name = "Getting Server Signing Secret",
        skip(self),
        fields(domains = ?self.domains)
    )]
    pub async fn signing_key_pem(&self) -> Result<String, CertError> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY: Duration = Duration::from_millis(500);

        let secrets_storage = self
            .secrets_storage
            .as_ref()
            .ok_or_else(|| CertError::Other(eyre!("Secrets storage not set")))?;

        // Try to load the existing signing key
        let secret_id = self.signing_secret_id();
        if let Some(secret) = secrets_storage.load(&secret_id).await? {
            info!("Found existing server secret. Skipping...");
            return Ok(secret);
        }

        // If the secret does not exist, try to generate and store a new one
        warn!("No existing server secret found. Generating a new one...");
        let keypair = Keypair::generate()?;
        let key_pem = keypair.to_pkcs8_pem()?;
        let mut retries = 0;
        loop {
            info!("Trying to store the newly generated server secret...");
            match secrets_storage.store(&secret_id, &key_pem).await {
                Ok(_) => {
                    info!("Successfully stored the secret");
                    return Ok(key_pem);
                }
                Err(e) => {
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        return Err(e.into());
                    }
                    warn!("Retrying secret storage after failure: {e:#}");
                    sleep(RETRY_DELAY).await;
                }
            }
        }
    }

    /// Attempt to get the certificate data
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
            return Err(CertError::Other(eyre!("Certificate storage not set")));
        }
        Ok(None)
    }

    /// Extract individual certificates from the certificate chain and return them as a vector of base64-encoded strings
    ///
    /// This fuction will return `None` if the server certificate was not found.
    ///
    /// # Errors
    /// Returns an error if the certificate chain cannot be parsed or if there was an issue when trying to retrieve the server certificate
    pub async fn cert_chain_parts(&self) -> Result<Option<Vec<String>>, CertError> {
        use base64::prelude::{Engine as _, BASE64_STANDARD};

        if let Some(cert_data) = self.certificate().await? {
            let certs = Pem::iter_from_buffer(cert_data.certificate.as_bytes())
                .map(|cert| {
                    cert.map(|pem| BASE64_STANDARD.encode(&pem.contents))
                        .map_err(|e| CertError::Parsing(e.to_string()))
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
        fields(domains = ?self.domains)
    )]
    pub async fn renew_cert_if_needed(&self) -> Result<(), CertError> {
        if let Some(cert_data) = self.certificate().await? {
            if self.should_renew_cert(&cert_data) {
                self.request_certificate().await?;
                info!("Certificate renewed successfully");
                return Ok(());
            }
        } else {
            info!("No certificate found for this domain, requesting new one...");
            self.request_certificate().await?;
            info!("New certificate issued successfully");
            return Ok(());
        }
        info!("Certificate is still valid. No need to renew");
        Ok(())
    }

    // Attempt to retrieve existing or create an ACME account
    #[instrument(
        name = "Getting or Creating ACME Account",
        skip(self),
        fields(domains = ?self.domains, email = %self.email)
    )]
    async fn acme_account(&self) -> Result<Account, CertError> {
        let secrets_storage = self
            .secrets_storage
            .as_ref()
            .ok_or_else(|| CertError::Other(eyre!("Secrets storage not set")))?;

        let mut client_guard = self.acme_client.lock().await;
        if let Some(account) = client_guard.as_ref() {
            info!("Found existing ACME account. Skipping...");
            return Ok(account.clone());
        }

        let account_id = self.acme_account_id();
        if let Some(credentials) = secrets_storage.load(&account_id).await? {
            info!("Found existing credentials. Trying to load account...");
            let credentials: AccountCredentials = serde_json::from_str(&credentials)?;
            let http_client = self.create_http_client();
            match Account::builder_with_http(http_client)
                .from_credentials(credentials)
                .await
            {
                Ok(account) => {
                    info!("Account successfully loaded");
                    *client_guard = Some(account.clone());
                    return Ok(account);
                }
                Err(e) => {
                    warn!("Invalid credentials: {e}\nrecreating new account...");
                    secrets_storage.delete(&account_id).await?;
                }
            }
        }
        // Create a new ACME account
        let (account, credentials) = Account::builder_with_http(self.create_http_client())
            .create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", self.email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.acme_directory_url.clone(),
                None,
            )
            .await?;
        // Store new credentials
        secrets_storage
            .store(&account_id, &serde_json::to_string(&credentials)?)
            .await?;
        *client_guard = Some(account.clone());
        info!("Account successfully created");
        Ok(account)
    }

    // Generate a certificate signing request with optional EKU
    fn generate_csr(&self, signing_key: &str) -> Result<Vec<u8>, CertError> {
        // Build certificate request parameters
        let mut params = CertificateParams::new(self.domains.clone())
            .map_err(|e| CertError::Parsing(e.to_string()))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &self.domains[0]);
        if let Some(organization) = &self.organization {
            dn.push(DnType::OrganizationName, organization);
        }
        params.distinguished_name = dn;
        // Add Extended Key Usage for Status List Token signing
        // https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html#section-10.1
        if let Some(eku) = &self.eku {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(eku.to_vec())];
        }
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

        // Generate certificate signing request
        let keypair =
            rcgen::KeyPair::from_pem(signing_key).map_err(|e| CertError::Parsing(e.to_string()))?;
        let csr = params
            .serialize_request(&keypair)
            .map_err(|e| CertError::Parsing(e.to_string()))?;
        Ok(csr.der().to_vec())
    }

    fn should_renew_cert(&self, cert_data: &CertificateData) -> bool {
        let days_to_secs = |days: u32| (days as i64) * 24 * 60 * 60;

        match self.renewal_strategy {
            RenewalStrategy::DaysBeforeExpiry(value) => {
                // Default to 30 days if not specified
                let days_before = value.unwrap_or(30);
                let renewal_time = cert_data.expires_at - days_to_secs(days_before);
                Utc::now().timestamp() >= renewal_time
            }
            RenewalStrategy::PercentageOfLifetime(value) => {
                // Default to 2/3 of the lifetime if not specified
                let percentage = value.unwrap_or(2.0 / 3.0);
                let lifetime = cert_data.expires_at - cert_data.valid_from;
                let elapsed = Utc::now().timestamp() - cert_data.valid_from;
                (elapsed as f32 / lifetime as f32) >= percentage
            }
            RenewalStrategy::FixedInterval(value) => {
                // Default to 60 days if not specified
                let interval = value.unwrap_or(60);
                let renewal_time = cert_data.valid_from + days_to_secs(interval);
                Utc::now().timestamp() >= renewal_time
            }
        }
    }

    fn parse_cert_pem(&self, cert_pem: &str) -> Result<Pem, CertError> {
        use x509_parser::pem::parse_x509_pem;

        let pem = parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| CertError::Parsing(e.to_string()))?
            .1;
        if pem.label != "CERTIFICATE" || pem.contents.is_empty() {
            return Err(CertError::Parsing("Invalid X509 certificate".into()));
        }
        Ok(pem)
    }

    #[inline]
    fn create_http_client(&self) -> Box<dyn HttpClient> {
        (self.acme_http_client_factory)()
    }

    #[inline]
    fn cert_key(&self) -> String {
        format!("certs-{}-cert_data.json", &tld_plus_one(&self.domains))
    }

    #[inline]
    fn acme_account_id(&self) -> String {
        format!("acme_accounts-{}", tld_plus_one(&self.domains))
    }

    #[inline]
    fn signing_secret_id(&self) -> String {
        format!("keys-{}", self.domains.join("-"))
    }
}

/// Setup the certificate renewal scheduler
pub async fn setup_cert_renewal_scheduler(cert_manager: Arc<CertManager>) -> Result<(), CertError> {
    let scheduler = JobScheduler::new().await?;

    // Schedule certificate renewal check every day at midnight
    scheduler
        .add(Job::new_async("0 0 0 * * *", move |_, _| {
            let cert_manager = cert_manager.clone();
            Box::pin(async move {
                info!("Running scheduled certificate renewal check");
                if let Err(e) = cert_manager.renew_cert_if_needed().await {
                    error!("Failed to renew certificate: {e}");
                }
            })
        })?)
        .await?;

    scheduler.start().await?;
    Ok(())
}

// Helper function to format timestamp as UTC time
fn ts_to_utc(timestamp: i64) -> String {
    use chrono::DateTime;

    DateTime::from_timestamp(timestamp, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| format!("Invalid timestamp: {timestamp}"))
}

// Helper function to get the TLD+1
fn tld_plus_one(domains: &[String]) -> String {
    use public_suffix::{EffectiveTLDProvider, DEFAULT_PROVIDER};

    let first = domains[0].clone();

    // Get the effective TLD+1 for the first domain
    DEFAULT_PROVIDER
        .effective_tld_plus_one(&first)
        .unwrap_or(&first)
        .to_string()
}
