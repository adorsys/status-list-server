mod builder;
mod errors;
mod strategy;
#[cfg(test)]
mod tests;

pub mod challenge;
pub mod http_client;
pub mod storage;

use crate::utils::cache::CertificateChain;
pub use builder::CertificateManagerBuilder;
use challenge::CleanupFuture;
pub use errors::CertError;
pub use strategy::{
    AcmeProvisioningStrategy, CertProvisioningStrategy, StoreProvisioningSource,
    StoreProvisioningStrategy,
};

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
use time::{OffsetDateTime, macros::format_description};
use tokio::{sync::Mutex, time::sleep};
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info, instrument, warn};
use x509_parser::pem::Pem as X509Pem;

use crate::{
    cert_manager::{challenge::ChallengeHandler, http_client::DefaultHttpClient, storage::Storage},
    utils::{cache::CertChainCache, keygen::Keypair},
};

use opentelemetry::{
    global,
    metrics::{Counter, Gauge},
};

// Renewal metrics constants
const RENEWAL_ATTEMPTS_METRIC: &str = "cert_renewal_attempts_total";
const RENEWAL_SUCCESSES_METRIC: &str = "cert_renewal_successes_total";
const RENEWAL_FAILURES_METRIC: &str = "cert_renewal_failures_total";
const TIME_TO_EXPIRY_METRIC: &str = "cert_time_to_expiry_seconds";
const LAST_SUCCESSFUL_RENEWAL_METRIC: &str = "cert_last_successful_renewal_timestamp";

#[derive(Clone, Debug)]
pub(crate) struct CertManagerMetrics {
    attempts: Counter<u64>,
    successes: Counter<u64>,
    failures: Counter<u64>,
    time_to_expiry: Gauge<i64>,
    last_successful_renewal: Gauge<i64>,
}

impl Default for CertManagerMetrics {
    fn default() -> Self {
        let meter = global::meter("status-list-server");
        Self {
            attempts: meter
                .u64_counter(RENEWAL_ATTEMPTS_METRIC)
                .with_description("Total number of certificate renewal attempts")
                .build(),
            successes: meter
                .u64_counter(RENEWAL_SUCCESSES_METRIC)
                .with_description("Total number of successful certificate renewals")
                .build(),
            failures: meter
                .u64_counter(RENEWAL_FAILURES_METRIC)
                .with_description("Total number of failed certificate renewals")
                .build(),
            time_to_expiry: meter
                .i64_gauge(TIME_TO_EXPIRY_METRIC)
                .with_description("Time remaining until the current certificate expires")
                .build(),
            last_successful_renewal: meter
                .i64_gauge(LAST_SUCCESSFUL_RENEWAL_METRIC)
                .with_description("Unix timestamp of the last successful certificate renewal")
                .build(),
        }
    }
}

/// Zero-initialize renewal counters so they appear in Prometheus scrapes before first use.
pub fn init_renewal_counters() {
    let meter = global::meter("status-list-server");
    meter
        .u64_counter(RENEWAL_ATTEMPTS_METRIC)
        .build()
        .add(0, &[]);
    meter
        .u64_counter(RENEWAL_SUCCESSES_METRIC)
        .build()
        .add(0, &[]);
    meter
        .u64_counter(RENEWAL_FAILURES_METRIC)
        .build()
        .add(0, &[]);
}

/// Default cache TTL when no override is supplied.
///
/// Exported as a single source of truth: `Config::load` references this
/// constant so the runtime default and the code fallback always agree.
pub const DEFAULT_CHAIN_CACHE_TTL: Duration = Duration::from_secs(3600);

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
    acme_http_client_factory: Option<ACMEHttpClientFactory>,
    // Certificate provisioning strategy
    provisioning_strategy: Box<dyn CertProvisioningStrategy>,
    // Certificate renewal strategy
    renewal_strategy: RenewalStrategy,
    // Parsed certificate chain cache
    cert_chain_cache: CertChainCache,
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
    metrics: CertManagerMetrics,
}

impl CertManager {
    /// Create a certificate manager builder.
    pub fn builder() -> CertificateManagerBuilder {
        CertificateManagerBuilder::default()
    }

    /// Create a new instance of [CertManager] with required parameters
    pub fn new(
        domains: impl IntoIterator<Item = impl Into<String>>,
        email: impl Into<String>,
        organization: Option<impl Into<String>>,
        acme_directory_url: impl Into<String>,
    ) -> Result<Self, CertError> {
        let http_client = DefaultHttpClient::new(None)?;
        let acme_http_client_factory =
            Box::new(move || Box::new(http_client.clone()) as Box<dyn HttpClient>);
        let renewal_strategy = RenewalStrategy::PercentageOfLifetime(None);

        let domains: Vec<String> = domains.into_iter().map(|d| d.into()).collect();
        let domain_label = domains.first().map(String::as_str).unwrap_or_default();
        let cert_chain_cache = CertChainCache::new(DEFAULT_CHAIN_CACHE_TTL, domain_label);

        Ok(Self {
            cert_storage: None,
            secrets_storage: None,
            challenge_handler: None,
            acme_client: Arc::new(Mutex::new(None)),
            acme_http_client_factory: Some(acme_http_client_factory),
            provisioning_strategy: Box::new(AcmeProvisioningStrategy),
            renewal_strategy,
            cert_chain_cache,
            domains,
            email: email.into(),
            organization: organization.map(|o| o.into()),
            eku: None,
            acme_directory_url: acme_directory_url.into(),
            metrics: CertManagerMetrics::default(),
        })
    }

    /// Set the storage backend for the certificate.
    ///
    /// **Note:** This method is required.
    pub fn with_cert_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.cert_storage = Some(Box::new(storage));
        self
    }

    /// Set the storage backend for the sensitive data.
    ///
    /// **Note:** This method is required.
    pub fn with_secrets_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.secrets_storage = Some(Box::new(storage));
        self
    }

    /// Set the handler for the ACME challenge.
    ///
    /// **Note:** This method is required.
    pub fn with_challenge_handler(mut self, handler: impl ChallengeHandler + 'static) -> Self {
        self.challenge_handler = Some(Box::new(handler));
        self
    }

    /// Override the default http client used by the ACME client
    ///
    /// Default: [`DefaultHttpClient`]
    pub fn with_acme_http_client(mut self, client: impl HttpClient + Clone + 'static) -> Self {
        self.acme_http_client_factory = Some(Box::new(move || Box::new(client.clone())));
        self
    }

    /// Override the default certificate renewal strategy
    ///
    /// Default: `PercentageOfLifetime`
    pub fn with_renewal_strategy(mut self, strategy: RenewalStrategy) -> Self {
        self.renewal_strategy = strategy;
        self
    }

    /// Override the certificate provisioning strategy.
    pub fn with_provisioning_strategy(
        mut self,
        strategy: impl CertProvisioningStrategy + 'static,
    ) -> Self {
        self.provisioning_strategy = Box::new(strategy);
        self
    }

    /// Override the in-memory parsed certificate chain cache TTL.
    ///
    /// A zero duration keeps the cache active with no TTL safety expiry; cache
    /// replacement still happens whenever this manager provisions a new certificate.
    ///
    /// **Multi-replica deployments:** Only the replica that performs the
    /// provisioning call (`request_certificate`) replaces its in-memory cache.
    /// Non-provisioning replicas therefore rely on the TTL as the only refresh
    /// mechanism for picking up a newly provisioned chain. Set `ttl = 0` only
    /// when the process is guaranteed to re-provision or restart on every
    /// rotation — otherwise long-lived replicas with a disabled TTL will serve
    /// the stale chain until they happen to re-provision.
    ///
    /// **Staleness safety:** This caching strategy is safe because the signing
    /// key is stable across certificate renewals — the provisioning flow reuses
    /// the stored secret key (`signing_key_pem`). If renewal ever rotates the
    /// signing key, the staleness window becomes a token-validation outage:
    /// verifiers would receive the old certificate chain while tokens are
    /// signed with the new key.
    pub fn with_cert_chain_cache_ttl(mut self, ttl: Duration) -> Self {
        let domain_label = self.domains.first().map(String::as_str).unwrap_or_default();
        self.cert_chain_cache = CertChainCache::new(ttl, domain_label);
        self
    }

    /// Set the key usage extensions code
    pub fn with_eku(mut self, eku: &[u64]) -> Self {
        self.eku = Some(eku.to_vec());
        self
    }

    /// Zero-initialize the certificate chain cache counters so they appear
    /// in Prometheus scrapes before first use.
    ///
    /// **Must** be called after the global metrics recorder has been installed.
    /// If metrics are disabled this is a harmless no-op.
    pub fn init_cert_chain_cache_counters(&self) {
        self.cert_chain_cache.init_counters();
    }

    /// Zero-initialize renewal counters so they appear in Prometheus scrapes
    /// before first use.
    ///
    /// **Must** be called after the global metrics recorder has been installed.
    /// If metrics are disabled this is a harmless no-op.
    pub fn init_renewal_counters(&self) {
        self.metrics.attempts.add(0, &[]);
        self.metrics.successes.add(0, &[]);
        self.metrics.failures.add(0, &[]);
    }

    /// Update the time-to-expiry gauge with the current certificate's expiry time.
    fn update_time_to_expiry(&self, cert_data: &CertificateData) {
        let now = now_unix_timestamp();
        let time_to_expiry = cert_data.expires_at.saturating_sub(now);
        self.metrics.time_to_expiry.record(time_to_expiry, &[]);
    }

    /// Record a successful renewal by updating counters and gauges.
    fn record_successful_renewal(&self) {
        self.metrics.successes.add(1, &[]);
        self.metrics
            .last_successful_renewal
            .record(now_unix_timestamp(), &[]);
    }

    /// Record a failed renewal attempt.
    fn record_failed_renewal(&self) {
        self.metrics.failures.add(1, &[]);
    }

    /// Provision a certificate with the configured strategy.
    #[instrument(
        name = "Provisioning certificate",
        skip(self),
        fields(
            domains = ?self.domains,
            strategy = %self.provisioning_strategy.name()
        )
    )]
    pub async fn request_certificate(&self) -> Result<CertificateData, CertError> {
        self.provisioning_strategy.provision(self).await
    }

    pub(crate) async fn request_acme_certificate(&self) -> Result<CertificateData, CertError> {
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

        let cert_data = CertificateData::new(cert_chain_pem, not_before, not_after);

        // Store the certificate
        self.persist_certificate_data_with_storage(cert_storage.as_ref(), &cert_data)
            .await?;
        self.cache_provisioned_chain(&cert_data.certificate).await?;

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

        let secrets_storage = self.secrets_storage()?;

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
        let cert_storage = self.cert_storage()?;
        let cert_key = self.cert_key();
        if let Some(cert_data) = cert_storage.load(&cert_key).await? {
            return Ok(Some(serde_json::from_str(&cert_data)?));
        }
        Ok(None)
    }

    /// Extract individual certificates from the certificate chain and return shared base64-encoded chain parts.
    ///
    /// This function will return `None` if the server certificate was not found.
    ///
    /// # Errors
    /// Returns an error if the certificate chain cannot be parsed or if there was an issue when trying to retrieve the server certificate
    pub async fn cert_chain_parts(&self) -> Result<Option<CertificateChain>, CertError> {
        let cert_key = self.cert_key();
        if let Some(certs) = self.cert_chain_cache.get(&cert_key).await {
            return Ok(Some(certs));
        }
        if let Some(cert_data) = self.certificate().await? {
            let certs = self.parse_cert_chain_parts(&cert_data.certificate)?;
            // NOTE: There is a benign race between this read-path insert and
            // the provisioning-path `replace` in `cache_provisioned_chain`.
            // If a concurrent `request_certificate` replaces the cache entry
            // between our miss and this insert, we overwrite the fresh chain
            // with the (still valid) old chain. The stale entry is bounded by
            // the cache TTL. This is acceptable because the signing key is
            // stable across renewals, so the old chain remains valid for
            // token verification.
            self.cert_chain_cache.insert(cert_key, certs.clone()).await;
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
        // Record renewal attempt
        self.metrics.attempts.add(1, &[]);

        if let Some(cert_data) = self.certificate().await? {
            // Update time-to-expiry gauge regardless of whether we renew
            self.update_time_to_expiry(&cert_data);

            if self
                .provisioning_strategy
                .should_provision_existing(self, &cert_data)
            {
                match self.request_certificate().await {
                    Ok(cert_data) => {
                        self.record_successful_renewal();
                        self.update_time_to_expiry(&cert_data);
                        info!(
                            "Certificate provisioned successfully with {} strategy",
                            self.provisioning_strategy.name()
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        self.record_failed_renewal();
                        return Err(e);
                    }
                }
            }
        } else {
            warn!(
                "No certificate found for this domain, provisioning with {} strategy...",
                self.provisioning_strategy.name()
            );
            match self.request_certificate().await {
                Ok(cert_data) => {
                    self.record_successful_renewal();
                    self.update_time_to_expiry(&cert_data);
                    info!("New certificate provisioned successfully");
                    return Ok(());
                }
                Err(e) => {
                    self.record_failed_renewal();
                    return Err(e);
                }
            }
        }
        info!("Certificate is still valid. No need to provision");
        Ok(())
    }

    // Attempt to retrieve existing or create an ACME account
    #[instrument(
        name = "Getting or Creating ACME Account",
        skip(self),
        fields(domains = ?self.domains, email = %self.email)
    )]
    async fn acme_account(&self) -> Result<Account, CertError> {
        let secrets_storage = self.secrets_storage()?;

        let mut client_guard = self.acme_client.lock().await;
        if let Some(account) = client_guard.as_ref() {
            info!("Found existing ACME account. Skipping...");
            return Ok(account.clone());
        }

        let account_id = self.acme_account_id();
        if let Some(credentials) = secrets_storage.load(&account_id).await? {
            info!("Found existing credentials. Trying to load account...");
            let credentials: AccountCredentials = serde_json::from_str(&credentials)?;
            let http_client = self.create_http_client()?;
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
        let (account, credentials) = Account::builder_with_http(self.create_http_client()?)
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

    pub(crate) fn should_renew_cert(&self, cert_data: &CertificateData) -> bool {
        let days_to_secs = |days: u32| (days as i64) * 24 * 60 * 60;

        match self.renewal_strategy {
            RenewalStrategy::DaysBeforeExpiry(value) => {
                // Default to 30 days if not specified
                let days_before = value.unwrap_or(30);
                let renewal_time = cert_data.expires_at - days_to_secs(days_before);
                now_unix_timestamp() >= renewal_time
            }
            RenewalStrategy::PercentageOfLifetime(value) => {
                // Default to 2/3 of the lifetime if not specified
                let percentage = value.unwrap_or(2.0 / 3.0);
                let lifetime = cert_data.expires_at - cert_data.valid_from;
                let elapsed = now_unix_timestamp() - cert_data.valid_from;
                (elapsed as f32 / lifetime as f32) >= percentage
            }
            RenewalStrategy::FixedInterval(value) => {
                // Default to 60 days if not specified
                let interval = value.unwrap_or(60);
                let renewal_time = cert_data.valid_from + days_to_secs(interval);
                now_unix_timestamp() >= renewal_time
            }
        }
    }

    fn parse_cert_pem(&self, cert_pem: &str) -> Result<X509Pem, CertError> {
        use x509_parser::pem::parse_x509_pem;

        let pem = parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| CertError::Parsing(e.to_string()))?
            .1;
        if pem.label != "CERTIFICATE" || pem.contents.is_empty() {
            return Err(CertError::Parsing("Invalid X509 certificate".into()));
        }
        Ok(pem)
    }

    pub(crate) fn certificate_data_from_pem(
        &self,
        certificate_pem: String,
    ) -> Result<CertificateData, CertError> {
        let parsed_cert_pem = self.parse_cert_pem(&certificate_pem)?;
        let x509 = parsed_cert_pem.parse_x509().map_err(|e| {
            error!("configured certificate appears to be invalid: {e}");
            CertError::Parsing(e.to_string())
        })?;
        Ok(CertificateData::new(
            certificate_pem,
            x509.validity().not_before.timestamp(),
            x509.validity().not_after.timestamp(),
        ))
    }

    pub(crate) fn certificate_data_from_der_or_pem(
        &self,
        certificate: Vec<u8>,
    ) -> Result<CertificateData, CertError> {
        if is_pem_certificate(&certificate) {
            let certificate_pem = String::from_utf8(certificate).map_err(|e| {
                CertError::Validation(format!("certificate PEM is not valid UTF-8: {e}"))
            })?;
            return self.certificate_data_from_pem(certificate_pem);
        }

        let (certificate_pem, valid_from, expires_at) = cert_der_chain_to_pem(certificate)?;
        Ok(CertificateData::new(
            certificate_pem,
            valid_from,
            expires_at,
        ))
    }

    pub(crate) fn cert_storage(&self) -> Result<&dyn Storage, CertError> {
        self.cert_storage
            .as_deref()
            .ok_or_else(|| CertError::Other(eyre!("Certificate storage not set")))
    }

    pub(crate) fn secrets_storage(&self) -> Result<&dyn Storage, CertError> {
        self.secrets_storage
            .as_deref()
            .ok_or_else(|| CertError::Other(eyre!("Secrets storage not set")))
    }

    pub(crate) async fn signing_key_from_storage(&self) -> Result<Option<String>, CertError> {
        self.secrets_storage()?
            .load(&self.signing_secret_id())
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn persist_certificate_data(
        &self,
        cert_data: &CertificateData,
    ) -> Result<(), CertError> {
        self.persist_certificate_data_with_storage(self.cert_storage()?, cert_data)
            .await
    }

    async fn persist_certificate_data_with_storage(
        &self,
        cert_storage: &dyn Storage,
        cert_data: &CertificateData,
    ) -> Result<(), CertError> {
        let serialized_cert_data = serde_json::to_string(cert_data)?;
        cert_storage
            .store(&self.cert_key(), &serialized_cert_data)
            .await?;
        Ok(())
    }

    pub(crate) async fn persist_signing_key(&self, signing_key: &str) -> Result<(), CertError> {
        let secrets_storage = self.secrets_storage()?;
        let secret_id = self.signing_secret_id();
        if secrets_storage.load(&secret_id).await?.is_some() {
            secrets_storage.update(&secret_id, signing_key).await?;
        } else {
            secrets_storage.store(&secret_id, signing_key).await?;
        }
        Ok(())
    }

    fn parse_cert_chain_parts(&self, cert_pem: &str) -> Result<CertificateChain, CertError> {
        use base64::prelude::{BASE64_STANDARD, Engine as _};

        let certs = X509Pem::iter_from_buffer(cert_pem.as_bytes())
            .map(|cert| {
                cert.map(|pem| BASE64_STANDARD.encode(&pem.contents))
                    .map_err(|e| CertError::Parsing(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(certs.into())
    }

    /// Parse `cert_pem` into chain parts and replace the cached entry so the
    /// next read returns the fresh chain without an extra storage load/parse.
    ///
    /// This is the hook called after a certificate is provisioned or renewed.
    async fn cache_provisioned_chain(&self, cert_pem: &str) -> Result<(), CertError> {
        let cert_key = self.cert_key();
        let parts = self.parse_cert_chain_parts(cert_pem)?;
        // Replace eagerly so the next request never hits storage for this key.
        self.cert_chain_cache.replace(cert_key, parts).await;
        Ok(())
    }

    #[inline]
    fn create_http_client(&self) -> Result<Box<dyn HttpClient>, CertError> {
        self.acme_http_client_factory
            .as_ref()
            .map(|factory| factory())
            .ok_or_else(|| CertError::Other(eyre!("ACME HTTP client factory not set")))
    }

    #[inline]
    fn cert_key(&self) -> String {
        format!("certs-{}-cert_data.json", tld_plus_one(&self.domains))
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

impl CertificateData {
    fn new(certificate: String, valid_from: i64, expires_at: i64) -> Self {
        Self {
            certificate,
            valid_from,
            expires_at,
            updated_at: now_unix_timestamp(),
        }
    }
}

fn is_pem_certificate(bytes: &[u8]) -> bool {
    bytes
        .windows(b"-----BEGIN CERTIFICATE-----".len())
        .any(|window| window == b"-----BEGIN CERTIFICATE-----")
}

fn cert_der_chain_to_pem(certificate_der: Vec<u8>) -> Result<(String, i64, i64), CertError> {
    use x509_parser::parse_x509_certificate;

    let mut remaining = certificate_der.as_slice();
    let mut certs = Vec::new();
    let mut validity = None;

    while !remaining.is_empty() {
        let before_len = remaining.len();
        let (next, cert) = parse_x509_certificate(remaining)
            .map_err(|e| CertError::Parsing(format!("invalid DER certificate chain: {e}")))?;
        let consumed_len = before_len - next.len();
        if consumed_len == 0 {
            return Err(CertError::Parsing(
                "invalid DER certificate chain: parser made no progress".to_string(),
            ));
        }

        if validity.is_none() {
            validity = Some((
                cert.validity().not_before.timestamp(),
                cert.validity().not_after.timestamp(),
            ));
        }

        let der = &remaining[..consumed_len];
        certs.push(::pem::Pem::new("CERTIFICATE", der));
        remaining = next;
    }

    let (valid_from, expires_at) =
        validity.ok_or_else(|| CertError::Parsing("empty DER certificate chain".to_string()))?;
    Ok((::pem::encode_many(&certs), valid_from, expires_at))
}

/// Setup the certificate renewal scheduler
pub async fn setup_cert_renewal_scheduler(
    cert_manager: Arc<CertManager>,
    cron_schedule: &str,
) -> Result<(), CertError> {
    let scheduler = JobScheduler::new().await?;

    // Schedule certificate renewal check based on the configured cron schedule
    scheduler
        .add(Job::new_async(cron_schedule, move |_, _| {
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
    const FORMAT: &[time::format_description::FormatItem<'_>] =
        format_description!("[year]-[month]-[day] [hour]:[minute] UTC");

    OffsetDateTime::from_unix_timestamp(timestamp)
        .ok()
        .and_then(|dt| dt.format(FORMAT).ok())
        .unwrap_or_else(|| format!("Invalid timestamp: {timestamp}"))
}

fn now_unix_timestamp() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

// Helper function to get the TLD+1
fn tld_plus_one(domains: &[String]) -> String {
    use public_suffix::{DEFAULT_PROVIDER, EffectiveTLDProvider};

    let Some(first) = domains.first() else {
        return String::new();
    };

    // Get the effective TLD+1 for the first domain
    DEFAULT_PROVIDER
        .effective_tld_plus_one(first)
        .unwrap_or(first)
        .to_string()
}
