mod builder;
mod errors;
mod strategy;
#[cfg(test)]
mod tests;

pub mod challenge;
pub mod http_client;
pub mod storage;

use crate::utils::cache::{CertChainCache, CertificateChain};
use crate::utils::cert_manager::storage::{CryptoStorage, Storage};
use crate::utils::crypto::{SigningAlgorithm, SigningKey};
use arc_swap::ArcSwapOption;
pub use builder::CertificateManagerBuilder;
use challenge::CleanupFuture;
pub use errors::CertError;
pub use strategy::{
    AcmeProvisioningStrategy, CertProvisioningStrategy, MaterialSource, StoreProvisioningSource,
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
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info, instrument, warn};
use x509_parser::pem::Pem as X509Pem;

use crate::cert_manager::{challenge::ChallengeHandler, http_client::DefaultHttpClient};
use crate::domain::ports::SigningMaterial;

use opentelemetry::{
    global,
    metrics::{Counter, Gauge},
};

const RENEWAL_ATTEMPTS_METRIC: &str = "cert_renewal_attempts";
const RENEWAL_SUCCESSES_METRIC: &str = "cert_renewal_successes";
const RENEWAL_FAILURES_METRIC: &str = "cert_renewal_failures";
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateData {
    pub certificate: String,
    pub valid_from: i64,
    pub expires_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub enum RenewalStrategy {
    /// Days after issue; defaults to 60.
    FixedInterval(Option<u32>),
    /// Defaults to 30.
    DaysBeforeExpiry(Option<u32>),
    /// A fraction (0.0 to 1.0), not a percent; defaults to 2/3.
    PercentageOfLifetime(Option<f32>),
}

type ACMEHttpClientFactory = Box<dyn Fn() -> Box<dyn HttpClient> + Send + Sync>;

pub struct CertManager {
    crypto_storage: Option<CryptoStorage>,
    challenge_handler: Option<Box<dyn ChallengeHandler>>,
    acme_client: Arc<Mutex<Option<Account>>>,
    acme_http_client_factory: Option<ACMEHttpClientFactory>,
    provisioning_strategy: Box<dyn CertProvisioningStrategy>,
    renewal_strategy: RenewalStrategy,
    cert_chain_cache: CertChainCache,
    active_signing_material: ArcSwapOption<SigningMaterial>,
    // Serializes manual reloads with the renewal cron.
    provisioning_lock: Mutex<()>,
    domains: Vec<String>,
    email: String,
    organization: Option<String>,
    eku: Option<Vec<u64>>,
    acme_directory_url: String,
    metrics: CertManagerMetrics,
}

impl CertManager {
    pub fn builder() -> CertificateManagerBuilder {
        CertificateManagerBuilder::default()
    }

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
        let cert_chain_cache = CertChainCache::new(domain_label);

        Ok(Self {
            crypto_storage: None,
            challenge_handler: None,
            acme_client: Arc::new(Mutex::new(None)),
            acme_http_client_factory: Some(acme_http_client_factory),
            provisioning_strategy: Box::new(AcmeProvisioningStrategy),
            renewal_strategy,
            cert_chain_cache,
            active_signing_material: ArcSwapOption::empty(),
            provisioning_lock: Mutex::new(()),
            domains,
            email: email.into(),
            organization: organization.map(|o| o.into()),
            eku: None,
            acme_directory_url: acme_directory_url.into(),
            metrics: CertManagerMetrics::default(),
        })
    }

    pub fn with_crypto_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.crypto_storage = Some(CryptoStorage::new(storage));
        self
    }

    /// Required.
    pub fn with_challenge_handler(mut self, handler: impl ChallengeHandler + 'static) -> Self {
        self.challenge_handler = Some(Box::new(handler));
        self
    }

    pub fn with_acme_http_client(mut self, client: impl HttpClient + Clone + 'static) -> Self {
        self.acme_http_client_factory = Some(Box::new(move || Box::new(client.clone())));
        self
    }

    pub fn with_renewal_strategy(mut self, strategy: RenewalStrategy) -> Self {
        self.renewal_strategy = strategy;
        self
    }

    pub fn with_provisioning_strategy(
        mut self,
        strategy: impl CertProvisioningStrategy + 'static,
    ) -> Self {
        self.provisioning_strategy = Box::new(strategy);
        self
    }

    pub fn with_eku(mut self, eku: &[u64]) -> Self {
        self.eku = Some(eku.to_vec());
        self
    }

    /// Call after the metrics recorder is installed, or the zeros go nowhere.
    pub fn init_cert_chain_cache_counters(&self) {
        self.cert_chain_cache.init_counters();
    }

    /// Call after the metrics recorder is installed.
    pub fn init_renewal_counters(&self) {
        self.metrics.attempts.add(0, &[]);
        self.metrics.successes.add(0, &[]);
        self.metrics.failures.add(0, &[]);
    }

    fn update_time_to_expiry(&self, cert_data: &CertificateData) {
        let now = now_unix_timestamp();
        let time_to_expiry = cert_data.expires_at.saturating_sub(now);
        self.metrics.time_to_expiry.record(time_to_expiry, &[]);
    }

    fn record_successful_renewal(&self) {
        self.metrics.successes.add(1, &[]);
        self.metrics
            .last_successful_renewal
            .record(now_unix_timestamp(), &[]);
    }

    fn record_failed_renewal(&self) {
        self.metrics.failures.add(1, &[]);
    }

    #[instrument(
        name = "Provisioning certificate",
        skip(self),
        fields(
            domains = ?self.domains,
            strategy = %self.provisioning_strategy.name()
        )
    )]
    pub async fn request_certificate(&self) -> Result<CertificateData, CertError> {
        let _guard = self.provisioning_lock.lock().await;
        self.provisioning_strategy.provision(self).await
    }

    pub(crate) async fn request_acme_certificate(&self) -> Result<CertificateData, CertError> {
        use instant_acme::RetryPolicy;

        self.crypto_storage()?;

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

        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        let mut cleanup_futures = vec![];
        let mut authorizations = order.authorizations();
        while let Some(authz_result) = authorizations.next().await {
            let mut authz = authz_result?;

            if authz.status == AuthorizationStatus::Valid {
                continue;
            }

            let cleanup_future = challenge_handler.handle_authorization(&mut authz).await?;
            cleanup_futures.push(cleanup_future);
        }

        self.poll_order(&mut order, cleanup_futures).await?;

        let server_key_pem = self.signing_key_pem().await?;
        let csr_der_bytes = self.generate_csr(&server_key_pem)?;

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

        self.persist_certificate_data(&cert_data).await?;
        self.cache_provisioned_chain(&cert_data.certificate).await?;
        self.store_active_signing_material(&cert_data.certificate, &server_key_pem)
            .await?;

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

        // Runs whether or not issuance succeeded.
        for cleanup_future in cleanup_futures {
            if let Err(e) = cleanup_future.run().await {
                warn!("Failed to clean up challenge: {e}");
            }
        }
        result
    }

    #[instrument(
        name = "Getting Server Signing Secret",
        skip(self),
        fields(domains = ?self.domains)
    )]
    pub async fn signing_key_pem(&self) -> Result<String, CertError> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY: Duration = Duration::from_millis(500);

        let material_storage = self.crypto_storage()?;

        let secret_id = self.signing_secret_id();
        if let Some(secret) = material_storage.load_signing_key(&secret_id).await? {
            info!("Found existing server secret. Skipping...");
            return Ok(secret);
        }

        warn!("No existing server secret found. Generating a new one...");
        let key = SigningKey::generate(SigningAlgorithm::Es256)?;
        let key_pem = key.to_pkcs8_pem()?;
        let mut retries = 0;
        loop {
            info!("Trying to store the newly generated server secret...");
            match material_storage
                .store_signing_key(&secret_id, &key_pem)
                .await
            {
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

    /// `None` until a certificate has been stored.
    ///
    /// # Errors
    ///
    /// Fails if no storage backend is configured, the backend errors, or the data doesn't parse.
    pub async fn certificate(&self) -> Result<Option<CertificateData>, CertError> {
        let material_storage = self.crypto_storage()?;
        let cert_key = self.cert_key();
        if let Some(cert_data) = material_storage.load_certificate_data(&cert_key).await? {
            return Ok(Some(serde_json::from_str(&cert_data)?));
        }
        Ok(None)
    }

    /// `None` when no certificate has been provisioned yet.
    ///
    /// # Errors
    ///
    /// Fails if loading the certificate fails or its chain doesn't parse.
    pub async fn cert_chain_parts(&self) -> Result<Option<CertificateChain>, CertError> {
        let cert_key = self.cert_key();
        if let Some(certs) = self.cert_chain_cache.get(&cert_key).await {
            return Ok(Some(certs));
        }
        if let Some(cert_data) = self.certificate().await? {
            let certs = self.parse_cert_chain_parts(&cert_data.certificate)?;
            // May race a renewal and cache the old chain; harmless, the key survives renewals.
            self.cert_chain_cache.insert(cert_key, certs.clone()).await;
            return Ok(Some(certs));
        }
        Ok(None)
    }

    /// Chain and key always come from the same snapshot.
    pub async fn signing_material(&self) -> Result<Arc<SigningMaterial>, CertError> {
        if let Some(material) = self.active_signing_material.load_full() {
            return Ok(material);
        }

        let _guard = self.provisioning_lock.lock().await;
        if let Some(material) = self.active_signing_material.load_full() {
            return Ok(material);
        }

        let signing_key_pem = self.signing_key_pem().await?;
        let certificate_chain = self.cert_chain_parts().await?;
        let signing_key = SigningKey::from_pem(&signing_key_pem).map_err(CertError::KeyOp)?;
        let material = SigningMaterial::new(
            certificate_chain.map(|c| c.as_ref().to_vec()),
            Arc::new(signing_key),
        )
        .map_err(|e| CertError::Validation(Box::new(e)))?;
        let material = Arc::new(material);
        self.active_signing_material
            .store(Some(Arc::clone(&material)));
        Ok(material)
    }

    #[instrument(
        name = "Checking Certificate Renewal",
        skip(self),
        fields(domains = ?self.domains)
    )]
    pub async fn renew_cert_if_needed(&self) -> Result<(), CertError> {
        self.metrics.attempts.add(1, &[]);

        if let Some(cert_data) = self.certificate().await? {
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

    #[instrument(
        name = "Getting or Creating ACME Account",
        skip(self),
        fields(domains = ?self.domains, email = %self.email)
    )]
    async fn acme_account(&self) -> Result<Account, CertError> {
        let material_storage = self.crypto_storage()?;

        let mut client_guard = self.acme_client.lock().await;
        if let Some(account) = client_guard.as_ref() {
            info!("Found existing ACME account. Skipping...");
            return Ok(account.clone());
        }

        let account_id = self.acme_account_id();
        if let Some(credentials) = material_storage.load_secret(&account_id).await? {
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
                    material_storage.delete_secret(&account_id).await?;
                }
            }
        }
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
        material_storage
            .store_secret(&account_id, &serde_json::to_string(&credentials)?)
            .await?;
        *client_guard = Some(account.clone());
        info!("Account successfully created");
        Ok(account)
    }

    fn generate_csr(&self, signing_key: &str) -> Result<Vec<u8>, CertError> {
        let mut params = CertificateParams::new(self.domains.clone())
            .map_err(|e| CertError::Parsing(e.to_string()))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &self.domains[0]);
        if let Some(organization) = &self.organization {
            dn.push(DnType::OrganizationName, organization);
        }
        params.distinguished_name = dn;
        // EKU for status list signing, draft-ietf-oauth-status-list §10.1.
        if let Some(eku) = &self.eku {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(eku.to_vec())];
        }
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

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
                let days_before = value.unwrap_or(30);
                let renewal_time = cert_data.expires_at - days_to_secs(days_before);
                now_unix_timestamp() >= renewal_time
            }
            RenewalStrategy::PercentageOfLifetime(value) => {
                let percentage = value.unwrap_or(2.0 / 3.0);
                let lifetime = cert_data.expires_at - cert_data.valid_from;
                let elapsed = now_unix_timestamp() - cert_data.valid_from;
                (elapsed as f32 / lifetime as f32) >= percentage
            }
            RenewalStrategy::FixedInterval(value) => {
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

    pub(crate) fn crypto_storage(&self) -> Result<&CryptoStorage, CertError> {
        self.crypto_storage
            .as_ref()
            .ok_or_else(|| CertError::Other(eyre!("Cryptographic-material backend not set")))
    }

    pub(crate) async fn signing_key_from_storage(&self) -> Result<Option<String>, CertError> {
        self.crypto_storage()?
            .load_signing_key(&self.signing_secret_id())
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn persist_certificate_data(
        &self,
        cert_data: &CertificateData,
    ) -> Result<(), CertError> {
        let serialized_cert_data = serde_json::to_string(cert_data)?;
        let material_storage = self.crypto_storage()?;
        let cert_key = self.cert_key();
        if material_storage
            .load_certificate_data(&cert_key)
            .await?
            .is_some()
        {
            material_storage
                .update_certificate_data(&cert_key, &serialized_cert_data)
                .await?;
        } else {
            material_storage
                .store_certificate_data(&cert_key, &serialized_cert_data)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn persist_signing_key(&self, signing_key: &str) -> Result<(), CertError> {
        let material_storage = self.crypto_storage()?;
        let secret_id = self.signing_secret_id();
        if material_storage
            .load_signing_key(&secret_id)
            .await?
            .is_some()
        {
            material_storage
                .update_signing_key(&secret_id, signing_key)
                .await?;
        } else {
            material_storage
                .store_signing_key(&secret_id, signing_key)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn persist_crypto_material(
        &self,
        cert_data: &CertificateData,
        signing_key: &str,
    ) -> Result<(), CertError> {
        self.persist_certificate_data(cert_data).await?;
        self.persist_signing_key(signing_key).await?;
        self.cache_provisioned_chain(&cert_data.certificate).await?;
        self.store_active_signing_material(&cert_data.certificate, signing_key)
            .await
    }

    async fn store_active_signing_material(
        &self,
        cert_pem: &str,
        signing_key_pem: &str,
    ) -> Result<(), CertError> {
        let certs = self.parse_cert_chain_parts(cert_pem)?;
        let signing_key = SigningKey::from_pem(signing_key_pem).map_err(CertError::KeyOp)?;
        let material = SigningMaterial::new(Some(certs.as_ref().to_vec()), Arc::new(signing_key))
            .map_err(|e| CertError::Validation(Box::new(e)))?;
        self.active_signing_material.store(Some(Arc::new(material)));
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
        storage::normalize_key(&format!(
            "certs-{}-cert_data.json",
            tld_plus_one(&self.domains)
        ))
    }

    #[inline]
    fn acme_account_id(&self) -> String {
        storage::normalize_key(&format!("acme_accounts-{}", tld_plus_one(&self.domains)))
    }

    #[inline]
    fn signing_secret_id(&self) -> String {
        storage::normalize_key(&format!("keys-{}", self.domains.join("-")))
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

pub async fn setup_cert_renewal_scheduler(
    cert_manager: Arc<CertManager>,
    cron_schedule: &str,
) -> Result<(), CertError> {
    let scheduler = JobScheduler::new().await?;

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

fn tld_plus_one(domains: &[String]) -> String {
    use public_suffix::{DEFAULT_PROVIDER, EffectiveTLDProvider};

    let Some(first) = domains.first() else {
        return String::new();
    };

    DEFAULT_PROVIDER
        .effective_tld_plus_one(first)
        .unwrap_or(first)
        .to_string()
}
