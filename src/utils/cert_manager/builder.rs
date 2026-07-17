use std::{sync::Arc, time::Duration};

use instant_acme::{Account, HttpClient};
use tokio::sync::Mutex;

use super::{
    AcmeProvisioningStrategy, CertError, CertManager, CertProvisioningStrategy,
    DEFAULT_CHAIN_CACHE_TTL, RenewalStrategy, StoreProvisioningStrategy,
    challenge::ChallengeHandler, http_client::DefaultHttpClient, storage::Storage,
};
use crate::utils::cache::CertChainCache;

type ACMEHttpClientFactory = Box<dyn Fn() -> Box<dyn HttpClient> + Send + Sync>;

/// Builder for [`CertManager`].
///
/// Defaults:
/// - provisioning strategy: ACME
/// - renewal strategy: `RenewalStrategy::PercentageOfLifetime(None)`, which renews at 2/3 of the certificate lifetime
/// - ACME HTTP client: [`DefaultHttpClient`] for ACME, no client for store provisioning
/// - email: empty string when omitted
/// - organization: none
/// - EKU: none
/// - ACME directory URL: empty string, but required when ACME is selected
/// - storage backends, domains, and ACME challenge handler: not set
///
/// Required for all strategies:
/// - at least one domain
/// - certificate storage backend
/// - secrets storage backend
///
/// Required for ACME:
/// - challenge handler
/// - ACME directory URL
///
/// Required for store provisioning:
/// - a [`StoreProvisioningStrategy`] built from filesystem paths or storage keys
///
/// # Examples
///
/// ACME example:
/// ```ignore
/// let manager = CertManager::builder()
///     .domains(["statuslist.example.com"])
///     .email("support@example.com")
///     .organization(Some("example.com"))
///     .acme_directory_url("https://acme-v02.api.letsencrypt.org/directory")
///     .cert_storage(cert_storage)
///     .secrets_storage(secrets_storage)
///     .challenge_handler(challenge_handler)
///     .eku(&[1, 3, 6, 1, 5, 5, 7, 3, 30])
///     .acme_strategy()
///     .build()?;
/// ```
///
/// Store example:
/// ```ignore
/// let manager = CertManager::builder()
///     .domains(["statuslist.example.com"])
///     .cert_storage(cert_storage)
///     .secrets_storage(secrets_storage)
///     .store_strategy(StoreProvisioningStrategy::filesystem(
///         "/etc/status-list/tls.crt",
///         "/etc/status-list/tls.key",
///     ))
///     .build()?;
/// ```
pub struct CertificateManagerBuilder {
    cert_storage: Option<Box<dyn Storage>>,
    secrets_storage: Option<Box<dyn Storage>>,
    challenge_handler: Option<Box<dyn ChallengeHandler>>,
    acme_http_client_factory: Option<ACMEHttpClientFactory>,
    provisioning_strategy: Option<Box<dyn CertProvisioningStrategy>>,
    renewal_strategy: RenewalStrategy,
    chain_cache_ttl: Option<Duration>,
    domains: Vec<String>,
    email: Option<String>,
    organization: Option<String>,
    eku: Option<Vec<u64>>,
    acme_directory_url: Option<String>,
}

impl Default for CertificateManagerBuilder {
    fn default() -> Self {
        Self {
            cert_storage: None,
            secrets_storage: None,
            challenge_handler: None,
            acme_http_client_factory: None,
            provisioning_strategy: None,
            renewal_strategy: RenewalStrategy::PercentageOfLifetime(None),
            chain_cache_ttl: None,
            domains: Vec::new(),
            email: None,
            organization: None,
            eku: None,
            acme_directory_url: None,
        }
    }
}

impl CertificateManagerBuilder {
    /// Create a new certificate manager builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set subject alternative names for the server certificate.
    pub fn domains(mut self, domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.domains = domains.into_iter().map(Into::into).collect();
        self
    }

    /// Set ACME account contact email.
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set optional certificate organization name.
    pub fn organization(mut self, organization: Option<impl Into<String>>) -> Self {
        self.organization = organization.map(Into::into);
        self
    }

    /// Set the ACME directory URL.
    pub fn acme_directory_url(mut self, url: impl Into<String>) -> Self {
        self.acme_directory_url = Some(url.into());
        self
    }

    /// Set the certificate storage backend.
    pub fn cert_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.cert_storage = Some(Box::new(storage));
        self
    }

    /// Set the signing key and ACME account storage backend.
    pub fn secrets_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.secrets_storage = Some(Box::new(storage));
        self
    }

    /// Set the ACME challenge handler.
    pub fn challenge_handler(mut self, handler: impl ChallengeHandler + 'static) -> Self {
        self.challenge_handler = Some(Box::new(handler));
        self
    }

    /// Set an ACME HTTP client implementation.
    pub fn acme_http_client(mut self, client: impl HttpClient + Clone + 'static) -> Self {
        self.acme_http_client_factory = Some(Box::new(move || Box::new(client.clone())));
        self
    }

    /// Set the certificate renewal strategy used by ACME.
    pub fn renewal_strategy(mut self, strategy: RenewalStrategy) -> Self {
        self.renewal_strategy = strategy;
        self
    }

    /// Set Extended Key Usage OID.
    pub fn eku(mut self, eku: &[u64]) -> Self {
        self.eku = Some(eku.to_vec());
        self
    }

    /// Set the certificate chain cache TTL.
    pub fn chain_cache_ttl(mut self, ttl: Duration) -> Self {
        self.chain_cache_ttl = Some(ttl);
        self
    }

    /// Use ACME provisioning.
    pub fn acme_strategy(mut self) -> Self {
        self.provisioning_strategy = Some(Box::new(AcmeProvisioningStrategy));
        self
    }

    /// Use direct store-based provisioning.
    pub fn store_strategy(mut self, strategy: StoreProvisioningStrategy) -> Self {
        self.provisioning_strategy = Some(Box::new(strategy));
        self
    }

    /// Build and validate the certificate manager.
    pub fn build(self) -> Result<CertManager, CertError> {
        if self.domains.is_empty() {
            return Err(CertError::Validation(
                "at least one certificate domain must be configured".to_string(),
            ));
        }

        let cert_storage = self.cert_storage.ok_or_else(|| {
            CertError::Validation("certificate storage backend must be configured".to_string())
        })?;
        let secrets_storage = self.secrets_storage.ok_or_else(|| {
            CertError::Validation("secrets storage backend must be configured".to_string())
        })?;

        let strategy = self
            .provisioning_strategy
            .unwrap_or_else(|| Box::new(AcmeProvisioningStrategy));

        let strategy_uses_acme = strategy.name() == "acme";
        if strategy_uses_acme {
            if self.challenge_handler.is_none() {
                return Err(CertError::Validation(
                    "ACME provisioning requires a challenge handler".to_string(),
                ));
            }
            if self
                .acme_directory_url
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                return Err(CertError::Validation(
                    "ACME provisioning requires an ACME directory URL".to_string(),
                ));
            }
        }

        let http_client_factory = match self.acme_http_client_factory {
            Some(factory) => Some(factory),
            None if strategy_uses_acme => {
                let http_client = DefaultHttpClient::new(None)?;
                Some(
                    Box::new(move || Box::new(http_client.clone()) as Box<dyn HttpClient>)
                        as ACMEHttpClientFactory,
                )
            }
            None => None,
        };

        let ttl = self.chain_cache_ttl.unwrap_or(DEFAULT_CHAIN_CACHE_TTL);
        let domain_label = self.domains.first().map(String::as_str).unwrap_or_default();
        let cert_chain_cache = CertChainCache::new(ttl, domain_label);

        Ok(CertManager {
            cert_storage: Some(cert_storage),
            secrets_storage: Some(secrets_storage),
            challenge_handler: self.challenge_handler,
            acme_client: Arc::new(Mutex::new(None::<Account>)),
            acme_http_client_factory: http_client_factory,
            provisioning_strategy: strategy,
            renewal_strategy: self.renewal_strategy,
            cert_chain_cache,
            domains: self.domains,
            email: self.email.unwrap_or_default(),
            organization: self.organization,
            eku: self.eku,
            acme_directory_url: self.acme_directory_url.unwrap_or_default(),
        })
    }
}
