use instant_acme::{Account, HttpClient};
use std::sync::Arc;
use tokio::sync::Mutex;

use super::{
    AcmeProvisioningStrategy, CertError, CertManager, CertManagerMetrics, CertProvisioningStrategy,
    RenewalStrategy, StoreProvisioningStrategy,
    challenge::ChallengeHandler,
    http_client::DefaultHttpClient,
    storage::{CryptoCachePolicy, CryptoStorage, Storage},
};
use crate::utils::cache::CertChainCache;

type ACMEHttpClientFactory = Box<dyn Fn() -> Box<dyn HttpClient> + Send + Sync>;

/// ACME needs a challenge handler and directory URL; store mode needs a StoreProvisioningStrategy.
pub struct CertificateManagerBuilder {
    crypto_storage: Option<Box<dyn Storage>>,
    cache_policy: CryptoCachePolicy,
    challenge_handler: Option<Box<dyn ChallengeHandler>>,
    acme_http_client_factory: Option<ACMEHttpClientFactory>,
    provisioning_strategy: Option<Box<dyn CertProvisioningStrategy>>,
    renewal_strategy: RenewalStrategy,
    domains: Vec<String>,
    email: Option<String>,
    organization: Option<String>,
    eku: Option<Vec<u64>>,
    acme_directory_url: Option<String>,
}

impl Default for CertificateManagerBuilder {
    fn default() -> Self {
        Self {
            crypto_storage: None,
            cache_policy: CryptoCachePolicy::default(),
            challenge_handler: None,
            acme_http_client_factory: None,
            provisioning_strategy: None,
            renewal_strategy: RenewalStrategy::PercentageOfLifetime(None),
            domains: Vec::new(),
            email: None,
            organization: None,
            eku: None,
            acme_directory_url: None,
        }
    }
}

impl CertificateManagerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn domains(mut self, domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.domains = domains.into_iter().map(Into::into).collect();
        self
    }

    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn organization(mut self, organization: Option<impl Into<String>>) -> Self {
        self.organization = organization.map(Into::into);
        self
    }

    pub fn acme_directory_url(mut self, url: impl Into<String>) -> Self {
        self.acme_directory_url = Some(url.into());
        self
    }

    pub fn crypto_storage(mut self, storage: impl Storage + 'static) -> Self {
        self.crypto_storage = Some(Box::new(storage));
        self
    }

    pub fn crypto_cache_policy(mut self, policy: CryptoCachePolicy) -> Self {
        self.cache_policy = policy;
        self
    }

    pub fn challenge_handler(mut self, handler: impl ChallengeHandler + 'static) -> Self {
        self.challenge_handler = Some(Box::new(handler));
        self
    }

    pub fn acme_http_client(mut self, client: impl HttpClient + Clone + 'static) -> Self {
        self.acme_http_client_factory = Some(Box::new(move || Box::new(client.clone())));
        self
    }

    pub fn renewal_strategy(mut self, strategy: RenewalStrategy) -> Self {
        self.renewal_strategy = strategy;
        self
    }

    pub fn eku(mut self, eku: &[u64]) -> Self {
        self.eku = Some(eku.to_vec());
        self
    }

    pub fn acme_strategy(mut self) -> Self {
        self.provisioning_strategy = Some(Box::new(AcmeProvisioningStrategy));
        self
    }

    pub fn store_strategy(mut self, strategy: StoreProvisioningStrategy) -> Self {
        self.provisioning_strategy = Some(Box::new(strategy));
        self
    }

    pub fn build(self) -> Result<CertManager, CertError> {
        if self.domains.is_empty() {
            return Err(CertError::validation(
                "at least one certificate domain must be configured",
            ));
        }

        let crypto_storage = self.crypto_storage.ok_or(CertError::validation(
            "cryptographic-material backend must be configured",
        ))?;
        let crypto_storage = CryptoStorage::with_cache_policy(crypto_storage, self.cache_policy);

        let default_strategy: Box<dyn CertProvisioningStrategy> =
            Box::new(AcmeProvisioningStrategy);
        let strategy = self.provisioning_strategy.unwrap_or(default_strategy);

        let strategy_uses_acme = strategy.name() == "acme";
        if strategy_uses_acme {
            if self.challenge_handler.is_none() {
                return Err(CertError::validation(
                    "ACME provisioning requires a challenge handler",
                ));
            }
            if self
                .acme_directory_url
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                return Err(CertError::validation(
                    "ACME provisioning requires an ACME directory URL",
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

        let domain_label = self.domains.first().map(String::as_str).unwrap_or_default();
        let cert_chain_cache = CertChainCache::new(domain_label);

        Ok(CertManager {
            crypto_storage: Some(crypto_storage),
            challenge_handler: self.challenge_handler,
            acme_client: Arc::new(Mutex::new(None::<Account>)),
            acme_http_client_factory: http_client_factory,
            provisioning_strategy: strategy,
            renewal_strategy: self.renewal_strategy,
            cert_chain_cache,
            active_signing_material: arc_swap::ArcSwapOption::empty(),
            provisioning_lock: Mutex::new(()),
            domains: self.domains,
            email: self.email.unwrap_or_default(),
            organization: self.organization,
            eku: self.eku,
            acme_directory_url: self.acme_directory_url.unwrap_or_default(),
            metrics: CertManagerMetrics::default(),
        })
    }
}
