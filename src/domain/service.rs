//! Service container holding injected outbound adapter ports.

use crate::domain::ports::{
    CertificateProvider, CredentialRepo, StatusListCache, StatusListHistoryRepo, StatusListRepo,
};
use std::sync::Arc;

/// Container struct for building and exposing external service ports injected into handlers.
#[derive(Clone)]
pub struct Service {
    pub status_list_repo: Arc<dyn StatusListRepo>,
    pub credential_repo: Arc<dyn CredentialRepo>,
    pub status_list_cache: Arc<dyn StatusListCache>,
    pub history_repo: Option<Arc<dyn StatusListHistoryRepo>>,
    pub cert_provider: Arc<dyn CertificateProvider>,
}

impl Service {
    pub fn new<S, C, SC, CP>(
        status_list_repo: S,
        credential_repo: C,
        status_list_cache: SC,
        history_repo: Option<Arc<dyn StatusListHistoryRepo>>,
        cert_provider: CP,
    ) -> Self
    where
        S: StatusListRepo,
        C: CredentialRepo,
        SC: StatusListCache,
        CP: CertificateProvider,
    {
        Self {
            status_list_repo: Arc::new(status_list_repo),
            credential_repo: Arc::new(credential_repo),
            status_list_cache: Arc::new(status_list_cache),
            history_repo,
            cert_provider: Arc::new(cert_provider),
        }
    }

    pub fn status_list_repo(&self) -> &dyn StatusListRepo {
        self.status_list_repo.as_ref()
    }

    pub fn credential_repo(&self) -> &dyn CredentialRepo {
        self.credential_repo.as_ref()
    }

    pub fn status_list_cache(&self) -> &dyn StatusListCache {
        self.status_list_cache.as_ref()
    }

    pub fn history_repo(&self) -> Option<&dyn StatusListHistoryRepo> {
        self.history_repo.as_deref()
    }

    pub fn cert_provider(&self) -> &dyn CertificateProvider {
        self.cert_provider.as_ref()
    }
}
