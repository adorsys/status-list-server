//! ACME Certificate Manager adapter implementing `CertificateProvider`.

use async_trait::async_trait;
use std::sync::Arc;

use crate::{
    cert_manager::CertManager,
    domain::{models::status_list::StatusListError, ports::CertificateProvider},
};

/// Adapter bridging ACME `CertManager` to domain `CertificateProvider` port.
#[derive(Clone)]
pub struct AcmeCertificateProvider {
    manager: Arc<CertManager>,
}

impl AcmeCertificateProvider {
    pub fn new(manager: Arc<CertManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl CertificateProvider for AcmeCertificateProvider {
    async fn certificate_chain(&self) -> Result<Option<Vec<String>>, StatusListError> {
        self.manager
            .cert_chain_parts()
            .await
            .map_err(|e| StatusListError::Backend(Box::new(e)))
            .map(|opt| opt.map(|arc| arc.to_vec()))
    }

    async fn signing_key_pem(&self) -> Result<String, StatusListError> {
        self.manager
            .signing_key_pem()
            .await
            .map_err(|e| StatusListError::Backend(Box::new(e)))
    }
}
