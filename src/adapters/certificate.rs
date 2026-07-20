//! Adapter exposing the existing ACME certificate manager through the
//! application-facing certificate port.
use async_trait::async_trait;
use std::sync::Arc;

use crate::{
    cert_manager::CertManager,
    ports::{CertificateProvider, PortError},
};

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
    async fn certificate_chain(&self) -> Result<Option<Vec<String>>, PortError> {
        self.manager
            .cert_chain_parts()
            .await
            .map_err(|e| PortError::ExternalServiceUnavailable {
                operation: "load certificate chain",
                detail: e.to_string(),
            })
            .map(|opt| opt.map(|arc| arc.to_vec()))
    }

    async fn signing_key_pem(&self) -> Result<String, PortError> {
        self.manager
            .signing_key_pem()
            .await
            .map_err(|e| PortError::ExternalServiceUnavailable {
                operation: "load signing key",
                detail: e.to_string(),
            })
    }
}
