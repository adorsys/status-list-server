//! ACME / Store Certificate adapter implementing `CertificateProvider`.

use async_trait::async_trait;

use crate::domain::{models::status_list::StatusListError, ports::CertificateProvider};

/// Adapter bridging ACME `CertManager` to domain `CertificateProvider` port.
#[cfg(feature = "acme")]
#[derive(Clone)]
pub struct AcmeCertificateProvider {
    manager: std::sync::Arc<crate::cert_manager::CertManager>,
}

#[cfg(feature = "acme")]
impl AcmeCertificateProvider {
    pub fn new(manager: std::sync::Arc<crate::cert_manager::CertManager>) -> Self {
        Self { manager }
    }
}

#[cfg(feature = "acme")]
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

/// Fallback adapter reading filesystem certificate and signing key when ACME feature is disabled.
#[cfg(not(feature = "acme"))]
#[derive(Clone)]
pub struct StoreCertificateProvider {
    cert_path: Option<String>,
    key_path: Option<String>,
}

#[cfg(not(feature = "acme"))]
impl StoreCertificateProvider {
    pub fn new(cert_path: Option<String>, key_path: Option<String>) -> Self {
        Self {
            cert_path,
            key_path,
        }
    }
}

#[cfg(not(feature = "acme"))]
#[async_trait]
impl CertificateProvider for StoreCertificateProvider {
    async fn certificate_chain(&self) -> Result<Option<Vec<String>>, StatusListError> {
        if let Some(path) = &self.cert_path {
            let content = tokio::fs::read_to_string(path)
                .await
                .map_err(|e| StatusListError::Backend(Box::new(e)))?;
            Ok(Some(vec![content]))
        } else {
            Ok(None)
        }
    }

    async fn signing_key_pem(&self) -> Result<String, StatusListError> {
        let path = self
            .key_path
            .as_deref()
            .unwrap_or("test_data/ec-private.pem");
        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| StatusListError::Backend(Box::new(e)))
    }
}
