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
            cert_path: cert_path.filter(|p| !p.trim().is_empty()),
            key_path: key_path.filter(|p| !p.trim().is_empty()),
        }
    }
}

#[cfg(not(feature = "acme"))]
#[async_trait]
impl CertificateProvider for StoreCertificateProvider {
    async fn certificate_chain(&self) -> Result<Option<Vec<String>>, StatusListError> {
        let Some(path) = &self.cert_path else {
            return Ok(None);
        };
        let content = tokio::fs::read(path)
            .await
            .map_err(|e| StatusListError::Backend(Box::new(e)))?;

        use base64::prelude::{BASE64_STANDARD, Engine as _};
        use x509_parser::pem::Pem as X509Pem;

        let certs: Vec<String> = X509Pem::iter_from_buffer(&content)
            .map(|cert| {
                cert.map(|pem| BASE64_STANDARD.encode(&pem.contents))
                    .map_err(|e| StatusListError::Backend(Box::new(e)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        if certs.is_empty() {
            if !content.is_empty() {
                Ok(Some(vec![BASE64_STANDARD.encode(&content)]))
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(certs))
        }
    }

    async fn signing_key_pem(&self) -> Result<String, StatusListError> {
        let path = self.key_path.as_deref().ok_or_else(|| {
            StatusListError::Backend(Box::from(
                "no signing key path configured (server.cert.store.signing_key_path); \
                 a PEM-encoded PKCS#8 private key is required for token signing",
            ))
        })?;
        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| StatusListError::Backend(Box::new(e)))
    }
}

#[cfg(all(test, not(feature = "acme")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signing_key_pem_fails_when_no_key_path_configured() {
        let provider = StoreCertificateProvider::new(None, None);
        let result = provider.signing_key_pem().await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no signing key path configured"),
            "unexpected error: {err_msg}"
        );
    }

    #[tokio::test]
    async fn signing_key_pem_fails_when_key_path_is_empty() {
        let provider = StoreCertificateProvider::new(None, Some("   ".to_string()));
        let result = provider.signing_key_pem().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn certificate_chain_returns_none_when_no_cert_path() {
        let provider = StoreCertificateProvider::new(None, None);
        let result = provider.certificate_chain().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn signing_key_pem_loads_valid_key() {
        let provider =
            StoreCertificateProvider::new(None, Some("test_data/ec-private.pem".to_string()));
        let result = provider.signing_key_pem().await;
        assert!(result.is_ok());
        let key = result.unwrap();
        assert!(key.contains("-----BEGIN"));
    }
}
