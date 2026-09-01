//! ACME / Store Certificate adapter implementing `CertificateProvider`.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::sync::Arc;

use crate::domain::{models::status_list::StatusListError, ports::CertificateProvider};
use crate::utils::keygen::Keypair;

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

#[derive(Clone)]
pub struct ReloadingCertificateProvider {
    active: Arc<ArcSwap<SigningMaterial>>,
}

#[derive(Debug)]
struct SigningMaterial {
    certificate_chain: Option<Vec<String>>,
    signing_key_pem: String,
}

impl ReloadingCertificateProvider {
    pub async fn from_files(cert_path: String, key_path: String) -> Result<Self, StatusListError> {
        let material = load_and_validate_signing_material(&cert_path, &key_path).await?;
        Ok(Self {
            active: Arc::new(ArcSwap::from_pointee(material)),
        })
    }

    pub async fn reload_from_files(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), StatusListError> {
        let material = load_and_validate_signing_material(cert_path, key_path).await?;
        self.active.store(Arc::new(material));
        Ok(())
    }
}

#[async_trait]
impl CertificateProvider for ReloadingCertificateProvider {
    async fn certificate_chain(&self) -> Result<Option<Vec<String>>, StatusListError> {
        Ok(self.active.load_full().certificate_chain.clone())
    }

    async fn signing_key_pem(&self) -> Result<String, StatusListError> {
        Ok(self.active.load_full().signing_key_pem.clone())
    }
}

async fn load_and_validate_signing_material(
    cert_path: &str,
    key_path: &str,
) -> Result<SigningMaterial, StatusListError> {
    let cert_pem = tokio::fs::read_to_string(cert_path)
        .await
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;
    let signing_key_pem = tokio::fs::read_to_string(key_path)
        .await
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;
    validate_signing_material(&cert_pem, &signing_key_pem)?;
    Ok(SigningMaterial {
        certificate_chain: Some(vec![cert_pem]),
        signing_key_pem,
    })
}

pub(crate) fn validate_signing_material(
    cert_pem: &str,
    signing_key_pem: &str,
) -> Result<(), StatusListError> {
    let keypair = Keypair::from_pkcs8_pem(signing_key_pem)
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;
    let (_, cert_pem_block) =
        x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).map_err(|err| {
            StatusListError::Backend(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err.to_string(),
            )))
        })?;
    let (_, certificate) = x509_parser::parse_x509_certificate(cert_pem_block.contents.as_ref())
        .map_err(|err| {
            StatusListError::Backend(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err.to_string(),
            )))
        })?;
    let cert_public_key = certificate.public_key().subject_public_key.data.as_ref();
    let key_public_key = keypair.verifying_key().to_sec1_point(false);
    if cert_public_key != key_public_key.as_bytes() {
        return Err(StatusListError::Backend(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "certificate public key does not match signing key",
        ))));
    }
    jsonwebtoken::EncodingKey::from_ec_pem(signing_key_pem.as_bytes())
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "status-list-cert-test-{}-{}",
                std::process::id(),
                time::OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn matching_cert_and_key() -> (String, String) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("generate test key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate params")
            .self_signed(&key)
            .expect("self-signed certificate")
            .pem();
        (cert, key.serialize_pem())
    }

    #[test]
    fn validates_matching_ec_certificate_and_key() {
        let (cert, key) = matching_cert_and_key();
        validate_signing_material(&cert, &key).expect("fixture cert/key should validate");
    }

    #[test]
    fn rejects_mismatched_certificate_and_key() {
        let err = validate_signing_material(
            include_str!("../../test_data/certs/emulator.crt"),
            include_str!("../../test_data/ec-private.pem"),
        )
        .expect_err("mismatched cert/key should fail");
        assert!(!err.to_string().contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn malformed_reload_keeps_last_known_good_material() {
        let dir = TempDir::new();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        let (cert, key) = matching_cert_and_key();
        tokio::fs::write(&cert_path, cert)
            .await
            .expect("write cert");
        tokio::fs::write(&key_path, key).await.expect("write key");

        let provider = ReloadingCertificateProvider::from_files(
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
        .await
        .expect("provider");
        let original = provider.signing_key_pem().await.expect("original key");

        tokio::fs::write(&key_path, "not a private key")
            .await
            .expect("write malformed key");
        assert!(
            provider
                .reload_from_files(
                    cert_path.to_str().expect("cert path"),
                    key_path.to_str().expect("key path")
                )
                .await
                .is_err()
        );
        assert_eq!(
            provider.signing_key_pem().await.expect("retained key"),
            original
        );
    }
}
