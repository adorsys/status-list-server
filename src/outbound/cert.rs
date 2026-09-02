//! ACME / Store Certificate adapter implementing `CertificateProvider`.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use std::sync::Arc;

use crate::domain::{
    models::status_list::StatusListError,
    ports::{CertificateProvider, SigningMaterial},
};
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
    async fn signing_material(&self) -> Result<SigningMaterial, StatusListError> {
        self.manager
            .signing_material()
            .await
            .map_err(|e| StatusListError::Backend(Box::new(e)))
    }
}

/// Filesystem-backed certificate provider used when the `acme` feature is **disabled**.
///
/// Loads PEM certificate chain and PKCS#8 private key from filesystem paths,
/// validates that the certificate and key match, and caches the material in
/// memory behind an `ArcSwap` for atomic hot-reload without downtime.
///
/// Both `cert_path` and `key_path` must be set together — they are always
/// sourced from the same location type (filesystem).
#[cfg(not(feature = "acme"))]
#[derive(Clone)]
pub struct ReloadingCertificateProvider {
    active: Arc<ArcSwap<SigningMaterial>>,
}

#[cfg(not(feature = "acme"))]
impl ReloadingCertificateProvider {
    /// Load and validate initial material from disk.  Fails immediately if files
    /// are missing, unreadable, or the certificate and signing key do not match.
    pub async fn from_files(cert_path: String, key_path: String) -> Result<Self, StatusListError> {
        let material = load_and_validate_signing_material(&cert_path, &key_path).await?;
        Ok(Self {
            active: Arc::new(ArcSwap::from_pointee(material)),
        })
    }

    /// Atomically reload material from disk; retains previous material on failure.
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

#[cfg(not(feature = "acme"))]
#[async_trait]
impl CertificateProvider for ReloadingCertificateProvider {
    async fn signing_material(&self) -> Result<SigningMaterial, StatusListError> {
        Ok((*self.active.load_full()).clone())
    }
}

/// Inline certificate provider used when the `acme` feature is **disabled** and
/// material is supplied entirely via environment variables (e.g.
/// `APP_SERVER__CERT__STORE__CERTIFICATE` / `APP_SERVER__CERT__STORE__SIGNING_KEY`).
///
/// Both certificate chain and signing key must be provided together as inline PEM
/// strings — they are always sourced from the same location type (inline).
/// Material is validated once at construction; a mismatch is a hard startup error.
#[cfg(not(feature = "acme"))]
#[derive(Clone)]
pub struct InlineCertificateProvider {
    material: Arc<SigningMaterial>,
}

#[cfg(not(feature = "acme"))]
impl InlineCertificateProvider {
    /// Validate and construct an inline provider.  Fails immediately if the
    /// certificate and signing key do not match or are malformed.
    pub fn new(cert_pem: String, signing_key_pem: String) -> Result<Self, StatusListError> {
        validate_signing_material(&cert_pem, &signing_key_pem)?;
        let certificate_chain = pem_chain_to_base64_der(&cert_pem)?;
        Ok(Self {
            material: Arc::new(SigningMaterial {
                certificate_chain: Some(certificate_chain),
                signing_key_pem,
            }),
        })
    }
}

#[cfg(not(feature = "acme"))]
#[async_trait]
impl CertificateProvider for InlineCertificateProvider {
    async fn signing_material(&self) -> Result<SigningMaterial, StatusListError> {
        Ok((*self.material).clone())
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
    let certificate_chain = pem_chain_to_base64_der(&cert_pem)?;
    Ok(SigningMaterial {
        certificate_chain: Some(certificate_chain),
        signing_key_pem,
    })
}

pub(crate) fn pem_chain_to_base64_der(cert_pem: &str) -> Result<Vec<String>, StatusListError> {
    let certs = x509_parser::pem::Pem::iter_from_buffer(cert_pem.as_bytes())
        .map(|cert| {
            cert.map(|pem| BASE64_STANDARD.encode(&pem.contents))
                .map_err(|err| {
                    StatusListError::Backend(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        err.to_string(),
                    )))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(StatusListError::Backend(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "certificate chain is empty",
        ))));
    }
    Ok(certs)
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

    #[cfg(not(feature = "acme"))]
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
        let original = provider
            .signing_material()
            .await
            .expect("original material")
            .signing_key_pem;

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
            provider
                .signing_material()
                .await
                .expect("retained material")
                .signing_key_pem,
            original
        );
    }

    #[cfg(not(feature = "acme"))]
    #[tokio::test]
    async fn successful_reload_swaps_certificate_and_key_atomically() {
        let dir = TempDir::new();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        let (first_cert, first_key) = matching_cert_and_key();
        let (second_cert, second_key) = matching_cert_and_key();
        tokio::fs::write(&cert_path, first_cert)
            .await
            .expect("write cert");
        tokio::fs::write(&key_path, first_key)
            .await
            .expect("write key");

        let provider = ReloadingCertificateProvider::from_files(
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
        .await
        .expect("provider");

        tokio::fs::write(&cert_path, second_cert.clone())
            .await
            .expect("write rotated cert");
        tokio::fs::write(&key_path, second_key.clone())
            .await
            .expect("write rotated key");
        provider
            .reload_from_files(
                cert_path.to_str().expect("cert path"),
                key_path.to_str().expect("key path"),
            )
            .await
            .expect("reload");

        let material = provider.signing_material().await.expect("material");
        assert_eq!(material.signing_key_pem, second_key);
        assert_eq!(
            material.certificate_chain,
            Some(pem_chain_to_base64_der(&second_cert).expect("chain"))
        );
    }

    #[cfg(not(feature = "acme"))]
    #[tokio::test]
    async fn filesystem_provider_exports_base64_der_chain_parts() {
        let dir = TempDir::new();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        let (cert, key) = matching_cert_and_key();
        tokio::fs::write(&cert_path, cert.clone())
            .await
            .expect("write cert");
        tokio::fs::write(&key_path, key).await.expect("write key");

        let provider = ReloadingCertificateProvider::from_files(
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
        .await
        .expect("provider");
        let material = provider.signing_material().await.expect("material");
        let chain = material.certificate_chain.expect("chain");
        assert_eq!(chain, pem_chain_to_base64_der(&cert).expect("b64 der"));
        assert!(!chain[0].contains("BEGIN CERTIFICATE"));
    }

    #[cfg(not(feature = "acme"))]
    #[test]
    fn inline_provider_validates_at_construction() {
        let (cert, key) = matching_cert_and_key();
        assert!(InlineCertificateProvider::new(cert, key).is_ok());
    }

    #[cfg(not(feature = "acme"))]
    #[test]
    fn inline_provider_rejects_mismatched_cert_and_key() {
        let (cert, _) = matching_cert_and_key();
        let (_, other_key) = matching_cert_and_key();
        assert!(InlineCertificateProvider::new(cert, other_key).is_err());
    }

    #[cfg(not(feature = "acme"))]
    #[tokio::test]
    async fn inline_provider_returns_base64_der_chain() {
        let (cert, key) = matching_cert_and_key();
        let provider = InlineCertificateProvider::new(cert.clone(), key).expect("provider");
        let material = provider.signing_material().await.expect("material");
        let chain = material.certificate_chain.expect("chain");
        assert_eq!(chain, pem_chain_to_base64_der(&cert).expect("b64 der"));
    }
}
