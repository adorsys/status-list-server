use std::path::PathBuf;

use async_trait::async_trait;
use tokio::fs;
use tracing::info;

use super::{CertError, CertManager, CertificateData};
use crate::outbound::cert::validate_signing_material;
use crate::utils::keygen::Keypair;

/// Provisioning strategy used by [`CertManager`].
#[async_trait]
pub trait CertProvisioningStrategy: Send + Sync {
    /// Human-readable strategy name used in logs and validation errors.
    fn name(&self) -> &'static str;

    /// Whether an existing stored certificate should be checked by this strategy.
    fn should_provision_existing(
        &self,
        manager: &CertManager,
        certificate: &CertificateData,
    ) -> bool;

    /// Provision, renew, or refresh certificate material.
    async fn provision(&self, manager: &CertManager) -> Result<CertificateData, CertError>;
}

/// ACME-based provisioning strategy.
#[derive(Debug, Clone, Default)]
pub struct AcmeProvisioningStrategy;

#[async_trait]
impl CertProvisioningStrategy for AcmeProvisioningStrategy {
    fn name(&self) -> &'static str {
        "acme"
    }

    fn should_provision_existing(
        &self,
        manager: &CertManager,
        certificate: &CertificateData,
    ) -> bool {
        manager.should_renew_cert(certificate)
    }

    async fn provision(&self, manager: &CertManager) -> Result<CertificateData, CertError> {
        manager.request_acme_certificate().await
    }
}

/// Source of individual cryptographic material (certificate or private key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterialSource {
    /// Load from a filesystem path.
    Filesystem(PathBuf),
    /// Load from the configured cryptographic material storage by key.
    Storage(String),
}

/// Source for directly provisioned certificate material.
#[derive(Debug, Clone)]
pub enum StoreProvisioningSource {
    /// Load PEM-encoded certificate chain and PKCS#8 signing key from local files.
    Filesystem {
        certificate_path: PathBuf,
        signing_key_path: PathBuf,
    },
    /// Load PEM-encoded certificate chain and PKCS#8 signing key from the configured material backend.
    Storage {
        certificate_key: String,
        signing_key_key: String,
    },
    /// Load certificate and signing key from independent sources.
    Mixed {
        certificate_source: MaterialSource,
        signing_key_source: MaterialSource,
    },
}

/// Store-based provisioning strategy.
#[derive(Debug, Clone)]
pub struct StoreProvisioningStrategy {
    certificate_source: MaterialSource,
    signing_key_source: MaterialSource,
}

impl StoreProvisioningStrategy {
    /// Build a store strategy with explicit sources for certificate and signing key.
    pub fn new(certificate_source: MaterialSource, signing_key_source: MaterialSource) -> Self {
        Self {
            certificate_source,
            signing_key_source,
        }
    }

    /// Build a store strategy that loads certificate material from filesystem paths.
    pub fn filesystem(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self {
            certificate_source: MaterialSource::Filesystem(cert_path.into()),
            signing_key_source: MaterialSource::Filesystem(key_path.into()),
        }
    }

    /// Build a store strategy that loads certificate material from the manager's configured storages.
    pub fn storage(certificate_key: impl Into<String>, signing_key_key: impl Into<String>) -> Self {
        Self {
            certificate_source: MaterialSource::Storage(certificate_key.into()),
            signing_key_source: MaterialSource::Storage(signing_key_key.into()),
        }
    }

    async fn load_source(
        source: &MaterialSource,
        manager: &CertManager,
        label: &str,
    ) -> Result<Vec<u8>, CertError> {
        match source {
            MaterialSource::Filesystem(path) => fs::read(path).await.map_err(|e| {
                CertError::Validation(format!(
                    "failed to read {label} file '{}': {e}",
                    path.display()
                ))
            }),
            MaterialSource::Storage(key) => {
                let material_storage = manager.crypto_storage()?;
                let secret = material_storage.load_secret(key).await?.ok_or_else(|| {
                    CertError::Validation(format!("store {label} key '{key}' was not found"))
                })?;
                decode_text_material(secret, label)
            }
        }
    }

    async fn load_material(&self, manager: &CertManager) -> Result<(Vec<u8>, Vec<u8>), CertError> {
        let certificate =
            Self::load_source(&self.certificate_source, manager, "certificate").await?;
        let signing_key =
            Self::load_source(&self.signing_key_source, manager, "signing key").await?;
        Ok((certificate, signing_key))
    }
}

#[async_trait]
impl CertProvisioningStrategy for StoreProvisioningStrategy {
    fn name(&self) -> &'static str {
        "store"
    }

    fn should_provision_existing(
        &self,
        _manager: &CertManager,
        _certificate: &CertificateData,
    ) -> bool {
        true
    }

    async fn provision(&self, manager: &CertManager) -> Result<CertificateData, CertError> {
        let (certificate, signing_key) = self.load_material(manager).await?;
        let signing_key_pem = normalize_pkcs8_key(signing_key)?;

        let certificate_data = manager.certificate_data_from_der_or_pem(certificate)?;
        validate_signing_material(&certificate_data.certificate, &signing_key_pem)
            .map_err(|err| CertError::Validation(err.to_string()))?;
        let current_certificate = manager.certificate().await?;
        let current_signing_key = manager.signing_key_from_storage().await?;

        if current_certificate.as_ref().is_some_and(|current| {
            current.certificate.as_str() == certificate_data.certificate.as_str()
        }) && current_signing_key.as_deref() == Some(signing_key_pem.as_str())
        {
            info!("Store certificate material is unchanged");
            return Ok(current_certificate.unwrap_or(certificate_data));
        }

        manager
            .persist_crypto_material(&certificate_data, &signing_key_pem)
            .await?;
        info!("Store certificate material refreshed");
        Ok(certificate_data)
    }
}

fn decode_text_material(value: String, label: &str) -> Result<Vec<u8>, CertError> {
    if value.contains("-----BEGIN ") {
        return Ok(value.into_bytes());
    }

    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Err(CertError::Validation(format!("{label} material is empty")));
    }

    decode_base64_text(&compact).ok_or_else(|| {
        CertError::Validation(format!(
            "{label} material must be PEM text or base64/base64url-encoded DER"
        ))
    })
}

fn decode_base64_text(value: &str) -> Option<Vec<u8>> {
    use base64::prelude::{
        BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD,
        Engine as _,
    };

    BASE64_STANDARD
        .decode(value)
        .or_else(|_| BASE64_STANDARD_NO_PAD.decode(value))
        .or_else(|_| BASE64_URL_SAFE.decode(value))
        .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(value))
        .ok()
}

fn normalize_pkcs8_key(signing_key: Vec<u8>) -> Result<String, CertError> {
    if is_pem_private_key(&signing_key) {
        let pem = String::from_utf8(signing_key).map_err(|e| {
            CertError::Validation(format!("signing key PEM is not valid UTF-8: {e}"))
        })?;
        Keypair::from_pkcs8_pem(&pem)?;
        return Ok(pem);
    }

    let keypair = Keypair::from_pkcs8_der(&signing_key)?;
    keypair.to_pkcs8_pem().map_err(Into::into)
}

fn is_pem_private_key(bytes: &[u8]) -> bool {
    bytes
        .windows(b"-----BEGIN ".len())
        .any(|window| window == b"-----BEGIN ")
}
