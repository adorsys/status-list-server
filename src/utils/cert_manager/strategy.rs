use std::path::PathBuf;

use async_trait::async_trait;
use tokio::fs;
use tracing::info;

use super::{CertError, CertManager, CertificateData};
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

/// Source for directly provisioned certificate material.
#[derive(Debug, Clone)]
pub enum StoreProvisioningSource {
    /// Load PEM-encoded certificate chain and PKCS#8 signing key from local files.
    Filesystem {
        certificate_path: PathBuf,
        signing_key_path: PathBuf,
    },
    /// Load PEM-encoded certificate chain and PKCS#8 signing key from configured storage backends.
    Storage {
        certificate_key: String,
        signing_key_key: String,
    },
    /// Load PEM-encoded certificate chain and PKCS#8 signing key from the secrets backend.
    SecretsStorage {
        certificate_key: String,
        signing_key_key: String,
    },
}

/// Store-based provisioning strategy.
#[derive(Debug, Clone)]
pub struct StoreProvisioningStrategy {
    source: StoreProvisioningSource,
}

impl StoreProvisioningStrategy {
    /// Build a store strategy that loads certificate material from filesystem paths.
    pub fn filesystem(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self {
            source: StoreProvisioningSource::Filesystem {
                certificate_path: cert_path.into(),
                signing_key_path: key_path.into(),
            },
        }
    }

    /// Build a store strategy that loads certificate material from the manager's configured storages.
    pub fn storage(certificate_key: impl Into<String>, signing_key_key: impl Into<String>) -> Self {
        Self {
            source: StoreProvisioningSource::Storage {
                certificate_key: certificate_key.into(),
                signing_key_key: signing_key_key.into(),
            },
        }
    }

    /// Build a store strategy that loads both PEM values from the configured secrets backend.
    pub fn secrets_storage(
        certificate_key: impl Into<String>,
        signing_key_key: impl Into<String>,
    ) -> Self {
        Self {
            source: StoreProvisioningSource::SecretsStorage {
                certificate_key: certificate_key.into(),
                signing_key_key: signing_key_key.into(),
            },
        }
    }

    async fn load_material(&self, manager: &CertManager) -> Result<(Vec<u8>, Vec<u8>), CertError> {
        match &self.source {
            StoreProvisioningSource::Filesystem {
                certificate_path,
                signing_key_path,
            } => {
                let certificate = fs::read(certificate_path).await.map_err(|e| {
                    CertError::Validation(format!(
                        "failed to read certificate file '{}': {e}",
                        certificate_path.display()
                    ))
                })?;
                let signing_key = fs::read(signing_key_path).await.map_err(|e| {
                    CertError::Validation(format!(
                        "failed to read signing key file '{}': {e}",
                        signing_key_path.display()
                    ))
                })?;
                Ok((certificate, signing_key))
            }
            StoreProvisioningSource::Storage {
                certificate_key,
                signing_key_key,
            } => {
                let cert_storage = manager.cert_storage()?;
                let secrets_storage = manager.secrets_storage()?;
                let certificate = cert_storage.load(certificate_key).await?.ok_or_else(|| {
                    CertError::Validation(format!(
                        "store certificate key '{certificate_key}' was not found"
                    ))
                })?;
                let signing_key =
                    secrets_storage
                        .load(signing_key_key)
                        .await?
                        .ok_or_else(|| {
                            CertError::Validation(format!(
                                "store signing key key '{signing_key_key}' was not found"
                            ))
                        })?;
                Ok((
                    decode_text_material(certificate, "certificate")?,
                    decode_text_material(signing_key, "signing key")?,
                ))
            }
            StoreProvisioningSource::SecretsStorage {
                certificate_key,
                signing_key_key,
            } => {
                let secrets_storage = manager.secrets_storage()?;
                let certificate =
                    secrets_storage
                        .load(certificate_key)
                        .await?
                        .ok_or_else(|| {
                            CertError::Validation(format!(
                                "store certificate secret '{certificate_key}' was not found"
                            ))
                        })?;
                let signing_key =
                    secrets_storage
                        .load(signing_key_key)
                        .await?
                        .ok_or_else(|| {
                            CertError::Validation(format!(
                                "store signing key secret '{signing_key_key}' was not found"
                            ))
                        })?;
                Ok((
                    decode_text_material(certificate, "certificate")?,
                    decode_text_material(signing_key, "signing key")?,
                ))
            }
        }
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
        let current_certificate = manager.certificate().await?;
        let current_signing_key = manager.signing_key_from_storage().await?;

        if current_certificate.as_ref().is_some_and(|current| {
            current.certificate.as_str() == certificate_data.certificate.as_str()
        }) && current_signing_key.as_deref() == Some(signing_key_pem.as_str())
        {
            info!("Store certificate material is unchanged");
            return Ok(current_certificate.unwrap_or(certificate_data));
        }

        manager.persist_certificate_data(&certificate_data).await?;
        manager.persist_signing_key(&signing_key_pem).await?;
        manager
            .cache_provisioned_chain(&certificate_data.certificate)
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
