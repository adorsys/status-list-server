//! Adapter that reads signing key and certificate chain from files on disk,
//! implementing the application-facing certificate port.
//!
//! Files are re-read on every call so that certificate rotation (e.g. by
//! Kubernetes cert-manager updating a mounted Secret) is picked up without
//! a pod restart.

use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use std::path::PathBuf;
use x509_parser::pem::Pem as X509Pem;

use crate::domain::{models::status_list::StatusListError, ports::CertificateProvider};

/// Certificate provider that reads signing key and certificate chain from
/// PEM-encoded files on disk.
///
/// Designed for environments where an external system (e.g. Kubernetes
/// cert-manager) manages certificate lifecycle and mounts the key material
/// as files. Because files are re-read on every call, rotation is picked up
/// without a restart.
#[derive(Clone, Debug)]
pub struct FileCertificateProvider {
    key_file: PathBuf,
    cert_file: PathBuf,
}

impl FileCertificateProvider {
    /// Create a new provider that reads from the given file paths.
    pub fn new(key_file: impl Into<PathBuf>, cert_file: impl Into<PathBuf>) -> Self {
        Self {
            key_file: key_file.into(),
            cert_file: cert_file.into(),
        }
    }
}

#[async_trait]
impl CertificateProvider for FileCertificateProvider {
    async fn certificate_chain(&self) -> Result<Option<Vec<String>>, StatusListError> {
        let cert_pem_bytes = tokio::fs::read(&self.cert_file).await.map_err(|e| {
            StatusListError::Backend(Box::new(std::io::Error::new(
                e.kind(),
                format!(
                    "failed to read certificate file '{}': {e}",
                    self.cert_file.display()
                ),
            )))
        })?;

        let certs: Vec<String> = X509Pem::iter_from_buffer(&cert_pem_bytes)
            .map(|pem| {
                pem.map(|p| BASE64_STANDARD.encode(&p.contents))
                    .map_err(|e| {
                        StatusListError::Backend(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("failed to parse certificate PEM: {e}"),
                        )))
                    })
            })
            .collect::<Result<_, _>>()?;

        if certs.is_empty() {
            return Err(StatusListError::Backend(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "certificate file '{}' contains no certificates",
                    self.cert_file.display()
                ),
            ))));
        }

        Ok(Some(certs))
    }

    async fn signing_key_pem(&self) -> Result<String, StatusListError> {
        tokio::fs::read_to_string(&self.key_file)
            .await
            .map_err(|e| {
                StatusListError::Backend(Box::new(std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to read signing key file '{}': {e}",
                        self.key_file.display()
                    ),
                )))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_test_files(tmp: &TempDir) -> (PathBuf, PathBuf) {
        let key_path = tmp.path().join("tls.key");
        let cert_path = tmp.path().join("tls.crt");

        let key_pem = include_str!("../../test_data/ec-private.pem");
        std::fs::write(&key_path, key_pem).unwrap();

        let cert_data: serde_json::Value =
            serde_json::from_str(include_str!("../../test_data/cert_data.json")).unwrap();
        let cert_pem = cert_data["certificate"].as_str().unwrap();
        std::fs::write(&cert_path, cert_pem).unwrap();

        (key_path, cert_path)
    }

    #[tokio::test]
    async fn reads_signing_key_from_file() {
        let tmp = TempDir::new().unwrap();
        let (key_path, cert_path) = write_test_files(&tmp);

        let provider = FileCertificateProvider::new(&key_path, &cert_path);
        let loaded_key = provider.signing_key_pem().await.unwrap();

        let expected = include_str!("../../test_data/ec-private.pem");
        assert_eq!(loaded_key, expected);
    }

    #[tokio::test]
    async fn reads_certificate_chain_from_file() {
        let tmp = TempDir::new().unwrap();
        let (key_path, cert_path) = write_test_files(&tmp);

        let provider = FileCertificateProvider::new(&key_path, &cert_path);
        let chain = provider.certificate_chain().await.unwrap();

        assert!(chain.is_some(), "certificate chain should be present");
        let certs = chain.unwrap();
        assert!(
            !certs.is_empty(),
            "certificate chain should contain at least one certificate"
        );
    }

    #[tokio::test]
    async fn returns_error_for_missing_key_file() {
        let tmp = TempDir::new().unwrap();
        let provider = FileCertificateProvider::new(
            tmp.path().join("missing.key"),
            tmp.path().join("tls.crt"),
        );

        assert!(provider.signing_key_pem().await.is_err());
    }

    #[tokio::test]
    async fn returns_error_for_missing_cert_file() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("tls.key");
        std::fs::write(&key_path, "unused").unwrap();

        let provider = FileCertificateProvider::new(&key_path, tmp.path().join("missing.crt"));

        assert!(provider.certificate_chain().await.is_err());
    }

    #[tokio::test]
    async fn returns_error_for_empty_cert_file() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("tls.key");
        let cert_path = tmp.path().join("tls.crt");
        std::fs::write(&key_path, "unused").unwrap();
        std::fs::File::create(&cert_path).unwrap();

        let provider = FileCertificateProvider::new(&key_path, &cert_path);

        assert!(provider.certificate_chain().await.is_err());
    }

    #[tokio::test]
    async fn picks_up_rotated_files_without_restart() {
        let tmp = TempDir::new().unwrap();
        let (key_path, cert_path) = write_test_files(&tmp);

        let provider = FileCertificateProvider::new(&key_path, &cert_path);

        let v1 = provider.signing_key_pem().await.unwrap();
        std::fs::write(
            &key_path,
            "-----BEGIN PRIVATE KEY-----\nrotated\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let v2 = provider.signing_key_pem().await.unwrap();

        assert_ne!(v1, v2, "provider should pick up the rotated file");
    }
}
