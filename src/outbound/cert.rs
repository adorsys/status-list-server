#[cfg(not(feature = "acme"))]
use arc_swap::ArcSwap;
use async_trait::async_trait;
#[cfg(not(feature = "acme"))]
use base64::prelude::{BASE64_STANDARD, Engine as _};
#[cfg(not(feature = "acme"))]
use opentelemetry::{global, metrics::Gauge};
use std::sync::Arc;
#[cfg(not(feature = "acme"))]
use std::sync::atomic::{AtomicI64, Ordering};

use crate::domain::{
    models::status_list::StatusListError,
    ports::{CertificateProvider, SigningMaterial},
};
use crate::utils::crypto::SigningKey;

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
    async fn signing_material(&self) -> Result<Arc<SigningMaterial>, StatusListError> {
        self.manager
            .signing_material()
            .await
            .map_err(|e| StatusListError::Backend(Box::new(e)))
    }
}

/// Accepts PKCS#8, SEC1 or PKCS#1 keys.
#[cfg(not(feature = "acme"))]
#[derive(Clone)]
pub struct ReloadingCertificateProvider {
    active: Arc<ArcSwap<SigningMaterial>>,
    expires_at: Arc<AtomicI64>,
    expiry_gauge: Gauge<i64>,
}

#[cfg(not(feature = "acme"))]
impl ReloadingCertificateProvider {
    pub async fn from_files(cert_path: String, key_path: String) -> Result<Self, StatusListError> {
        let (material, expires_at) =
            load_and_validate_signing_material(&cert_path, &key_path).await?;
        let expires_at = Arc::new(AtomicI64::new(expires_at));
        let expiry_gauge = global::meter("status-list-server")
            .i64_gauge("cert_time_to_expiry_seconds")
            .with_description("Time remaining until the current certificate expires")
            .build();
        record_expiry(&expiry_gauge, expires_at.load(Ordering::Relaxed));
        let task_expiry = Arc::downgrade(&expires_at);
        let task_gauge = expiry_gauge.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(expires_at) = task_expiry.upgrade() else {
                    break;
                };
                record_expiry(&task_gauge, expires_at.load(Ordering::Relaxed));
            }
        });
        Ok(Self {
            active: Arc::new(ArcSwap::from_pointee(material)),
            expires_at,
            expiry_gauge,
        })
    }

    /// Atomically reload material from disk; retains previous material on failure.
    pub async fn reload_from_files(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), StatusListError> {
        let (material, expires_at) =
            load_and_validate_signing_material(cert_path, key_path).await?;
        self.active.store(Arc::new(material));
        self.expires_at.store(expires_at, Ordering::Relaxed);
        record_expiry(&self.expiry_gauge, expires_at);
        Ok(())
    }
}

#[cfg(not(feature = "acme"))]
#[async_trait]
impl CertificateProvider for ReloadingCertificateProvider {
    async fn signing_material(&self) -> Result<Arc<SigningMaterial>, StatusListError> {
        Ok(self.active.load_full())
    }
}

#[cfg(not(feature = "acme"))]
#[derive(Clone)]
pub struct InlineCertificateProvider {
    material: Arc<SigningMaterial>,
}

#[cfg(not(feature = "acme"))]
impl InlineCertificateProvider {
    pub fn new(cert_pem: String, signing_key_pem: String) -> Result<Self, StatusListError> {
        let signing_key = validate_signing_material(&cert_pem, &signing_key_pem)?;
        let certificate_chain = pem_chain_to_base64_der(&cert_pem)?;
        Ok(Self {
            material: Arc::new(SigningMaterial::new(
                Some(certificate_chain),
                Arc::new(signing_key),
            )?),
        })
    }
}

#[cfg(not(feature = "acme"))]
#[async_trait]
impl CertificateProvider for InlineCertificateProvider {
    async fn signing_material(&self) -> Result<Arc<SigningMaterial>, StatusListError> {
        Ok(self.material.clone())
    }
}

#[cfg(not(feature = "acme"))]
async fn load_and_validate_signing_material(
    cert_path: &str,
    key_path: &str,
) -> Result<(SigningMaterial, i64), StatusListError> {
    let cert_pem = tokio::fs::read_to_string(cert_path)
        .await
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;
    let signing_key_pem = tokio::fs::read_to_string(key_path)
        .await
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;
    let signing_key = validate_signing_material(&cert_pem, &signing_key_pem)?;
    let expires_at = certificate_expiry(&cert_pem)?;
    if expires_at <= time::OffsetDateTime::now_utc().unix_timestamp() {
        return Err(StatusListError::Backend(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "signing certificate has expired",
        ))));
    }
    let certificate_chain = pem_chain_to_base64_der(&cert_pem)?;
    Ok((
        SigningMaterial::new(Some(certificate_chain), Arc::new(signing_key))?,
        expires_at,
    ))
}

#[cfg(not(feature = "acme"))]
fn record_expiry(gauge: &Gauge<i64>, expires_at: i64) {
    gauge.record(
        expires_at.saturating_sub(time::OffsetDateTime::now_utc().unix_timestamp()),
        &[],
    );
}

#[cfg(not(feature = "acme"))]
fn certificate_expiry(cert_pem: &str) -> Result<i64, StatusListError> {
    let (_, block) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).map_err(|err| {
        StatusListError::Backend(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            err.to_string(),
        )))
    })?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&block.contents).map_err(|err| {
        StatusListError::Backend(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            err.to_string(),
        )))
    })?;
    Ok(certificate.validity().not_after.timestamp())
}

#[cfg(not(feature = "acme"))]
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
) -> Result<SigningKey, StatusListError> {
    let signing_key = SigningKey::from_pem(signing_key_pem)
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
    // Both sides are the raw key bits, not SPKI DER, so they compare directly.
    let cert_public_key = certificate.public_key().subject_public_key.data.as_ref();
    let key_public_key = signing_key.public_key_bytes();
    if cert_public_key != key_public_key {
        return Err(StatusListError::Backend(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "certificate public key does not match signing key",
        ))));
    }
    Ok(signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "acme"))]
    use std::path::{Path, PathBuf};
    #[cfg(not(feature = "acme"))]
    use std::sync::atomic::AtomicU64;

    #[cfg(not(feature = "acme"))]
    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    #[cfg(not(feature = "acme"))]
    struct TempDir {
        path: PathBuf,
    }

    #[cfg(not(feature = "acme"))]
    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "status-list-cert-test-{}-{}-{}",
                std::process::id(),
                time::OffsetDateTime::now_utc().unix_timestamp_nanos(),
                NEXT_TEMP_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ));
            std::fs::create_dir(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    #[cfg(not(feature = "acme"))]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn matching_cert_and_key() -> (String, String) {
        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate test cert and key");
        (
            certified_key.cert.pem(),
            certified_key.signing_key.serialize_pem(),
        )
    }

    #[test]
    fn validates_matching_ec_certificate_and_key() {
        let (cert, key) = matching_cert_and_key();
        validate_signing_material(&cert, &key).expect("fixture cert/key should validate");
    }

    #[test]
    fn validates_matching_p384_certificate_and_key() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            .expect("generate P-384 signing key");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate parameters");
        let cert = params
            .self_signed(&key)
            .expect("self-sign certificate")
            .pem();

        validate_signing_material(&cert, &key.serialize_pem())
            .expect("matching P-384 cert/key should validate");
    }

    #[test]
    fn validates_matching_ed25519_certificate_and_key() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("generate Ed25519 signing key");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate parameters");
        let cert = params
            .self_signed(&key)
            .expect("self-sign certificate")
            .pem();
        validate_signing_material(&cert, &key.serialize_pem())
            .expect("matching Ed25519 cert/key should validate");
    }

    #[test]
    fn validates_matching_rsa_certificate_and_key() {
        validate_signing_material(
            include_str!("../../test_data/gcloud_test_cert.dummy.pem"),
            include_str!("../../test_data/gcloud_test_key.dummy.pem"),
        )
        .expect("matching RSA cert/key should validate");
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
        let original_public_key = provider
            .signing_material()
            .await
            .expect("original material")
            .signing_key
            .public_key_bytes()
            .to_vec();

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
                .signing_key
                .public_key_bytes(),
            original_public_key
        );
    }

    #[cfg(not(feature = "acme"))]
    #[tokio::test]
    async fn expired_reload_keeps_last_known_good_material() {
        let dir = TempDir::new();
        let cert_path = dir.path().join("statuslist.crt");
        let key_path = dir.path().join("statuslist.key");
        let (cert, key) = matching_cert_and_key();
        tokio::fs::write(&cert_path, cert)
            .await
            .expect("write cert");
        tokio::fs::write(&key_path, &key).await.expect("write key");
        let provider = ReloadingCertificateProvider::from_files(
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
        .await
        .expect("provider");
        let original_key = provider
            .signing_material()
            .await
            .expect("material")
            .signing_key
            .public_key_bytes()
            .to_vec();
        let original_chain = provider
            .signing_material()
            .await
            .expect("material")
            .certificate_chain()
            .expect("certificate chain")
            .to_vec();

        let signing_key = rcgen::KeyPair::from_pem(&key).expect("parse key");
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate parameters");
        params.not_before = time::OffsetDateTime::UNIX_EPOCH;
        params.not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(1);
        let expired = params
            .self_signed(&signing_key)
            .expect("expired certificate")
            .pem();
        tokio::fs::write(&cert_path, expired)
            .await
            .expect("write expired cert");
        assert!(
            provider
                .reload_from_files(
                    cert_path.to_str().expect("cert path"),
                    key_path.to_str().expect("key path"),
                )
                .await
                .is_err()
        );
        assert_eq!(
            provider
                .signing_material()
                .await
                .expect("retained material")
                .signing_key
                .public_key_bytes(),
            original_key
        );
        assert_eq!(
            provider
                .signing_material()
                .await
                .expect("retained material")
                .certificate_chain()
                .expect("certificate chain"),
            original_chain
        );
    }

    #[cfg(not(feature = "acme"))]
    #[tokio::test]
    async fn expired_certificate_is_rejected_on_startup() {
        let dir = TempDir::new();
        let cert_path = dir.path().join("statuslist.crt");
        let key_path = dir.path().join("statuslist.key");
        let key = rcgen::KeyPair::generate().expect("generate key");
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate parameters");
        params.not_before = time::OffsetDateTime::UNIX_EPOCH;
        params.not_after = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(1);
        let cert = params.self_signed(&key).expect("expired certificate").pem();
        tokio::fs::write(&cert_path, cert)
            .await
            .expect("write cert");
        tokio::fs::write(&key_path, key.serialize_pem())
            .await
            .expect("write key");
        assert!(
            ReloadingCertificateProvider::from_files(
                cert_path.to_string_lossy().to_string(),
                key_path.to_string_lossy().to_string(),
            )
            .await
            .is_err()
        );
    }

    #[cfg(not(feature = "acme"))]
    #[test]
    fn filesystem_provider_updates_expiry_metric_on_reload() {
        use crate::config::{TelemetryConfig, TelemetryEnvironment};
        use crate::utils::metrics::{metrics_test_lock, setup_metrics};
        use opentelemetry_sdk::Resource;

        let _metrics_guard = metrics_test_lock();
        let registry = prometheus::Registry::new();
        let config = TelemetryConfig {
            environment: TelemetryEnvironment::Development,
            otlp_endpoint: "http://localhost:4317".to_string(),
            sampler_ratio: 1.0,
            enabled: false,
        };
        let _meter_provider = setup_metrics(
            &registry,
            &config,
            Resource::builder()
                .with_service_name("cert-file-test")
                .build(),
        )
        .expect("metrics setup");
        let gauge_value = || {
            registry
                .gather()
                .into_iter()
                .find(|family| family.name().contains("cert_time_to_expiry_seconds"))
                .and_then(|family| {
                    family
                        .get_metric()
                        .first()
                        .map(|metric| metric.get_gauge().value())
                })
                .expect("expiry gauge")
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async {
            let dir = TempDir::new();
            let cert_path = dir.path().join("statuslist.crt");
            let key_path = dir.path().join("statuslist.key");
            let key = rcgen::KeyPair::generate().expect("generate key");
            let now = time::OffsetDateTime::now_utc();
            let certificate = |days| {
                let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
                    .expect("certificate parameters");
                params.not_before = now - time::Duration::days(1);
                params.not_after = now + time::Duration::days(days);
                params.self_signed(&key).expect("sign certificate").pem()
            };
            tokio::fs::write(&cert_path, certificate(30))
                .await
                .expect("write certificate");
            tokio::fs::write(&key_path, key.serialize_pem())
                .await
                .expect("write key");
            let provider = ReloadingCertificateProvider::from_files(
                cert_path.to_string_lossy().to_string(),
                key_path.to_string_lossy().to_string(),
            )
            .await
            .expect("provider");
            let first = gauge_value();
            assert!(first > 29.0 * 86_400.0);

            tokio::fs::write(&cert_path, certificate(60))
                .await
                .expect("write renewed certificate");
            provider
                .reload_from_files(
                    cert_path.to_str().expect("cert path"),
                    key_path.to_str().expect("key path"),
                )
                .await
                .expect("reload");
            assert!(gauge_value() > first + 20.0 * 86_400.0);
        });
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
        let expected_key = SigningKey::from_pem(&second_key).expect("second signing key");
        assert_eq!(
            material.signing_key.public_key_bytes(),
            expected_key.public_key_bytes()
        );
        assert_eq!(
            material.certificate_chain(),
            Some(
                pem_chain_to_base64_der(&second_cert)
                    .expect("chain")
                    .as_slice()
            )
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
        let chain = material.certificate_chain().expect("chain");
        assert_eq!(
            chain,
            pem_chain_to_base64_der(&cert).expect("b64 der").as_slice()
        );
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
        let chain = material.certificate_chain().expect("chain");
        assert_eq!(
            chain,
            pem_chain_to_base64_der(&cert).expect("b64 der").as_slice()
        );
    }
}
