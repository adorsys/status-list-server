use crate::{
    cert_manager::storage::{Storage, StorageError},
    utils::keygen::Keypair,
};

use super::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{
    Arc, Once,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Mutex;

fn days_to_secs(days: u32) -> i64 {
    (days as i64) * 24 * 60 * 60
}

static INIT_CRYPTO: Once = Once::new();

fn init_crypto() {
    INIT_CRYPTO.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install crypto provider");
    });
}

#[derive(Clone)]
struct MockStorage {
    data: Arc<Mutex<HashMap<String, String>>>,
    load_count: Arc<AtomicUsize>,
}

impl MockStorage {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
            load_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn load_count(&self) -> usize {
        self.load_count.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Storage for MockStorage {
    async fn store(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.data
            .lock()
            .await
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.load_count.fetch_add(1, Ordering::Relaxed);
        Ok(self.data.lock().await.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.data.lock().await.remove(key);
        Ok(())
    }
}

#[test]
fn test_cert_manager_builder() {
    init_crypto();

    let cert_storage = MockStorage::new();
    let secrets_storage = MockStorage::new();

    let manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        Some("Test Org"),
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_cert_storage(cert_storage)
    .with_secrets_storage(secrets_storage)
    .with_eku(&[1, 2, 3, 4]);

    assert!(manager.cert_storage.is_some());
    assert!(manager.secrets_storage.is_some());
    assert!(manager.challenge_handler.is_none());
    assert_eq!(manager.eku, Some(vec![1, 2, 3, 4]));
}

#[test]
fn test_acme_builder_requires_challenge_handler() {
    init_crypto();

    let result = CertManager::builder()
        .domains(["example.com"])
        .email("test@example.com")
        .acme_directory_url("https://acme.example.com/directory")
        .cert_storage(MockStorage::new())
        .secrets_storage(MockStorage::new())
        .acme_strategy()
        .build();

    let err = match result {
        Ok(_) => panic!("ACME builder must require a challenge handler"),
        Err(err) => err,
    };

    assert!(matches!(err, CertError::Validation(message) if message.contains("challenge handler")));
}

#[test]
fn test_store_builder_does_not_require_acme_components() {
    init_crypto();

    let result = CertManager::builder()
        .domains(["example.com"])
        .cert_storage(MockStorage::new())
        .secrets_storage(MockStorage::new())
        .store_strategy(StoreProvisioningStrategy::filesystem(
            "/tmp/example-cert.pem",
            "/tmp/example-key.pem",
        ))
        .build();

    assert!(result.is_ok());
}

#[test]
fn test_renewal_strategy_days_before_expiry() {
    init_crypto();

    let strategy = RenewalStrategy::DaysBeforeExpiry(Some(30));

    let manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_renewal_strategy(strategy);

    let now = now_unix_timestamp();

    // Certificate expires in 20 days - should renew (threshold is 30 days)
    let cert_data_should_renew = CertificateData {
        certificate: "mock_cert".to_string(),
        valid_from: now - days_to_secs(60),
        expires_at: now + days_to_secs(20),
        updated_at: now,
    };
    assert!(manager.should_renew_cert(&cert_data_should_renew));

    // Certificate expires in 40 days - should not renew
    let cert_data_should_not_renew = CertificateData {
        certificate: "mock_cert".to_string(),
        valid_from: now - days_to_secs(50),
        expires_at: now + days_to_secs(40),
        updated_at: now,
    };
    assert!(!manager.should_renew_cert(&cert_data_should_not_renew));
}

#[tokio::test]
async fn test_renewal_strategy_percentage_of_lifetime() {
    init_crypto();

    let strategy = RenewalStrategy::PercentageOfLifetime(Some(0.8));

    let manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_renewal_strategy(strategy);

    let now = now_unix_timestamp();
    let cert_lifetime = days_to_secs(90);

    // Certificate is at 85% of its lifetime - should renew (threshold is 80%)
    let elapsed_time = (cert_lifetime as f32 * 0.85) as i64;
    let cert_data_should_renew = CertificateData {
        certificate: "mock_cert".to_string(),
        valid_from: now - elapsed_time,
        expires_at: now - elapsed_time + cert_lifetime,
        updated_at: now,
    };
    assert!(manager.should_renew_cert(&cert_data_should_renew));

    // Certificate is at 70% of its lifetime - should not renew
    let elapsed_time = (cert_lifetime as f32 * 0.70) as i64;
    let cert_data_should_not_renew = CertificateData {
        certificate: "mock_cert".to_string(),
        valid_from: now - elapsed_time,
        expires_at: now - elapsed_time + cert_lifetime,
        updated_at: now,
    };
    assert!(!manager.should_renew_cert(&cert_data_should_not_renew));
}

#[tokio::test]
async fn test_renewal_strategy_fixed_interval() {
    init_crypto();

    let strategy = RenewalStrategy::FixedInterval(Some(60));

    let manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_renewal_strategy(strategy);

    let now = now_unix_timestamp();

    // Certificate issued 70 days ago - should renew (interval is 60 days)
    let cert_data_should_renew = CertificateData {
        certificate: "mock_cert".to_string(),
        valid_from: now - days_to_secs(70),
        expires_at: now + days_to_secs(40),
        updated_at: now,
    };
    assert!(manager.should_renew_cert(&cert_data_should_renew));

    // Certificate issued 50 days ago - should not renew
    let cert_data_should_not_renew = CertificateData {
        certificate: "mock_cert".to_string(),
        valid_from: now - days_to_secs(50),
        expires_at: now + days_to_secs(40),
        updated_at: now,
    };
    assert!(!manager.should_renew_cert(&cert_data_should_not_renew));
}

#[tokio::test]
async fn test_certificate_returns_none_if_not_found() {
    init_crypto();

    let cert_storage = MockStorage::new();
    let cert_manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_cert_storage(cert_storage);

    let cert = cert_manager.certificate().await.unwrap();
    assert!(cert.is_none());
}

#[tokio::test]
async fn test_certificate_storage_and_retrieval() {
    init_crypto();

    let cert_storage = MockStorage::new();

    let manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_cert_storage(cert_storage.clone());

    let cert = manager.certificate().await.unwrap();
    assert!(cert.is_none());

    // Store the certificate manually
    let serialized = include_str!("../../../test_data/cert_data.json");
    let cert_data: CertificateData = serde_json::from_str(serialized).unwrap();

    let cert_key = manager.cert_key();
    cert_storage.store(&cert_key, serialized).await.unwrap();

    let retrieved_cert = manager.certificate().await.unwrap();
    assert!(retrieved_cert.is_some());
    let retrieved = retrieved_cert.unwrap();
    assert_eq!(retrieved.certificate, cert_data.certificate);
    assert_eq!(retrieved.valid_from, cert_data.valid_from);
    assert_eq!(retrieved.expires_at, cert_data.expires_at);
}

#[tokio::test]
async fn test_signing_key_generation_and_storage() {
    init_crypto();

    let secrets_storage = MockStorage::new();

    let manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_secrets_storage(secrets_storage.clone());

    // First call should generate and store a new key
    let generated_key = manager.signing_key_pem().await.unwrap();
    assert!(generated_key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(generated_key.ends_with("-----END PRIVATE KEY-----\n"));

    // Second call should return the same key
    let key = manager.signing_key_pem().await.unwrap();
    assert_eq!(key, generated_key);

    // The key should have been stored
    let stored_key = secrets_storage
        .load("keys-example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(key, stored_key);
}

#[tokio::test]
async fn test_store_filesystem_strategy_persists_material() {
    init_crypto();

    let source_cert_data: CertificateData =
        serde_json::from_str(include_str!("../../../test_data/cert_data.json")).unwrap();
    let cert_pem = source_cert_data.certificate.as_str();
    let key_pem = include_str!("../../../test_data/ec-private.pem");
    let temp_dir = std::env::temp_dir().join(format!(
        "status-list-server-cert-store-{}",
        uuid::Uuid::new_v4()
    ));
    let cert_path = temp_dir.join("tls.crt");
    let key_path = temp_dir.join("tls.key");

    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    tokio::fs::write(&cert_path, cert_pem).await.unwrap();
    tokio::fs::write(&key_path, key_pem).await.unwrap();

    let manager = CertManager::builder()
        .domains(["example.com"])
        .cert_storage(MockStorage::new())
        .secrets_storage(MockStorage::new())
        .store_strategy(StoreProvisioningStrategy::filesystem(cert_path, key_path))
        .build()
        .unwrap();

    let cert_data = manager.request_certificate().await.unwrap();

    assert_eq!(cert_data.certificate, cert_pem);
    assert_eq!(manager.signing_key_pem().await.unwrap(), key_pem);
    assert_eq!(
        manager.certificate().await.unwrap().unwrap().certificate,
        cert_pem
    );
}

#[tokio::test]
async fn test_store_filesystem_strategy_accepts_der_material() {
    init_crypto();

    let source_cert_data: CertificateData =
        serde_json::from_str(include_str!("../../../test_data/cert_data.json")).unwrap();
    let cert_pem = source_cert_data.certificate.as_str();
    let (_, cert_der) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).unwrap();
    let key_pem = include_str!("../../../test_data/ec-private.pem");
    let key_der = Keypair::from_pkcs8_pem(key_pem)
        .unwrap()
        .to_pkcs8_der_bytes()
        .unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "status-list-server-cert-store-der-{}",
        uuid::Uuid::new_v4()
    ));
    let cert_path = temp_dir.join("tls.der");
    let key_path = temp_dir.join("tls.pk8");

    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    tokio::fs::write(&cert_path, cert_der.contents)
        .await
        .unwrap();
    tokio::fs::write(&key_path, key_der).await.unwrap();

    let manager = CertManager::builder()
        .domains(["example.com"])
        .cert_storage(MockStorage::new())
        .secrets_storage(MockStorage::new())
        .store_strategy(StoreProvisioningStrategy::filesystem(cert_path, key_path))
        .build()
        .unwrap();

    let cert_data = manager.request_certificate().await.unwrap();

    assert!(
        cert_data
            .certificate
            .contains("-----BEGIN CERTIFICATE-----")
    );
    assert_eq!(manager.signing_key_pem().await.unwrap(), key_pem);
    assert_eq!(manager.cert_chain_parts().await.unwrap().unwrap().len(), 1);
}

#[tokio::test]
async fn test_store_secrets_strategy_persists_material() {
    init_crypto();

    let cert_storage = MockStorage::new();
    let secrets_storage = MockStorage::new();
    let source_cert_data: CertificateData =
        serde_json::from_str(include_str!("../../../test_data/cert_data.json")).unwrap();
    let cert_pem = source_cert_data.certificate.as_str();
    let key_pem = include_str!("../../../test_data/ec-private.pem");

    secrets_storage
        .store("source-cert", cert_pem)
        .await
        .unwrap();
    secrets_storage.store("source-key", key_pem).await.unwrap();

    let manager = CertManager::builder()
        .domains(["example.com"])
        .cert_storage(cert_storage)
        .secrets_storage(secrets_storage)
        .store_strategy(StoreProvisioningStrategy::secrets_storage(
            "source-cert",
            "source-key",
        ))
        .build()
        .unwrap();

    let cert_data = manager.request_certificate().await.unwrap();

    assert_eq!(cert_data.certificate, cert_pem);
    assert_eq!(manager.signing_key_pem().await.unwrap(), key_pem);
}

#[tokio::test]
async fn test_store_secrets_strategy_accepts_base64_der_material() {
    use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD, Engine as _};

    init_crypto();

    let cert_storage = MockStorage::new();
    let secrets_storage = MockStorage::new();
    let source_cert_data: CertificateData =
        serde_json::from_str(include_str!("../../../test_data/cert_data.json")).unwrap();
    let cert_pem = source_cert_data.certificate.as_str();
    let (_, cert_der) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).unwrap();
    let key_pem = include_str!("../../../test_data/ec-private.pem");
    let key_der = Keypair::from_pkcs8_pem(key_pem)
        .unwrap()
        .to_pkcs8_der_bytes()
        .unwrap();

    secrets_storage
        .store("source-cert", &BASE64_STANDARD.encode(cert_der.contents))
        .await
        .unwrap();
    secrets_storage
        .store("source-key", &BASE64_URL_SAFE_NO_PAD.encode(key_der))
        .await
        .unwrap();

    let manager = CertManager::builder()
        .domains(["example.com"])
        .cert_storage(cert_storage)
        .secrets_storage(secrets_storage)
        .store_strategy(StoreProvisioningStrategy::secrets_storage(
            "source-cert",
            "source-key",
        ))
        .build()
        .unwrap();

    let cert_data = manager.request_certificate().await.unwrap();

    assert!(
        cert_data
            .certificate
            .contains("-----BEGIN CERTIFICATE-----")
    );
    assert_eq!(manager.signing_key_pem().await.unwrap(), key_pem);
}

#[test]
fn test_tld_plus_one_function() {
    init_crypto();

    let domains = vec!["www.example.com".to_string()];
    let result = tld_plus_one(&domains);
    assert_eq!(result, "example.com");

    let domains = vec!["sub.domain.example.co.uk".to_string()];
    let result = tld_plus_one(&domains);
    assert_eq!(result, "example.co.uk");

    let domains = ["sub.example.com".to_string(), "acme.test.com".to_string()];
    let result = tld_plus_one(&domains);
    assert_eq!(result, "example.com");
}

#[test]
fn test_ts_to_local_helper() {
    init_crypto();

    let timestamp = 1749045448;
    let result = ts_to_utc(timestamp);
    assert_eq!("2025-06-04 13:57 UTC", result);
}

#[tokio::test]
async fn test_cert_chain_parts() {
    init_crypto();

    let cert_storage = MockStorage::new();
    let cert_manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_cert_storage(cert_storage.clone());

    // there are 2 parts in the certificate chain
    let serialized = include_str!("../../../test_data/cert_data.json");
    cert_storage
        .store("certs-example.com-cert_data.json", serialized)
        .await
        .unwrap();

    let parts = cert_manager.cert_chain_parts().await.unwrap().unwrap();
    assert_eq!(parts.len(), 2);
}

#[tokio::test]
async fn test_cert_chain_parts_are_cached_after_first_load() {
    init_crypto();

    let cert_storage = MockStorage::new();
    let cert_manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_cert_storage(cert_storage.clone());

    let serialized = include_str!("../../../test_data/cert_data.json");
    cert_storage
        .store("certs-example.com-cert_data.json", serialized)
        .await
        .unwrap();

    let first = cert_manager.cert_chain_parts().await.unwrap().unwrap();
    let second = cert_manager.cert_chain_parts().await.unwrap().unwrap();

    assert_eq!(first.len(), 2);
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(cert_storage.load_count(), 1);
}

#[tokio::test]
async fn test_cache_provisioned_chain_replaces_cached_entry() {
    init_crypto();

    let cert_storage = MockStorage::new();
    let cert_manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_cert_storage(cert_storage.clone());

    let cert_key = cert_manager.cert_key();
    let serialized = include_str!("../../../test_data/cert_data.json");
    cert_storage.store(&cert_key, serialized).await.unwrap();

    // First read populates the cache from storage.
    let first = cert_manager.cert_chain_parts().await.unwrap().unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(cert_storage.load_count(), 1);

    // Simulate re-provisioning with a different certificate by invoking the
    // same hook `request_certificate` calls after storing a new cert.
    let replacement_pem = include_str!("../../../test_data/test_cert2.pem");
    cert_manager
        .cache_provisioned_chain(replacement_pem)
        .await
        .unwrap();

    // The next read must return the replaced chain — no storage load needed.
    let reloaded = cert_manager.cert_chain_parts().await.unwrap().unwrap();
    assert_eq!(reloaded.len(), 1);
    assert!(!Arc::ptr_eq(&first, &reloaded));
    assert_eq!(cert_storage.load_count(), 1);
}

#[tokio::test]
async fn test_cert_chain_cache_invalidation_reloads_chain() {
    init_crypto();

    let cert_storage = MockStorage::new();
    let cert_manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_cert_storage(cert_storage.clone());

    let cert_key = cert_manager.cert_key();
    let serialized = include_str!("../../../test_data/cert_data.json");
    cert_storage.store(&cert_key, serialized).await.unwrap();

    let first = cert_manager.cert_chain_parts().await.unwrap().unwrap();
    assert_eq!(first.len(), 2);

    let replacement = CertificateData {
        certificate: include_str!("../../../test_data/test_cert2.pem").to_string(),
        valid_from: 1,
        expires_at: 2,
        updated_at: 3,
    };
    let serialized_replacement = serde_json::to_string(&replacement).unwrap();
    cert_storage
        .store(&cert_key, &serialized_replacement)
        .await
        .unwrap();

    let stale_cached = cert_manager.cert_chain_parts().await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&first, &stale_cached));
    assert_eq!(cert_storage.load_count(), 1);

    cert_manager.cert_chain_cache.invalidate(&cert_key).await;
    let reloaded = cert_manager.cert_chain_parts().await.unwrap().unwrap();

    assert_eq!(reloaded.len(), 1);
    assert!(!Arc::ptr_eq(&first, &reloaded));
    assert_eq!(cert_storage.load_count(), 2);
}

// Tests for renewal metrics

#[test]
fn test_describe_renewal_metrics_is_safe_before_recorder_installed() {
    // This should not panic
    describe_renewal_metrics();
}

#[test]
fn test_init_renewal_counters_registers_zero_values() {
    init_renewal_counters();
}

#[test]
fn test_update_time_to_expiry_sets_gauge() {
    init_crypto();

    let cert_manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap();

    let now = now_unix_timestamp();
    let cert_data = CertificateData {
        certificate: "mock_cert".to_string(),
        valid_from: now - days_to_secs(30),
        expires_at: now + days_to_secs(60),
        updated_at: now,
    };

    cert_manager.update_time_to_expiry(&cert_data);
}

#[test]
fn test_record_successful_renewal_updates_counters_and_gauge() {
    init_crypto();

    let cert_manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap();

    cert_manager.init_renewal_counters();
    cert_manager.record_successful_renewal();
}

#[test]
fn test_record_failed_renewal_increments_failure_counter() {
    init_crypto();

    let cert_manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap();

    cert_manager.init_renewal_counters();
    cert_manager.record_failed_renewal();
    cert_manager.record_failed_renewal();
}

#[test]
fn test_renewal_attempts_metric_via_manager() {
    init_crypto();

    let cert_storage = MockStorage::new();
    let secrets_storage = MockStorage::new();

    let cert_manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_cert_storage(cert_storage)
    .with_secrets_storage(secrets_storage);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        cert_manager.init_renewal_counters();
        let _ = cert_manager.renew_cert_if_needed().await;
    });
}
