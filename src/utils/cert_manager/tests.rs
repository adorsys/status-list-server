use crate::cert_manager::storage::{Storage, StorageError};

use super::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Once};
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
}

impl MockStorage {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
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
fn test_renewal_strategy_days_before_expiry() {
    init_crypto();

    let strategy = RenewalStrategy {
        strategy_type: RenewalType::DaysBeforeExpiry,
        threshold_days: Some(30),
        threshold_percent: None,
        interval_days: None,
    };

    let manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_renewal_strategy(strategy);

    let now = 1749043205;

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

    let strategy = RenewalStrategy {
        strategy_type: RenewalType::PercentageOfLifetime,
        threshold_days: None,
        threshold_percent: Some(0.8),
        interval_days: None,
    };

    let manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_renewal_strategy(strategy);

    let now = 1749043205;
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

    let strategy = RenewalStrategy {
        strategy_type: RenewalType::FixedInterval,
        threshold_days: None,
        threshold_percent: None,
        interval_days: Some(60),
    };

    let manager = CertManager::new(
        vec!["example.com"],
        "test@example.com",
        None::<String>,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap()
    .with_renewal_strategy(strategy);

    let now = 1749043205;

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
    let serialized = include_str!("../../test_resources/cert_data.json");
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
        .load("keys/example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(key, stored_key);
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
    let result = ts_to_local(timestamp);
    assert_eq!("2025-06-04 14:57", result);
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
    let serialized = include_str!("../../test_resources/cert_data.json");
    cert_storage
        .store("certs/example.com/cert_data.json", serialized)
        .await
        .unwrap();

    let parts = cert_manager.cert_chain_parts().await.unwrap().unwrap();
    assert_eq!(parts.len(), 2);
}
