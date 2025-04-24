use crate::{
    database::queries::SeaOrmStore,
    model::{Credentials, StatusListToken},
};
use p256::ecdsa::signature::{SignerMut, Verifier};
use p256::ecdsa::Signature;
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use super::errors::Error;
use super::keygen::Keypair;

#[derive(Clone)]
pub struct AppState {
    pub credential_repository: Arc<SeaOrmStore<Credentials>>,
    pub status_list_token_repository: Arc<SeaOrmStore<StatusListToken>>,
    pub server_key: Arc<Keypair>,
}

fn validate_keypair(keypair: &mut Keypair) -> Result<(), Error> {
    // Test signing and verifying to ensure the keypair is valid
    let test_data = b"test data";
    let signature: Signature = keypair.signing_key_mut().sign(test_data);
    if !keypair
        .verifying_key()
        .verify(test_data, &signature)
        .is_ok()
    {
        return Err(Error::Generic("Keypair validation failed".to_string()));
    }
    Ok(())
}

fn load_or_generate_keypair(pem_path: &Path) -> Result<Keypair, Error> {
    tracing::debug!("Loading keypair from {}", pem_path.display());

    if pem_path.exists() {
        tracing::info!("Loading existing keypair from {}", pem_path.display());
        let pem_content = fs::read_to_string(pem_path).map_err(|e| {
            tracing::error!("Failed to read key file: {}", e);
            Error::ReadCertificate(pem_path.to_path_buf())
        })?;

        if pem_content
            .trim()
            .starts_with("-----BEGIN PRIVATE KEY-----")
        {
            let normalized_pem = pem_content.trim();

            match Keypair::from_pkcs8_pem(normalized_pem) {
                Ok(mut keypair) => {
                    if let Err(e) = validate_keypair(&mut keypair) {
                        tracing::warn!("Loaded keypair validation failed: {}", e);
                    } else {
                        tracing::info!("Successfully loaded and validated keypair");
                        return Ok(keypair);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to parse key file: {}", e);
                }
            }
        } else {
            tracing::warn!("Key file does not contain a valid PEM key");
        }
    } else {
        tracing::info!("Key file does not exist at {}", pem_path.display());
    }

    tracing::info!("Generating new keypair");
    let mut keypair = Keypair::generate().map_err(|e| {
        tracing::error!("Failed to generate new keypair: {}", e);
        e
    })?;

    validate_keypair(&mut keypair).map_err(|e| {
        tracing::error!("Failed to validate new keypair: {}", e);
        e
    })?;

    tracing::info!("Saving new keypair to {}", pem_path.display());

    if let Some(parent) = pem_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            tracing::error!("Failed to create key directory: {}", e);
            Error::Generic("Failed to create key directory".to_string())
        })?;
    }

    let pem_content = keypair.to_pkcs8_pem().map_err(|e| {
        tracing::error!("Failed to convert key to PEM: {}", e);
        e
    })?;

    fs::write(pem_path, pem_content.as_bytes()).map_err(|e| {
        tracing::error!("Failed to write key file: {}", e);
        Error::Generic("Failed to write key file".to_string())
    })?;

    tracing::info!("Successfully saved new keypair");
    Ok(keypair)
}

pub async fn setup() -> AppState {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL env not set");
    let db: DatabaseConnection = Database::connect(&url)
        .await
        .expect("Failed to connect to database");

    crate::database::Migrator::up(&db, None)
        .await
        .expect("Failed to apply migrations");

    // Load or generate server key
    let server_key = load_or_generate_keypair(Path::new("server_key.pem"))
        .expect("Failed to load or generate server key");

    let db = Arc::new(db);
    AppState {
        credential_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        status_list_token_repository: Arc::new(SeaOrmStore::new(Arc::clone(&db))),
        server_key: Arc::new(server_key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_load_or_generate_keypair_with_env() {
        let temp_path_str = "./src/test_resources/test_key_roundtrip.pem".to_string();
        let temp_path = Path::new(&temp_path_str);

        let test_resources_dir = Path::new("./src/test_resources");
        if !test_resources_dir.exists() {
            fs::create_dir_all(test_resources_dir)
                .expect("Failed to create test_resources directory");
        }

        if temp_path.exists() {
            fs::remove_file(temp_path).expect("Failed to remove existing test file");
        }

        // First call: Generate and save a keypair
        let mut keypair1 =
            load_or_generate_keypair(temp_path).expect("Failed to load or generate first keypair");
        assert!(validate_keypair(&mut keypair1).is_ok());
        assert!(temp_path.exists(), "File should exist after first call");

        // Second call: Load the saved keypair
        let mut keypair2 =
            load_or_generate_keypair(temp_path).expect("Failed to load or generate second keypair");
        assert!(validate_keypair(&mut keypair2).is_ok());

        // Verify both keypairs are identical
        let pem1 = keypair1
            .to_pkcs8_pem()
            .expect("Failed to get PEM from first keypair");
        let pem2 = keypair2
            .to_pkcs8_pem()
            .expect("Failed to get PEM from second keypair");
        assert_eq!(pem1, pem2, "Keypairs should match when loaded from file");
    }

    #[test]
    fn test_load_or_generate_keypair_invalid_file() {
        let temp_path_str = "./src/test_resources/test_key_invalid_content.pem".to_string();
        let temp_path = Path::new(&temp_path_str);

        let test_resources_dir = Path::new("./src/test_resources");
        if !test_resources_dir.exists() {
            fs::create_dir_all(test_resources_dir)
                .expect("Failed to create test_resources directory");
        }

        if temp_path.exists() {
            fs::remove_file(temp_path).expect("Failed to remove existing test file");
        }

        // Write invalid content
        fs::write(temp_path, "invalid key content").expect("Failed to write invalid content");

        // Call the function: Should overwrite with a valid keypair
        let mut keypair =
            load_or_generate_keypair(temp_path).expect("Failed to load or generate keypair");
        assert!(validate_keypair(&mut keypair).is_ok());

        // Verify the file was overwritten
        let saved_content = fs::read_to_string(temp_path).expect("Failed to read saved key");
        assert!(!saved_content.is_empty(), "Saved key should not be empty");
        assert!(
            saved_content
                .trim()
                .starts_with("-----BEGIN PRIVATE KEY-----"),
            "Saved content should be a valid PEM key"
        );
        assert_ne!(
            saved_content.trim(),
            "invalid key content",
            "Saved key should replace invalid content"
        );
    }
}
