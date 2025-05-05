use crate::{
    database::queries::SeaOrmStore,
    model::{Credentials, StatusListToken},
};
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

fn load_or_generate_keypair() -> Result<Keypair, Error> {
    if let Ok(pem_path) = std::env::var("SERVER_KEY_PATH") {
        let pem_path = Path::new(&pem_path);
        if pem_path.try_exists().unwrap_or(false) {
            match fs::read_to_string(pem_path) {
                Ok(pem_content) => {
                    let trimmed_pem = pem_content.trim();
                    match Keypair::from_pkcs8_pem(trimmed_pem) {
                        Ok(keypair) => {
                            tracing::info!("Loaded server key from {}", pem_path.display());
                            return Ok(keypair);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to parse keypair from {}: {}; generating a new one",
                                pem_path.display(),
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to read key file {}: {}; generating a new one",
                        pem_path.display(),
                        e
                    );
                }
            }
        } else {
            tracing::info!(
                "Key file does not exist at {}; generating a new one",
                pem_path.display()
            );
        }

        // Generate and save a new keypair
        let keypair = Keypair::generate().map_err(|e| {
            tracing::error!("Failed to generate new keypair: {}", e);
            e
        })?;

        if let Some(parent) = pem_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                tracing::error!("Failed to create key directory: {}", e);
                Error::Generic("Failed to create key directory".to_string())
            })?;
        }

        // Save the PEM content with consistent trimming
        let pem_content = keypair.to_pkcs8_pem().map_err(|e| {
            tracing::error!("Failed to serialize new keypair to PEM: {}", e);
            e
        })?;
        fs::write(pem_path, pem_content).map_err(|e| {
            tracing::error!("Failed to save new keypair: {}", e);
            Error::WriteCertificate(pem_path.to_path_buf())
        })?;

        tracing::info!(
            "Generated and saved new server key to {}",
            pem_path.display()
        );
        Ok(keypair)
    } else {
        // No SERVER_KEY_PATH, just generate
        tracing::info!("Generating new server keypair (no path specified)");
        Keypair::generate()
    }
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
    let server_key = load_or_generate_keypair().expect("Failed to load or generate server key");

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
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_or_generate_keypair_no_env() {
        // Clear any existing SERVER_KEY_PATH
        env::remove_var("SERVER_KEY_PATH");

        let keypair = load_or_generate_keypair().expect("Failed to load or generate keypair");
        // Verify the keypair can be serialized to PEM
        assert!(
            keypair.to_pkcs8_pem().is_ok(),
            "Keypair should serialize to PEM successfully"
        );
    }

    #[test]
    fn test_load_or_generate_keypair_with_env() {
        // Create a temporary file that will be automatically deleted when the test ends
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_path_buf();
        let temp_path_str = temp_path
            .to_str()
            .expect("Failed to get temp path as string");

        println!("Temporary file created at: {}", temp_path.display());

        // Ensure we start with a clean state
        env::remove_var("SERVER_KEY_PATH");
        env::set_var("SERVER_KEY_PATH", temp_path_str);

        // Generate a keypair and save it
        let keypair1 = Keypair::generate().expect("Failed to generate keypair");
        let pem1 = keypair1
            .to_pkcs8_pem()
            .expect("Failed to serialize keypair to PEM");
        fs::write(&temp_path, &pem1).expect("Failed to write keypair to file");

        // Test the load_or_generate_keypair function
        let keypair2 =
            load_or_generate_keypair().expect("Failed to load or generate second keypair");
        let pem2 = keypair2
            .to_pkcs8_pem()
            .expect("Failed to serialize second keypair to PEM");

        // Compare the PEMs after trimming
        assert_eq!(
            pem1.trim(),
            pem2.trim(),
            "Loaded keypair should match the original keypair"
        );

        // Clean up
        env::remove_var("SERVER_KEY_PATH");
    }

    #[test]
    fn test_load_or_generate_keypair_invalid_file() {
        // Create a temporary file with invalid content
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_str().expect("Failed to get temp path");
        let invalid_content = "invalid key content";
        std::fs::write(temp_path, invalid_content).expect("Failed to write invalid content");

        // Set the environment variable
        env::set_var("SERVER_KEY_PATH", temp_path);

        // Should generate a new key despite invalid file
        let _keypair = load_or_generate_keypair().expect("Failed to load or generate keypair");

        // Verify the key was saved and is different from the invalid content
        let saved_content = std::fs::read_to_string(temp_path).expect("Failed to read saved key");
        assert!(!saved_content.is_empty(), "Saved key should not be empty");
        assert!(
            saved_content.starts_with("-----BEGIN PRIVATE KEY-----"),
            "Saved content should be a valid PEM key"
        );
        assert_ne!(
            saved_content, invalid_content,
            "Saved key should be different from invalid content"
        );

        // Clean up
        env::remove_var("SERVER_KEY_PATH");
    }
}
