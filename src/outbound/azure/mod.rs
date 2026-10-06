//! Azure outbound adapters: shared identity credential chain and Key Vault secret storage.

pub(crate) mod identity;
mod kv;

pub use kv::{AzureKeyVaultClient, AzureKeyVaultClientBuilder};
