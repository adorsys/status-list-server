//! Shared Azure identity helpers for Azure-backed adapters.

use std::sync::Arc;

use async_trait::async_trait;
use azure_core::credentials::{
    AccessToken, Secret as AzureSecret, TokenCredential, TokenRequestOptions,
};
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    WorkloadIdentityCredential,
};
use tracing::{debug, warn};

/// Chained token credential that evaluates supported ambient Azure identity
/// sources in order: Environment client secret -> Workload Identity ->
/// Managed Identity -> Developer Tools.
#[derive(Debug)]
pub(crate) struct DefaultAzureCredential {
    sources: Vec<(&'static str, Arc<dyn TokenCredential>)>,
}

impl DefaultAzureCredential {
    /// Create a new [`DefaultAzureCredential`] chain with available credential sources.
    pub(crate) fn new() -> azure_core::Result<Arc<Self>> {
        let mut sources: Vec<(&'static str, Arc<dyn TokenCredential>)> = Vec::new();

        let tenant_id = std::env::var("AZURE_TENANT_ID");
        let client_id = std::env::var("AZURE_CLIENT_ID");
        let client_secret = std::env::var("AZURE_CLIENT_SECRET");
        if let (Ok(tenant_id), Ok(client_id), Ok(client_secret)) =
            (tenant_id, client_id, client_secret)
        {
            match ClientSecretCredential::new(
                tenant_id.as_str(),
                client_id,
                AzureSecret::new(client_secret),
                None,
            ) {
                Ok(cred) => sources.push(("EnvironmentClientSecretCredential", cred)),
                Err(err) => warn!(
                    "AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET are set, but the \
                     ClientSecretCredential could not be constructed: {err}"
                ),
            }
        }
        if let Ok(cred) = WorkloadIdentityCredential::new(None) {
            sources.push(("WorkloadIdentityCredential", cred));
        }
        if let Ok(cred) = ManagedIdentityCredential::new(None) {
            sources.push(("ManagedIdentityCredential", cred));
        }
        if let Ok(cred) = DeveloperToolsCredential::new(None) {
            sources.push(("DeveloperToolsCredential", cred));
        }

        if sources.is_empty() {
            return Err(azure_core::Error::with_message(
                azure_core::error::ErrorKind::Other,
                "no Azure credential sources could be constructed",
            ));
        }

        Ok(Arc::new(Self { sources }))
    }
}

#[async_trait]
impl TokenCredential for DefaultAzureCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let mut last_error = None;
        for (name, cred) in &self.sources {
            match cred.get_token(scopes, options.clone()).await {
                Ok(token) => return Ok(token),
                Err(err) => {
                    debug!("{name} could not obtain token: {err}");
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            azure_core::Error::with_message(
                azure_core::error::ErrorKind::Other,
                "all Azure credentials in default chain failed to acquire a token",
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap()
    }

    #[test]
    fn tenant_and_client_id_without_secret_is_not_an_incomplete_config_error() {
        let _guard = lock_env();
        unsafe {
            std::env::set_var("AZURE_TENANT_ID", "tenant");
            std::env::set_var("AZURE_CLIENT_ID", "client");
            std::env::remove_var("AZURE_CLIENT_SECRET");
        }

        let result = DefaultAzureCredential::new();
        if let Err(err) = result {
            assert!(
                !err.to_string()
                    .contains("incomplete Azure service principal"),
                "tenant + client ID without secret must fall through to Workload \
                 Identity, not fail as an incomplete service principal: {err}"
            );
        }

        unsafe {
            std::env::remove_var("AZURE_TENANT_ID");
            std::env::remove_var("AZURE_CLIENT_ID");
        }
    }
}
