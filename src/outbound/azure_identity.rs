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
use tracing::debug;

/// Chained token credential that evaluates supported ambient Azure identity
/// sources in order: Environment client secret -> Workload Identity ->
/// Managed Identity -> Developer Tools.
#[derive(Debug)]
pub struct DefaultAzureCredential {
    sources: Vec<(&'static str, Arc<dyn TokenCredential>)>,
}

impl DefaultAzureCredential {
    /// Create a new [`DefaultAzureCredential`] chain with available credential sources.
    pub fn new() -> azure_core::Result<Arc<Self>> {
        let mut sources: Vec<(&'static str, Arc<dyn TokenCredential>)> = Vec::new();

        if let (Ok(tenant_id), Ok(client_id), Ok(client_secret)) = (
            std::env::var("AZURE_TENANT_ID"),
            std::env::var("AZURE_CLIENT_ID"),
            std::env::var("AZURE_CLIENT_SECRET"),
        ) {
            if let Ok(cred) = ClientSecretCredential::new(
                tenant_id.as_str(),
                client_id,
                AzureSecret::new(client_secret),
                None,
            ) {
                sources.push(("EnvironmentClientSecretCredential", cred));
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
