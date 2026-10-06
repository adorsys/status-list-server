//! Shared Azure identity helpers for Azure-backed adapters.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use azure_core::credentials::{
    AccessToken, Secret as AzureSecret, TokenCredential, TokenRequestOptions,
};
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    WorkloadIdentityCredential, WorkloadIdentityCredentialOptions,
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
        Self::new_from_env(
            std::env::var("AZURE_TENANT_ID").ok(),
            std::env::var("AZURE_CLIENT_ID").ok(),
            std::env::var("AZURE_CLIENT_SECRET").ok(),
            std::env::var("AZURE_FEDERATED_TOKEN_FILE").ok(),
        )
    }

    /// Build the credential chain from explicit environment values.
    ///
    /// Split out from [`Self::new`] so the selection logic is testable without
    /// mutating process-global environment variables.
    fn new_from_env(
        tenant_id: Option<String>,
        client_id: Option<String>,
        client_secret: Option<String>,
        federated_token_file: Option<String>,
    ) -> azure_core::Result<Arc<Self>> {
        let mut sources: Vec<(&'static str, Arc<dyn TokenCredential>)> = Vec::new();

        if let (Some(tenant_id), Some(client_id), Some(client_secret)) =
            (tenant_id.as_ref(), client_id.as_ref(), client_secret.as_ref())
        {
            match ClientSecretCredential::new(
                tenant_id.as_str(),
                client_id.clone(),
                AzureSecret::new(client_secret.clone()),
                None,
            ) {
                Ok(cred) => sources.push(("EnvironmentClientSecretCredential", cred)),
                Err(err) => warn!(
                    "AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET are set, but the \
                     ClientSecretCredential could not be constructed: {err}"
                ),
            }
        }
        if let (Some(tenant_id), Some(client_id), Some(federated_token_file)) =
            (tenant_id.as_ref(), client_id.as_ref(), federated_token_file.as_ref())
        {
            match WorkloadIdentityCredential::new(Some(WorkloadIdentityCredentialOptions {
                client_id: Some(client_id.clone()),
                tenant_id: Some(tenant_id.clone()),
                token_file_path: Some(PathBuf::from(federated_token_file.clone())),
                ..Default::default()
            })) {
                Ok(cred) => sources.push(("WorkloadIdentityCredential", cred)),
                Err(err) => warn!(
                    "AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_FEDERATED_TOKEN_FILE are set, but the \
                     WorkloadIdentityCredential could not be constructed: {err}"
                ),
            }
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

    fn source_names(credential: &DefaultAzureCredential) -> Vec<&'static str> {
        credential.sources.iter().map(|(name, _)| *name).collect()
    }

    #[test]
    fn tenant_and_client_id_without_secret_falls_through_to_workload_identity() {
        let dir = std::env::temp_dir().join(format!("sls-azure-identity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let token_file = dir.join("federated-token");
        std::fs::write(&token_file, "dummy-token").expect("write federated token file");

        let credential = DefaultAzureCredential::new_from_env(
            Some("tenant".into()),
            Some("client".into()),
            None,
            Some(token_file.to_string_lossy().into_owned()),
        )
        .expect("credential chain should build");
        let names = source_names(&credential);
        assert!(
            names.contains(&"WorkloadIdentityCredential"),
            "tenant + client ID without secret must fall through to Workload Identity, \
             got sources: {names:?}"
        );
        assert!(
            !names.contains(&"EnvironmentClientSecretCredential"),
            "no secret set, so the client secret credential must not be in the chain: {names:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn complete_service_principal_uses_environment_client_secret() {
        let credential = DefaultAzureCredential::new_from_env(
            Some("tenant".into()),
            Some("client".into()),
            Some("secret".into()),
            None,
        )
        .expect("credential chain should build");
        let names = source_names(&credential);
        assert!(
            names.contains(&"EnvironmentClientSecretCredential"),
            "all three service-principal vars set, so the client secret credential must be in \
             the chain: {names:?}"
        );
    }
}
