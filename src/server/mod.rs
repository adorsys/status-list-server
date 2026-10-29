//! Inbound HTTP web server module containing handlers, auth middleware, and shared application state.

pub mod auth;
pub mod cache;
pub mod error;
pub mod handlers;
pub mod health;
pub mod rate_limit;

use crate::domain::models::credential::{AggregationId, Issuer};
use crate::domain::service::{Service, StatusListPolicy};
use axum::{Json, extract::State};
use std::collections::HashSet;
use std::sync::Arc;
use url::Url;

/// JWT policy for protected management endpoints.
#[derive(Debug, Clone)]
pub struct ManagementAuthConfig {
    pub leeway_secs: u64,
    pub max_token_lifetime_secs: u64,
    pub audiences: Vec<String>,
}

impl Default for ManagementAuthConfig {
    fn default() -> Self {
        Self {
            leeway_secs: 60,
            max_token_lifetime_secs: 300,
            audiences: Vec::new(),
        }
    }
}

impl From<&crate::config::ManagementAuthConfig> for ManagementAuthConfig {
    fn from(config: &crate::config::ManagementAuthConfig) -> Self {
        Self {
            leeway_secs: config.leeway_secs,
            max_token_lifetime_secs: config.max_token_lifetime_secs,
            audiences: config.audiences.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdminAuthConfig {
    pub leeway_secs: u64,
    pub max_token_lifetime_secs: u64,
    pub audiences: Vec<String>,
}

impl From<&crate::config::AdminAuthConfig> for AdminAuthConfig {
    fn from(config: &crate::config::AdminAuthConfig) -> Self {
        Self {
            leeway_secs: config.leeway_secs,
            max_token_lifetime_secs: config.max_token_lifetime_secs,
            audiences: config.audiences.clone(),
        }
    }
}

/// Links exposed in the `GET /` service document.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceLinks {
    pub documentation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portal: Option<String>,
}

/// The minimal `application/json` service document returned by `GET /`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceDocument {
    pub service: &'static str,
    pub links: ServiceLinks,
}

/// Shared application state injected into web handlers.
#[derive(Clone)]
pub struct AppState {
    /// Domain service container holding secondary ports.
    pub service: Arc<Service>,
    /// Resolved public base URL (e.g. `https://statuslist.example.com/api/v1`).
    /// Used to build the `sub` URI signed into issued tokens and returned to
    /// issuers as the publish `Location`.
    pub public_base_url: String,
    /// The aggregation endpoint's URL. Tokens and registrations advertise it
    /// scoped to one issuer; see [`AppState::aggregation_uri_for`].
    pub aggregation_uri: Option<Url>,
    /// Issuers that were over one aggregation page at startup.
    pub aggregation_withheld_from: Arc<HashSet<Issuer>>,
    pub token_exp_secs: u64,
    pub token_ttl_secs: u64,
    pub max_status_index: i32,
    pub max_statuses_per_request: usize,
    pub max_serialized_list_size: usize,
    pub max_lists_per_issuer: u64,
    pub snapshot_retention_secs: u64,
    pub management_auth: ManagementAuthConfig,
    pub admin_auth: AdminAuthConfig,
    pub admin_registry: Arc<auth::issuer_registry::RegistryHandle>,
    pub hosted_issuer_store: Option<Arc<dyn crate::domain::ports::HostedIssuerStore>>,
    /// Last-known-good operator-managed issuer trust registry snapshot.
    pub issuer_registry: Arc<dyn crate::domain::ports::IssuerDirectory>,
    /// Trust-source port used by authentication.
    pub issuer_key_resolver: Arc<dyn crate::domain::ports::IssuerKeyResolver>,
    /// Links exposed in the `GET /` service document.
    pub links: ServiceLinks,
    /// Per-replica cache of signed status-list token bytes.
    pub token_bytes_cache: crate::server::cache::TokenBytesCache,
    /// Dependency readiness checks backing the `/health/ready` endpoint.
    pub readiness: health::Readiness,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

impl AppState {
    pub fn set_issuer_registry(&mut self, registry: Arc<auth::issuer_registry::RegistryHandle>) {
        self.issuer_key_resolver = registry.clone();
        self.admin_registry = registry.clone();
        self.issuer_registry = registry;
    }
    /// The issuer's aggregation URI, or `None` when aggregation is not
    /// configured or is withheld from the issuer.
    pub fn aggregation_uri_for(
        &self,
        issuer: &Issuer,
        aggregation_id: AggregationId,
    ) -> Option<String> {
        if self.aggregation_withheld_from.contains(issuer) {
            return None;
        }
        let mut uri = self.aggregation_uri.clone()?;
        uri.path_segments_mut()
            .ok()?
            .push(&aggregation_id.to_string());
        Some(uri.into())
    }

    pub fn status_list_policy(&self) -> StatusListPolicy {
        StatusListPolicy {
            token_exp_secs: self.token_exp_secs,
            max_status_index: self.max_status_index,
            max_statuses_per_request: self.max_statuses_per_request,
            max_serialized_list_size: self.max_serialized_list_size,
            max_lists_per_issuer: self.max_lists_per_issuer,
        }
    }
}

/// `GET /` service document: a minimal `application/json` body naming the
/// service and its documentation (and portal when configured). No version and
/// no HTML, so a proxy/ingress health-checking the root sees a stable JSON
/// contract.
pub async fn service_document(State(state): State<AppState>) -> Json<ServiceDocument> {
    Json(ServiceDocument {
        service: "Status List Server",
        links: state.links,
    })
}
