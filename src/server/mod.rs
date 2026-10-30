//! Inbound HTTP web server module containing handlers, auth middleware, and shared application state.

pub mod auth;
pub mod cache;
pub mod error;
pub mod handlers;
pub mod health;
pub mod rate_limit;

use crate::domain::models::credential::{AggregationId, Issuer};
use crate::domain::models::tier::{IssuerTier, Tiers};
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
#[derive(Debug, Clone)]
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
    pub max_serialized_list_size: usize,
    /// Per-tier quotas and request bounds, resolved from `tiers.*`.
    pub tiers: Arc<Tiers>,
    /// Per-replica write budgets keyed on the authenticated issuer.
    pub issuer_rate_limiter: Arc<rate_limit::IssuerRateLimiter>,
    pub snapshot_retention_secs: u64,
    pub management_auth: ManagementAuthConfig,
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

impl AppState {
    pub fn set_issuer_registry(&mut self, registry: Arc<auth::issuer_registry::RegistryHandle>) {
        self.issuer_key_resolver = registry.clone();
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

    pub fn status_list_policy(&self, tier: IssuerTier) -> StatusListPolicy {
        let limits = self.tiers.get(tier);
        StatusListPolicy {
            token_exp_secs: self.token_exp_secs,
            max_status_index: limits.max_status_index,
            max_statuses_per_request: limits.max_statuses_per_request,
            max_serialized_list_size: self.max_serialized_list_size,
            max_lists_per_issuer: limits.max_lists,
        }
    }

    #[cfg(test)]
    pub(crate) fn tier_limits_mut(
        &mut self,
        tier: IssuerTier,
    ) -> &mut crate::domain::models::tier::TierLimits {
        let tiers = Arc::make_mut(&mut self.tiers);
        match tier {
            IssuerTier::Standard => &mut tiers.standard,
            IssuerTier::Sandbox => &mut tiers.sandbox,
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
