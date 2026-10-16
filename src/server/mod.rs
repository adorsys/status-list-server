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

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceLinks {
    pub documentation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portal: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceDocument {
    pub service: &'static str,
    pub links: ServiceLinks,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub service: Arc<Service>,
    /// Base of every sub URI; changing it doesn't rewrite lists already published.
    pub public_base_url: String,
    /// Unscoped; use aggregation_uri_for to get an issuer's URI.
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
    pub links: ServiceLinks,
    pub token_bytes_cache: crate::server::cache::TokenBytesCache,
    pub readiness: health::Readiness,
}

impl AppState {
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

/// No version and no HTML, so proxies probing `/` see a stable JSON contract.
pub async fn service_document(State(state): State<AppState>) -> Json<ServiceDocument> {
    Json(ServiceDocument {
        service: "Status List Server",
        links: state.links,
    })
}
