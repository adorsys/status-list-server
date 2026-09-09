//! Inbound HTTP web server module containing handlers, auth middleware, and shared application state.

pub mod auth;
pub mod error;
pub mod handlers;
pub mod health;
pub mod rate_limit;

use crate::domain::service::Service;
use std::sync::Arc;

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
            max_token_lifetime_secs: 3600,
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

/// Shared application state injected into web handlers.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Domain service container holding secondary ports.
    pub service: Arc<Service>,
    pub server_domain: String,
    pub aggregation_uri: Option<String>,
    pub token_exp_secs: u64,
    pub token_ttl_secs: u64,
    pub max_status_index: i32,
    pub max_statuses_per_request: usize,
    pub max_serialized_list_size: usize,
    pub snapshot_retention_secs: u64,
    pub management_auth: ManagementAuthConfig,
    /// Dependency readiness checks backing the `/health/ready` endpoint.
    pub readiness: health::Readiness,
}
