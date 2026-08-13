//! Inbound HTTP web server module containing handlers, auth middleware, and shared application state.

pub mod auth;
pub mod error;
pub mod handlers;
pub mod health;
pub mod rate_limit;

use crate::domain::service::Service;
use std::sync::Arc;

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
    /// Dependency readiness checks backing the `/health/ready` endpoint.
    pub readiness: health::Readiness,
}
