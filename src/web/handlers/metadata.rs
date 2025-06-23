use axum::{extract::State, response::IntoResponse, http::{StatusCode, header}};
use crate::utils::state::AppState;
use serde_json::json;

pub async fn openid_configuration(State(state): State<AppState>) -> impl IntoResponse {
    let base_url = format!("https://{}", state.server_domain);
    let aggregation_url = format!("{}/status-lists", base_url);
    let metadata = json!({
        "issuer": base_url,
        "status_list_aggregation_endpoint": aggregation_url,
        // ... add other OpenID/OAuth metadata fields as needed ...
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        metadata.to_string(),
    )
} 