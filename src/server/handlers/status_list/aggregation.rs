use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::server::{AppState, error::ApiError};

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct AggregationResponse {
    pub(super) status_lists: Vec<String>,
}

pub async fn get_aggregation(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let status_lists = state.service.list_uris().await?;

    tracing::info!(
        "Serving status list aggregation with {} list(s)",
        status_lists.len()
    );

    Ok((StatusCode::OK, Json(AggregationResponse { status_lists })))
}
