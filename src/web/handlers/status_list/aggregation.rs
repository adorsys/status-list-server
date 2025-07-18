use axum::{extract::State, response::IntoResponse, Json};
use serde::Serialize;
use crate::utils::state::AppState;
use crate::web::handlers::status_list::error::StatusListError;

#[derive(Serialize)]
pub struct AggregationResponse {
    pub status_lists: Vec<String>,
}

pub async fn aggregation(State(state): State<AppState>) -> Result<impl IntoResponse, StatusListError> {
    let records = state.status_list_repo.find_all().await.map_err(|e| {
        tracing::error!("Failed to fetch all status lists: {:?}", e);
        StatusListError::InternalServerError
    })?;
    let status_lists = records.into_iter().map(|rec| rec.sub).collect();
    Ok(Json(AggregationResponse { status_lists }))
} 