use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::HeaderMap, response::IntoResponse,
};

use crate::utils::state::AppState;

use super::error::StatusListError;

pub async fn status_list_token(
    State(db): State<Arc<AppState>>,
    Path(list_id): Path<u32>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusListError> {
    let status_list = db
        .get_status_list(status_list_id)
        .await
        .map_err(StatusListError::Database)?;

    Ok(status_list)
}
