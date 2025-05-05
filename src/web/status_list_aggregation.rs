use std::sync::Arc;

use axum::{
    extract::{Json, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use tracing;

use crate::{
    model::StatusList,
    utils::state::AppState,
};

use super::status_list::{
    constants::{ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT},
    error::StatusListError,
    handler::{build_status_list_token, StatusListToken},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusListAggregationRequest {
    pub list_ids: Vec<String>,
}

pub async fn aggregate_status_lists(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<StatusListAggregationRequest>,
) -> Result<impl IntoResponse, StatusListError> {
    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());

    // Validate accept header
    let accept = match accept {
        None => ACCEPT_STATUS_LISTS_HEADER_JWT, // Default to JWT if no accept header
        Some(accept) if accept == ACCEPT_STATUS_LISTS_HEADER_JWT || accept == ACCEPT_STATUS_LISTS_HEADER_CWT => accept,
        Some(_) => return Err(StatusListError::InvalidAcceptHeader),
    };

    // Get all status lists from the database
    let mut status_lists = Vec::new();
    for list_id in request.list_ids {
        let status_list = state
            .status_list_token_repository
            .find_one_by(list_id.clone())
            .await
            .map_err(|err| {
                tracing::error!("Failed to get status list {list_id} from database: {err:?}");
                StatusListError::InternalServerError
            })?
            .ok_or(StatusListError::StatusListNotFound)?;
        status_lists.push(status_list);
    }

    // Aggregate the status lists
    let aggregated_list = aggregate_status_lists_impl(status_lists)?;

    // Create a new status list token for the aggregated list
    let aggregated_token = StatusListToken {
        list_id: "aggregated".to_string(), // This is a placeholder, you might want to generate a unique ID
        exp: None, // No expiration for aggregated list
        iat: chrono::Utc::now().timestamp(),
        status_list: aggregated_list,
        sub: "aggregated".to_string(), // This is a placeholder
        ttl: None, // No TTL for aggregated list
    };

    // Return the aggregated list in the requested format
    build_status_list_token(accept, "aggregated", &state).await
}

fn aggregate_status_lists_impl(status_lists: Vec<StatusListToken>) -> Result<StatusList, StatusListError> {
    if status_lists.is_empty() {
        return Err(StatusListError::InvalidRequest("No status lists provided".to_string()));
    }

    // Get the maximum bits value from all lists
    let max_bits = status_lists.iter().map(|list| list.status_list.bits).max().unwrap_or(0);

    // Combine all status lists
    let mut combined_lst = String::new();
    for list in status_lists {
        combined_lst.push_str(&list.status_list.lst);
    }

    Ok(StatusList {
        bits: max_bits,
        lst: combined_lst,
    })
}
