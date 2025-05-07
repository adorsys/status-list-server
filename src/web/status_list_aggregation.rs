use std::fmt::Debug;

use axum::{
    extract::{Json, State},
    http::{header, HeaderMap},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use tracing;
use uuid::Uuid;

use crate::{
    model::{StatusList, StatusListToken},
    utils::state::AppState,
    web::handlers::status_list::{
        constants::{ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT},
        error::StatusListError,
        handler::build_status_list_token,
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusListAggregationRequest {
    pub list_ids: Vec<String>,
}

pub async fn aggregate_status_lists(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<StatusListAggregationRequest>,
) -> Result<impl IntoResponse + Debug, StatusListError> {
    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());

    // Validate accept header
    let accept = match accept {
        None => ACCEPT_STATUS_LISTS_HEADER_JWT, // Default to JWT if no accept header
        Some(accept)
            if accept == ACCEPT_STATUS_LISTS_HEADER_JWT
                || accept == ACCEPT_STATUS_LISTS_HEADER_CWT =>
        {
            accept
        }
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

    // Generate a unique ID for the aggregated list
    let aggregated_id = format!("aggregated_{}", Uuid::new_v4());

    // Create a new status list token for the aggregated list
    let aggregated_token = StatusListToken {
        list_id: aggregated_id.clone(),
        exp: None, // No expiration for aggregated list
        iat: chrono::Utc::now().timestamp(),
        status_list: aggregated_list.clone(),
        sub: "aggregated".to_string(),
        ttl: None, // No TTL for aggregated list
    };

    // Store the aggregated list in the database
    state
        .status_list_token_repository
        .insert_one(aggregated_token.clone())
        .await
        .map_err(|err| {
            tracing::error!("Failed to store aggregated status list: {err:?}");
            StatusListError::InternalServerError
        })?;

    // Return the aggregated list in the requested format
    build_status_list_token(accept, &aggregated_token, &state).await
}

fn aggregate_status_lists_impl(
    status_lists: Vec<StatusListToken>,
) -> Result<StatusList, StatusListError> {
    if status_lists.is_empty() {
        return Err(StatusListError::Generic(
            "No status lists provided".to_string(),
        ));
    }

    // Get the maximum bits value from all lists
    let max_bits = status_lists
        .iter()
        .map(|list| list.status_list.bits)
        .max()
        .unwrap_or(0);

    // Combine all status lists
    let mut combined_lst = String::new();
    for list in status_lists {
        // If the list has fewer bits than max_bits, pad it with zeros
        let mut lst = list.status_list.lst;
        if list.status_list.bits < max_bits {
            let padding = "0".repeat(max_bits - list.status_list.bits);
            lst.push_str(&padding);
        }
        combined_lst.push_str(&lst);
    }

    Ok(StatusList {
        bits: max_bits,
        lst: combined_lst,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        model::{StatusList, StatusListToken},
        web::handlers::status_list::handler::StatusListTokenExt,
    };
    use sea_orm::{DatabaseBackend, MockDatabase};

    fn encode_lst(bits: Vec<u8>) -> String {
        base64url::encode(
            bits.iter()
                .flat_map(|&n| n.to_be_bytes())
                .collect::<Vec<u8>>(),
        )
    }

    #[tokio::test]
    async fn test_update_statuslist_success() {
        let _mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let initial_status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 0, 0]),
        };
        let _existing_token = StatusListToken::new(
            "test_list".to_string(),
            None,
            1234567890,
            initial_status_list.clone(),
            "test_subject".to_string(),
            None,
        );
        let updated_status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 1, 0]), // After update: index 1 set to INVALID
        };
        let _updated_token = StatusListToken::new(
            "test_list".to_string(),
            None,
            1234567890,
            updated_status_list,
            "test_subject".to_string(),
            None,
        );
    }
}
