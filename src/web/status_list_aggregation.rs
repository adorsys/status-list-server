use std::collections::HashMap;
use std::fmt::Debug;
use tokio::sync::Mutex;

use axum::{
    extract::{Json, Path, State},
    http::{header, HeaderMap},
    response::IntoResponse,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use tracing;
use uuid::Uuid;

use crate::{
    utils::state::AppState,
    web::handlers::status_list::{
        constants::{ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT},
        error::StatusListError,
    },
};

lazy_static! {
    static ref AGGREGATION_MAP: Mutex<HashMap<String, Vec<String>>> = Mutex::new(HashMap::new());
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusListAggregationRequest {
    pub list_ids: Option<Vec<String>>,
    pub issuer: Option<String>,
}

pub async fn aggregate_status_lists(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<StatusListAggregationRequest>,
) -> Result<impl IntoResponse + Debug, StatusListError> {
    let _accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());

    // Validate accept header
    let _accept = match _accept {
        None => ACCEPT_STATUS_LISTS_HEADER_JWT, // Default to JWT if no accept header
        Some(accept)
            if accept == ACCEPT_STATUS_LISTS_HEADER_JWT
                || accept == ACCEPT_STATUS_LISTS_HEADER_CWT =>
        {
            accept
        }
        Some(_) => return Err(StatusListError::InvalidAcceptHeader),
    };

    // Get status lists based on either list_ids or issuer
    let mut status_lists = Vec::new();

    if let Some(list_ids) = request.list_ids {
        // Fetch by specific list IDs
        for list_id in list_ids {
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
    } else if let Some(issuer) = request.issuer {
        // Fetch all status lists for the given issuer
        status_lists = state
            .status_list_token_repository
            .find_by_issuer(issuer)
            .await
            .map_err(|err| {
                tracing::error!("Failed to get status lists for issuer: {err:?}");
                StatusListError::InternalServerError
            })?;
    } else {
        return Err(StatusListError::Generic(
            "Either list_ids or issuer must be provided".to_string(),
        ));
    }

    if status_lists.is_empty() {
        return Err(StatusListError::Generic(
            "No status lists found".to_string(),
        ));
    }

    // Generate a unique aggregation ID
    let aggregation_id = format!("aggregation_{}", Uuid::new_v4());

    // Store the mapping from aggregation_id to the list of status list IDs
    {
        let mut map = AGGREGATION_MAP.lock().await;
        map.insert(
            aggregation_id.clone(),
            status_lists.iter().map(|t| t.list_id.clone()).collect(),
        );
    }

    // Return the aggregation URI
    let aggregation_uri = format!("/statuslists/aggregate/{}", aggregation_id);
    Ok(axum::Json(
        serde_json::json!({ "aggregation_uri": aggregation_uri }),
    ))
}

pub async fn get_aggregated_status_lists(
    Path(aggregation_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusListError> {
    let map = AGGREGATION_MAP.lock().await;
    let list_ids = map
        .get(&aggregation_id)
        .ok_or(StatusListError::StatusListNotFound)?;

    // Fetch all tokens from the DB
    let mut tokens = Vec::new();
    for list_id in list_ids {
        let token = state
            .status_list_token_repository
            .find_one_by(list_id.clone())
            .await
            .map_err(|_| StatusListError::InternalServerError)?
            .ok_or(StatusListError::StatusListNotFound)?;
        tokens.push(token);
    }

    Ok(axum::Json(tokens))
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
