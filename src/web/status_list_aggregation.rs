use crate::{
    utils::state::AppState,
    web::handlers::status_list::{
        constants::{ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT},
        error::StatusListError,
    },
};
use axum::{
    extract::{Json, State, Path},
    http::{header, HeaderMap},
    response::IntoResponse,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use tracing;
use uuid::Uuid;
use std::collections::HashMap;
use std::fmt::Debug;
use tokio::sync::Mutex;

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
    use super::*;
    use crate::{
        database::queries::SeaOrmStore,
        model::{status_list_tokens, StatusList, StatusListToken},
        utils::state::AppState,
        utils::keygen::Keypair,
    };
    use axum::http::StatusCode;
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::sync::Arc;

    // Helper to create a test request payload
    fn create_test_request(list_ids: Option<Vec<String>>, issuer: Option<String>) -> StatusListAggregationRequest {
        StatusListAggregationRequest { list_ids, issuer }
    }

    // Helper to generate a test server key
    fn server_key() -> Keypair {
        Keypair::generate().unwrap()
    }

    #[tokio::test]
    async fn test_aggregate_by_list_ids() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let list_id1 = "list1";
        let list_id2 = "list2";
        let request = create_test_request(Some(vec![list_id1.to_string(), list_id2.to_string()]), None);

        let status_list1 = StatusListToken {
            list_id: list_id1.to_string(),
            exp: None,
            iat: chrono::Utc::now().timestamp(),
            status_list: StatusList {
                bits: 2,
                lst: "abc".to_string(),
            },
            sub: "issuer1".to_string(),
            ttl: None,
        };

        let status_list2 = StatusListToken {
            list_id: list_id2.to_string(),
            exp: None,
            iat: chrono::Utc::now().timestamp(),
            status_list: StatusList {
                bits: 2,
                lst: "def".to_string(),
            },
            sub: "issuer2".to_string(),
            ttl: None,
        };

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![status_list1.clone()], // find_one_by for list1
                    vec![status_list2.clone()], // find_one_by for list2
                ])
                .into_connection(),
        );

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

        let headers = HeaderMap::new();
        let response = aggregate_status_lists(State(app_state), headers, Json(request))
            .await
            .unwrap()
            .into_response();
        
        assert_eq!(response.status(), StatusCode::OK);
        
        // Verify the response contains an aggregation URI
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("aggregation_uri").is_some());
    }

    #[tokio::test]
    async fn test_aggregate_by_issuer() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let issuer = "test_issuer";
        let request = create_test_request(None, Some(issuer.to_string()));

        let status_list1 = StatusListToken {
            list_id: "list1".to_string(),
            exp: None,
            iat: chrono::Utc::now().timestamp(),
            status_list: StatusList {
                bits: 2,
                lst: "abc".to_string(),
            },
            sub: issuer.to_string(),
            ttl: None,
        };

        let status_list2 = StatusListToken {
            list_id: "list2".to_string(),
            exp: None,
            iat: chrono::Utc::now().timestamp(),
            status_list: StatusList {
                bits: 2,
                lst: "def".to_string(),
            },
            sub: issuer.to_string(),
            ttl: None,
        };

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![status_list1.clone(), status_list2.clone()], // find_by_issuer
                ])
                .into_connection(),
        );

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

        let headers = HeaderMap::new();
        let response = aggregate_status_lists(State(app_state), headers, Json(request))
            .await
            .unwrap()
            .into_response();
        
        assert_eq!(response.status(), StatusCode::OK);
        
        // Verify the response contains an aggregation URI
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("aggregation_uri").is_some());
    }

    #[tokio::test]
    async fn test_aggregate_no_lists_found() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let request = create_test_request(Some(vec!["nonexistent".to_string()]), None);

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![], // find_one_by returns None
                ])
                .into_connection(),
        );

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

        let headers = HeaderMap::new();
        let response = aggregate_status_lists(State(app_state), headers, Json(request))
            .await
            .unwrap_err()
            .into_response();
        
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
