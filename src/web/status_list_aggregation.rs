use crate::{utils::state::AppState, web::handlers::status_list::error::StatusListError};
use axum::{
    extract::{Json, State},
    http::HeaderMap,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusListAggregationRequest {
    pub list_ids: Option<Vec<String>>,
    pub issuer: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatusListAggregationResponse {
    pub aggregation_uri: String,
}

pub async fn aggregate_status_lists(
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
    Json(request): Json<StatusListAggregationRequest>,
) -> Result<impl IntoResponse, StatusListError> {
    let mut status_lists = Vec::new();

    if let Some(list_ids) = request.list_ids {
        for list_id in list_ids {
            if let Some(token) = state
                .status_list_token_repository
                .find_one_by(list_id.clone())
                .await
                .map_err(|_| StatusListError::InternalServerError)?
            {
                status_lists.push(token);
            }
        }
    } else if let Some(issuer) = request.issuer {
        status_lists = state
            .status_list_token_repository
            .find_by_issuer(&issuer)
            .await
            .map_err(|_| StatusListError::InternalServerError)?;
    }

    if status_lists.is_empty() {
        return Err(StatusListError::StatusListNotFound);
    }

    // TODO: Implement actual aggregation logic
    // For now, just return a placeholder URI
    Ok(Json(StatusListAggregationResponse {
        aggregation_uri: format!(
            "{}/status-list-aggregation/{}",
            state.server_public_domain,
            uuid::Uuid::new_v4()
        ),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{status_list_tokens, StatusList, StatusListToken},
        test_utils::test::test_app_state,
    };
    use axum::http::StatusCode;
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::sync::Arc;

    // Helper to create a test request payload
    fn create_test_request(
        list_ids: Option<Vec<String>>,
        issuer: Option<String>,
    ) -> StatusListAggregationRequest {
        StatusListAggregationRequest { list_ids, issuer }
    }

    #[tokio::test]
    async fn test_aggregate_by_list_ids() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let list_id1 = "list1";
        let list_id2 = "list2";
        let request =
            create_test_request(Some(vec![list_id1.to_string(), list_id2.to_string()]), None);

        let status_list1 = StatusListToken {
            list_id: list_id1.to_string(),
            issuer: "issuer1".to_string(),
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
            issuer: "issuer2".to_string(),
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

        let app_state = Arc::new(test_app_state(db_conn));

        let headers = HeaderMap::new();
        let response = aggregate_status_lists(State(app_state), headers, Json(request))
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the response contains an aggregation URI
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
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
            issuer: issuer.to_string(),
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
            issuer: issuer.to_string(),
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

        let app_state = Arc::new(test_app_state(db_conn));

        let headers = HeaderMap::new();
        let response = aggregate_status_lists(State(app_state), headers, Json(request))
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the response contains an aggregation URI
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
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

        let app_state = Arc::new(test_app_state(db_conn));

        let headers = HeaderMap::new();
        let response = aggregate_status_lists(State(app_state), headers, Json(request))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
