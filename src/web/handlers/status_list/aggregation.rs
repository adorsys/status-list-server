use crate::utils::state::AppState;
use crate::web::handlers::status_list::error::StatusListError;
use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AggregationResponse {
    pub status_lists: Vec<String>,
}

pub async fn aggregation(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusListError> {
    let records = state.status_list_repo.find_all().await.map_err(|e| {
        tracing::error!("Failed to fetch all status lists: {:?}", e);
        StatusListError::InternalServerError
    })?;
    let status_lists = records.into_iter().map(|rec| rec.sub).collect();
    Ok(Json(AggregationResponse { status_lists }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{status_lists, StatusList, StatusListRecord},
        test_utils::test_app_state,
    };
    use axum::{body::to_bytes, http::StatusCode, Router};
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::sync::Arc;
    use tower::ServiceExt; // for .oneshot()

    #[tokio::test]
    async fn test_aggregation_returns_all_status_list_uris() {
        let status_list1 = StatusListRecord {
            list_id: "list1".to_string(),
            issuer: "issuer1".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "foo".to_string(),
            },
            sub: "https://example.com/statuslists/list1".to_string(),
        };
        let status_list2 = StatusListRecord {
            list_id: "list2".to_string(),
            issuer: "issuer2".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "bar".to_string(),
            },
            sub: "https://example.com/statuslists/list2".to_string(),
        };
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                status_list1.clone(),
                status_list2.clone(),
            ]])
            .into_connection();
        let app_state = test_app_state(Some(Arc::new(mock_db))).await;
        let app = Router::new()
            .route("/aggregation", axum::routing::get(aggregation))
            .with_state(app_state);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/aggregation")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let result: AggregationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(result.status_lists.len(), 2);
        assert!(result
            .status_lists
            .contains(&"https://example.com/statuslists/list1".to_string()));
        assert!(result
            .status_lists
            .contains(&"https://example.com/statuslists/list2".to_string()));
    }
}
