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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::test_utils::test_app_state;
    use axum::extract::State;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn test_aggregation_empty_when_no_lists() {
        let state = test_app_state(None).await;
        let response = get_aggregation(State(state)).await.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_aggregation_returns_all_list_uris() {
        let state = test_app_state(None).await;
        let list_id = uuid::Uuid::new_v4().to_string();

        state
            .service
            .publish_status_list(
                list_id.clone(),
                Issuer("issuer1".into()),
                format!("https://example.com/api/v1/status-lists/{list_id}"),
                vec![],
                900,
                100_000,
                5_000,
                1_048_576,
            )
            .await
            .unwrap();

        let response = get_aggregation(State(state)).await.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_aggregation_returns_uris_from_multiple_issuers() {
        let state = test_app_state(None).await;
        let id1 = uuid::Uuid::new_v4().to_string();
        let id2 = uuid::Uuid::new_v4().to_string();

        state
            .service
            .publish_status_list(
                id1.clone(),
                Issuer("issuer1".into()),
                format!("https://example.com/api/v1/status-lists/{id1}"),
                vec![],
                900,
                100_000,
                5_000,
                1_048_576,
            )
            .await
            .unwrap();

        state
            .service
            .publish_status_list(
                id2.clone(),
                Issuer("issuer2".into()),
                format!("https://example.com/api/v1/status-lists/{id2}"),
                vec![],
                900,
                100_000,
                5_000,
                1_048_576,
            )
            .await
            .unwrap();

        let response = get_aggregation(State(state)).await.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
