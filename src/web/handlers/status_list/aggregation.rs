use axum::{extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::utils::state::AppState;

use super::error::StatusListError;

#[derive(Debug, Serialize, Deserialize)]
pub struct AggregationResponse {
    pub status_lists: Vec<String>,
}

pub async fn get_aggregation(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusListError> {
    let mut status_lists = state.status_list_repo.find_all_subs().await.map_err(|e| {
        tracing::error!("Failed to fetch status lists for aggregation: {e:?}");
        StatusListError::InternalServerError
    })?;

    status_lists.sort_unstable();
    status_lists.dedup();

    tracing::info!(
        "Serving status list aggregation with {} list(s)",
        status_lists.len()
    );

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        axum::Json(AggregationResponse { status_lists }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_app_state;
    use axum::{body::to_bytes, response::IntoResponse};
    use sea_orm::{DatabaseBackend, MockDatabase, Value};
    use std::{collections::BTreeMap, sync::Arc};

    fn row_with_sub(sub: &str) -> BTreeMap<String, Value> {
        BTreeMap::from([("sub".to_string(), Value::from(sub))])
    }

    #[tokio::test]
    async fn test_aggregation_returns_all_list_uris() {
        let rows = vec![
            row_with_sub("https://example.com/statuslists/b"),
            row_with_sub("https://example.com/statuslists/a"),
        ];
        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<BTreeMap<String, Value>, Vec<_>, _>(vec![rows])
                .into_connection(),
        );
        let state = test_app_state(Some(db_conn)).await;

        let response = get_aggregation(State(state)).await.unwrap().into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );

        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let payload: AggregationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload.status_lists,
            vec![
                "https://example.com/statuslists/a".to_string(),
                "https://example.com/statuslists/b".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn test_aggregation_empty_when_no_lists() {
        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<BTreeMap<String, Value>, Vec<_>, _>(vec![Vec::<
                    BTreeMap<String, Value>,
                >::new(
                )])
                .into_connection(),
        );
        let state = test_app_state(Some(db_conn)).await;

        let response = get_aggregation(State(state)).await.unwrap().into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let payload: AggregationResponse = serde_json::from_slice(&body).unwrap();
        assert!(payload.status_lists.is_empty());
    }

    #[tokio::test]
    async fn test_aggregation_deduplicates_and_sorts() {
        let rows = vec![
            row_with_sub("https://example.com/statuslists/b"),
            row_with_sub("https://example.com/statuslists/a"),
            row_with_sub("https://example.com/statuslists/a"),
        ];
        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<BTreeMap<String, Value>, Vec<_>, _>(vec![rows])
                .into_connection(),
        );
        let state = test_app_state(Some(db_conn)).await;

        let response = get_aggregation(State(state)).await.unwrap().into_response();
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let payload: AggregationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload.status_lists,
            vec![
                "https://example.com/statuslists/a".to_string(),
                "https://example.com/statuslists/b".to_string(),
            ]
        );
    }
}
