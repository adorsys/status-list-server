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
    let records = state.status_list_repo.find_all().await.map_err(|e| {
        tracing::error!("Failed to fetch status lists for aggregation: {e:?}");
        StatusListError::InternalServerError
    })?;

    let mut status_lists: Vec<String> = records.into_iter().map(|r| r.sub).collect();
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
    use crate::{
        models::{StatusList, StatusListRecord, status_lists},
        test_utils::test_app_state,
    };
    use axum::{body::to_bytes, response::IntoResponse};
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::sync::Arc;

    fn record(list_id: &str, sub: &str) -> StatusListRecord {
        StatusListRecord {
            list_id: list_id.to_string(),
            issuer: "issuer".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "lst".to_string(),
                aggregation_uri: None,
            },
            sub: sub.to_string(),
        }
    }

    #[tokio::test]
    async fn test_aggregation_returns_all_list_uris() {
        let records = vec![
            record("a", "https://example.com/statuslists/a"),
            record("b", "https://example.com/statuslists/b"),
        ];
        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![records])
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
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![Vec::<
                    status_lists::Model,
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
        let records = vec![
            record("b", "https://example.com/statuslists/b"),
            record("a", "https://example.com/statuslists/a"),
            record("a-dup", "https://example.com/statuslists/a"),
        ];
        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![records])
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
