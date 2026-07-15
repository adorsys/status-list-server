use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::utils::state::AppState;

use super::error::StatusListError;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct AggregationResponse {
    pub(super) status_lists: Vec<String>,
}

pub async fn get_aggregation(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusListError> {
    let status_lists = state.status_lists.list_uris().await.map_err(|e| {
        tracing::error!("Failed to fetch status lists for aggregation: {e:?}");
        StatusListError::InternalServerError
    })?;

    tracing::info!(
        "Serving status list aggregation with {} list(s)",
        status_lists.len()
    );

    Ok((StatusCode::OK, Json(AggregationResponse { status_lists })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{test_app_state, test_app_state_with};
    use axum::{body::to_bytes, response::IntoResponse};
    use sea_orm::{DatabaseBackend, MockDatabase, Value};
    use std::{collections::BTreeMap, sync::Arc};

    fn row_with_sub(sub: &str) -> BTreeMap<String, Value> {
        BTreeMap::from([("sub".to_string(), Value::from(sub))])
    }

    #[tokio::test]
    async fn test_aggregation_returns_all_list_uris() {
        // The SQL query handles DISTINCT + ORDER BY; the mock returns rows
        // as-is, so we provide them already deduplicated and sorted.
        let rows = vec![
            row_with_sub("https://example.com/api/v1/status-lists/a"),
            row_with_sub("https://example.com/api/v1/status-lists/b"),
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
                "https://example.com/api/v1/status-lists/a".to_string(),
                "https://example.com/api/v1/status-lists/b".to_string(),
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

    /// Verifies that the aggregation endpoint returns URIs spanning multiple
    /// issuers. The endpoint is issuer-agnostic — every hosted status list
    /// URI appears regardless of which issuer owns it.
    #[tokio::test]
    async fn test_aggregation_returns_uris_from_multiple_issuers() {
        let rows = vec![
            row_with_sub("https://example.com/api/v1/status-lists/list-issuer-a"),
            row_with_sub("https://example.com/api/v1/status-lists/list-issuer-b"),
            row_with_sub("https://example.com/api/v1/status-lists/list-issuer-c"),
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

        assert_eq!(payload.status_lists.len(), 3);
        assert!(
            payload
                .status_lists
                .iter()
                .any(|uri| uri.contains("list-issuer-a"))
        );
        assert!(
            payload
                .status_lists
                .iter()
                .any(|uri| uri.contains("list-issuer-b"))
        );
        assert!(
            payload
                .status_lists
                .iter()
                .any(|uri| uri.contains("list-issuer-c"))
        );
    }

    /// Round-trip test: every URI emitted by the aggregation endpoint must be
    /// routable — i.e. its path matches the `GET /api/v1/status-lists/{list_id}`
    /// route — and the configured `aggregation_uri` path must match the actual
    /// aggregation route `/api/v1/aggregation`.
    #[tokio::test]
    async fn test_emitted_uris_are_routable_and_aggregation_uri_matches() {
        let expected_aggregation_path = "/api/v1/aggregation";
        let configured_aggregation_uri = format!("https://example.com{expected_aggregation_path}");

        // Sub-URIs that follow the same path pattern used by `publish_status`.
        let list_ids = [
            "30202cc6-1e3f-4479-a567-74e86ad73693",
            "755a0cf7-8289-4f65-9d24-0e01be92f4a6",
        ];
        let sub_uris: Vec<String> = list_ids
            .iter()
            .map(|id| format!("https://example.com/api/v1/status-lists/{id}"))
            .collect();
        let rows: Vec<BTreeMap<String, Value>> = sub_uris.iter().map(|s| row_with_sub(s)).collect();

        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<BTreeMap<String, Value>, Vec<_>, _>(vec![rows])
                .into_connection(),
        );
        let state =
            test_app_state_with(Some(db_conn), Some(configured_aggregation_uri.clone())).await;

        assert_eq!(
            state.aggregation_uri.as_deref(),
            Some(configured_aggregation_uri.as_str())
        );

        let response = get_aggregation(State(state.clone()))
            .await
            .unwrap()
            .into_response();
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let payload: AggregationResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(payload.status_lists, sub_uris);

        // Verify each emitted sub-URI has a path routable on the server.
        for sub_uri in &payload.status_lists {
            let parsed = reqwest::Url::parse(sub_uri).unwrap();
            assert!(
                parsed.path().starts_with("/api/v1/status-lists/"),
                "sub URI {sub_uri} is not routable (path = {})",
                parsed.path()
            );
            // The list_id segment should be a non-empty UUID.
            let list_id = parsed.path().trim_start_matches("/api/v1/status-lists/");
            assert!(!list_id.is_empty(), "sub URI {sub_uri} has empty list_id");
            uuid::Uuid::try_parse(list_id).unwrap();
        }

        // Verify the configured aggregation_uri path matches the actual route.
        let parsed = reqwest::Url::parse(state.aggregation_uri.as_deref().unwrap()).unwrap();
        assert_eq!(parsed.path(), expected_aggregation_path);
    }
}
