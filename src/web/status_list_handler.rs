use crate::utils::state::AppState;
use axum::body::Body;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

pub async fn get_status_list(
    State(state): State<AppState>,
    Path(status_list_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let status_list_id = status_list_id.trim().to_string();
    tracing::debug!("Normalized status_list_id: {:?}", status_list_id);

    let store = match &state.repository {
        Some(repo) => repo,
        None => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "".to_string()));
        }
    };

    match store
        .status_list_token_repository
        .find_one_by(status_list_id.clone())
        .await
    {
        Ok(Some(status_list)) => {
            let json_body = serde_json::to_string(&status_list).unwrap();

            Ok((StatusCode::OK, Body::from(json_body)).into_response())
        }
        Ok(None) => {
            tracing::warn!(
                "No status list found for status_list_id: {}",
                status_list_id
            );
            Err((StatusCode::NOT_FOUND, "Status list not found".to_string()))
        }
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

#[tokio::test]
async fn test_get_status_list() {
    use crate::model::StatusList;
    use crate::model::StatusListToken;
    use crate::test_resources::setup::test_setup;
    use axum::body::to_bytes;
    use axum::{extract::State, http::StatusCode};
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };

    // Create a mock repository
    let mut status_list_repo = HashMap::new();
    let test_status_list_id = "test-id".to_string();
    let test_status_list = StatusListToken {
        exp: Some(1735689600),
        iat: 1704067200,
        status_list: StatusList {
            bits: 1,
            lst: "list".to_string(),
        },
        sub: "test-issuer12".to_string(),
        ttl: Some("3600".to_string()),
        list_id: "boris".to_string(),
    };

    status_list_repo.insert(test_status_list_id.clone(), test_status_list);
    let app_state = test_setup(
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(RwLock::new(status_list_repo)),
    );

    // Call the function with a mock state and test path
    let response = get_status_list(
        State(app_state),
        axum::extract::Path(test_status_list_id.clone()),
    )
    .await
    .unwrap()
    .into_response();

    // Validate response
    assert_eq!(response.status(), StatusCode::OK);

    // Extract body
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(body_str.contains("test-issuer12"));
}
