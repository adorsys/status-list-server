use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use hyper::StatusCode;
use serde_json::Value;
use std::sync::Arc;

use crate::{
    database::repository::Repository,
    model::{Status, StatusList, StatusListToken, StatusUpdate},
    utils::state::AppState,
};

use super::error::StatusError;

#[axum::debug_handler]
pub async fn update_statuslist(
    State(appstate): State<Arc<AppState>>,
    Path(list_id): Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let updates = match body
        .as_object()
        .and_then(|body| body.get("updates"))
        .and_then(|statuslist| statuslist.as_array())
    {
        Some(updates) => updates,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                StatusError::MalformedBody.to_string(),
            )
                .into_response();
        }
    };

    let updates_json = match serde_json::to_vec(updates) {
        Ok(json) => json,
        Err(e) => {
            tracing::error!("Failed to serialize updates: {e}");
            return (StatusCode::BAD_REQUEST, "Failed to serialize request body").into_response();
        }
    };

    let updates: Vec<StatusUpdate> = match serde_json::from_slice(&updates_json) {
        Ok(updates) => updates,
        Err(e) => {
            tracing::error!("Malformed request body: {e}");
            return (
                StatusCode::BAD_REQUEST,
                StatusError::MalformedBody.to_string(),
            )
                .into_response();
        }
    };

    // Ensure repository exists
    let store = match &appstate.repository {
        Some(store) => store,
        None => {
            tracing::error!("Repository is unavailable");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Repository unavailable").into_response();
        }
    };

    // Fetch the status list token from the database
    let status_list_token = match store
        .status_list_token_repository
        .find_one_by(list_id.clone())
        .await
    {
        Ok(token) => token,
        Err(_) => {
            tracing::error!("Status list not found: {}", list_id);
            return (
                StatusCode::NOT_FOUND,
                StatusError::StatusListNotFound.to_string(),
            )
                .into_response();
        }
    };

    let mut lst = status_list_token.status_list.lst.clone();

    // Apply updates
    for update in updates {
        lst = match update_status(&lst, update) {
            Ok(updated_lst) => updated_lst,
            Err(e) => {
                tracing::error!("Status update failed: {:?}", e);
                return match e {
                    StatusError::InvalidIndex => {
                        (StatusCode::BAD_REQUEST, "Invalid index").into_response()
                    }
                    _ => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        StatusError::UpdateFailed.to_string(),
                    )
                        .into_response(),
                };
            }
        };
    }

    // Construct the new status list token
    let status_list = StatusList {
        bits: status_list_token.status_list.bits.clone(),
        lst,
    };

    let statuslisttoken = StatusListToken::new(
        status_list_token.exp,
        status_list_token.iat,
        status_list,
        status_list_token.sub.clone(),
        status_list_token.ttl.clone(),
    );

    // Store updated list in the database
    match store
        .status_list_token_repository
        .update_one(list_id.clone(), statuslisttoken)
        .await
    {
        Ok(true) => StatusCode::ACCEPTED.into_response(),
        Ok(false) => {
            tracing::error!("Failed to update status list");
            (StatusCode::CONFLICT, StatusError::UpdateFailed.to_string()).into_response()
        }
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Database update failed").into_response()
        }
    }
}

fn encode_lst(bits: Vec<i32>) -> String {
    base64url::encode(
        &bits
            .iter()
            .flat_map(|&n| n.to_be_bytes())
            .collect::<Vec<u8>>(),
    )
}

pub fn update_status(lst: &str, updates: StatusUpdate) -> Result<String, StatusError> {
    let decoded_lst = base64url::decode(lst).map_err(|e| StatusError::Generic(e.to_string()))?;

    let mut bits: Vec<i32> = decoded_lst.iter().map(|&b| b as i32).collect();

    let index = updates.index as usize;
    if index >= bits.len() {
        return Err(StatusError::InvalidIndex);
    }

    bits[index] = match updates.status {
        Status::VALID => 0,
        Status::INVALID => 1,
        Status::SUSPENDED => 2,
        Status::APPLICATIONSPECIFIC => 3,
    };

    Ok(encode_lst(bits))
}

#[cfg(test)]
#[tokio::test]
async fn test_update_statuslist() {
    use std::{collections::HashMap, sync::RwLock};
    struct AppState {
        repository: Option<HashMap<String, StatusListToken>>,
    }

    use axum::{body::Body, routing::put, Router};
    use base64url::encode;
    use hyper::Request;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::model::Credentials;

    let mut mock_repo = HashMap::new();
    let mock_credential_repo: HashMap<String, Credentials> = HashMap::new();

    let status = vec![1, 0, 3, 3];
    let lst = encode(status);

    let list_id = "test_list_id".to_string();
    let existing_status_list = StatusList { bits: 1, lst };

    let existing_token = StatusListToken::new(
        list_id,
        Some(123456789), // exp
        123456000,       // iat
        existing_status_list,
        "test_sub".to_string(),
        Some("3600".to_string()), // ttl
    );

    // store the token
    mock_repo.insert(list_id, existing_token);

    let app_state = <dyn Repository>::from(RwLock::new(mock_credential_repo), RwLock::new(mock_repo));

    let app = Router::new()
        .route("/statuslist/:list_id", put(update_statuslist))
        .with_state(app_state);

    // JSON request body
    let body = json!({
        "updates": [
            { "index": 2, "status": "VALID" },
            { "index": 0, "status": "INVALID" }
        ]
    });

    let request = Request::builder()
        .method("PUT")
        .uri(format!("/statuslist/{}", list_id))
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    // Send request
    let response = app.oneshot(request).await.unwrap();

    // Check response status
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}
