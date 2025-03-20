use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::Value;

use crate::{
    model::{Status, StatusList, StatusListToken, StatusUpdate},
    utils::state::AppState,
};

use super::{constants::STATUS_LISTS_HEADER_JWT, error::StatusListError};

// Get status list information
pub async fn handle_status_list_retrieval(
    State(state): State<Arc<AppState>>,
    Path(list_id): Path<i32>,
    headers: HeaderMap,
) -> Result<StatusList, StatusListError> {
    // check the persistence layer
    let repo = state.repository.as_ref().ok_or_else(|| {
        tracing::error!("Repository is unavailable");
        StatusListError::InternalServerError
    })?;

    // Validate accept header
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or(STATUS_LISTS_HEADER_JWT);

    if !accept.contains(STATUS_LISTS_HEADER_JWT) {
        return Err(StatusListError::InvalidAcceptHeader);
    }

    // Get status list claims from database
    let status_claims = repo
        .status_list_token_repository
        .find_one_by(list_id.to_string())
        .await
        .map_err(|err| {
            tracing::error!("Failed to get status list {list_id} from database: {err:?}");
            StatusListError::InternalServerError
        })?
        .ok_or(StatusListError::StatusListNotFound)?;

    Ok(status_claims.status_list)
}

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
                StatusListError::MalformedBody(
                    "Request body must contain a valid 'updates' array".to_string(),
                ),
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
                StatusListError::MalformedBody(
                    "Request body must contain a valid 'updates' array".to_string(),
                ),
            )
                .into_response();
        }
    };

    // Ensure repository exists
    let store = match &appstate.repository {
        Some(store) => store,
        None => {
            tracing::error!("Repository is unavailable");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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
                StatusListError::StatusListNotFound.to_string(),
            )
                .into_response();
        }
    };
    if let Some(status_list_token) = status_list_token {
        let lst = status_list_token.status_list.lst.clone();

        // Apply updates

        let updated_lst = match update_status(&lst, updates) {
            Ok(updated_lst) => updated_lst,
            Err(e) => {
                tracing::error!("Status update failed: {:?}", e);
                return match e {
                    StatusListError::InvalidIndex => {
                        (StatusCode::BAD_REQUEST, "Invalid index").into_response()
                    }
                    _ => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        StatusListError::UpdateFailed.to_string(),
                    )
                        .into_response(),
                };
            }
        };

        // Construct the new status list token
        let status_list = StatusList {
            bits: status_list_token.status_list.bits,
            lst: updated_lst,
        };

        let list_id = status_list_token.list_id;
        let statuslisttoken = StatusListToken::new(
            list_id.clone(),
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
                (
                    StatusCode::BAD_REQUEST,
                    StatusListError::UpdateFailed.to_string(),
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database update failed").into_response()
            }
        }
    } else {
        (StatusCode::NOT_FOUND, "Status list not found").into_response()
    }
}

fn encode_lst(bits: Vec<u8>) -> String {
    let encoded = base64url::encode(
        bits.iter()
            .flat_map(|&n| n.to_be_bytes())
            .collect::<Vec<u8>>(),
    );
    encoded
}

fn update_status(lst: &str, updates: Vec<StatusUpdate>) -> Result<String, StatusListError> {
    let mut decoded_lst =
        base64url::decode(lst).map_err(|e| StatusListError::Generic(e.to_string()))?;

    for update in updates {
        let index = update.index as usize;
        if index >= decoded_lst.len() {
            return Err(StatusListError::InvalidIndex);
        }

        decoded_lst[index] = match update.status {
            Status::VALID => 0,
            Status::INVALID => 1,
            Status::SUSPENDED => 2,
            Status::APPLICATIONSPECIFIC => 3,
        };
    }

    Ok(encode_lst(decoded_lst))
}

#[cfg(test)]
mod test {

    use super::*;
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };

    use axum::{body::Body, extract::Request, routing::put, Router};
    use base64url::encode;
    use hyper::StatusCode;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::{
        model::{Credentials, StatusList, StatusListToken},
        test_resources::setup::test_setup,
        utils::state::AppState,
    };

    pub fn setup() -> (AppState, Arc<RwLock<HashMap<String, StatusListToken>>>) {
        let mut mock_statustk_repo = HashMap::new();
        let mock_credential_repo: HashMap<String, Credentials> = HashMap::new();

        let status = vec![2, 1, 3, 1];
        let lst = encode(status);

        let list_id = "test_list_id".to_string();
        let existing_status_list = StatusList { bits: 1, lst };

        let existing_token = StatusListToken::new(
            list_id.clone(),
            Some(123456789),
            123456000,
            existing_status_list,
            "test_sub".to_string(),
            Some("3600".to_string()),
        );

        // store the token
        mock_statustk_repo.insert(list_id.clone(), existing_token);
        let shared_statustk_repo = Arc::new(RwLock::new(mock_statustk_repo));

        let appstate = test_setup(
            Arc::new(RwLock::new(mock_credential_repo)),
            shared_statustk_repo.clone(),
        );
        (appstate, shared_statustk_repo)
    }

    #[tokio::test]
    async fn test_update_statuslist() {
        let appstate = setup();

        let app = Router::new()
            .route("/statuslist/{issuer}", put(update_statuslist))
            .with_state(Arc::new(appstate.0));

        // JSON request body
        let body = json!({
        "updates": [
            { "index": 1, "status": "VALID" },
            { "index": 3, "status": "INVALID" }
            ]
        });
        let updated_lst = vec![2, 0, 3, 1];
        let expected_lst = encode(updated_lst);

        let list_id = "test_list_id".to_string();
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
        let shared_lst = appstate
            .1
            .read()
            .unwrap()
            .get(&list_id)
            .unwrap()
            .status_list
            .lst
            .clone();

        // assert the lst has been updated
        assert_eq!(shared_lst, expected_lst);
    }

    #[tokio::test]
    async fn test_malformed_body() {
        let appstate = setup();

        let app = Router::new()
            .route("/statuslist/{issuer}", put(update_statuslist))
            .with_state(Arc::new(appstate.0));

        // JSON request body
        let bad_body = json!({
        "updates": [
            { "index": 1, "status": "VALID" },
            { "index": 3, "status": "UNKNOWSTATUS" }
            ]
        });

        let list_id = "test_list_id".to_string();
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/statuslist/{}", list_id))
            .header("Content-Type", "application/json")
            .body(Body::from(bad_body.to_string()))
            .unwrap();

        // Send request
        let response = app.oneshot(request).await.unwrap();

        // Check response status
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
