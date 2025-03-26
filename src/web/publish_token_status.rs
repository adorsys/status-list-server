use crate::{model::StatusListToken, utils::state::AppState};
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone)]
pub struct PublishTokenStatusRequest {
    pub list_id: String,
    pub status_list: StatusListToken,
}

pub async fn publish_token_status(
    State(appstate): State<AppState>,
    Json(payload): Json<PublishTokenStatusRequest>,
) -> impl IntoResponse {
    // Validate that list_id in request matches list_id in status_list
    if payload.list_id != payload.status_list.list_id {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let store = match &appstate.repository {
        Some(store) => store,
        None => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Check if the token already exists
    match store
        .status_list_token_repository
        .find_one_by(payload.list_id.clone())
        .await
    {
        Ok(Some(_)) => {
            // Token already exists
            return StatusCode::CONFLICT.into_response();
        }
        Ok(None) => {
            // Proceed to insert the new token
            match store
                .status_list_token_repository
                .insert_one(payload.status_list)
                .await
            {
                Ok(_) => StatusCode::CREATED.into_response(),
                Err(e) => {
                    eprintln!("Failed to insert token: {:?}", e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::{collections::HashMap, sync::RwLock};

    use axum::extract::State;
    use axum::response::IntoResponse;
    use axum::Json;
    use hyper::StatusCode;

    use crate::model::{StatusList, StatusListToken};
    use crate::test_resources::setup::test_setup;
    use crate::web::publish_token_status::{publish_token_status, PublishTokenStatusRequest};

    // Helper function to create a test token
    fn create_test_token(list_id: &str, sub: &str) -> PublishTokenStatusRequest {
        PublishTokenStatusRequest {
            list_id: list_id.to_string(),
            status_list: StatusListToken {
                list_id: list_id.to_string(),
                exp: Some(1735689600),
                iat: 1704067200,
                status_list: StatusList {
                    bits: 1,
                    lst: "list".to_string(),
                },
                sub: sub.to_string(),
                ttl: Some("3600".to_string()),
            },
        }
    }

    #[tokio::test]
    //test if the token is inserted
    async fn test_successful_token_insertion() {
        let cred_repo = Arc::new(RwLock::new(HashMap::new()));
        let status_list_repo: Arc<RwLock<HashMap<String, StatusListToken>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let app_state = test_setup(cred_repo, status_list_repo);
        let new_token_id = "token1";
        let payload = create_test_token(new_token_id, "test-issuer12");

        let response = publish_token_status(State(app_state.clone()), Json(payload.clone()))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::CREATED);

        let repository = app_state
            .repository
            .as_ref()
            .unwrap()
            .status_list_token_repository
            .clone();
        let result = repository
            .find_one_by(new_token_id.to_string())
            .await
            .unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().list_id, new_token_id.to_string());
    }

    #[tokio::test]
    // if the token already exist then we should hava conflict
    async fn test_token_conflict() {
        let cred_repo = Arc::new(RwLock::new(HashMap::new()));
        let status_list_repo = Arc::new(RwLock::new(HashMap::new()));
        let app_state = test_setup(cred_repo, status_list_repo);
        let token_id = "token1";
        let payload = create_test_token(token_id, "test-issuer12");

        let first_response = publish_token_status(State(app_state.clone()), Json(payload.clone()))
            .await
            .into_response();
        assert_eq!(first_response.status(), StatusCode::CREATED);

        let second_response = publish_token_status(State(app_state), Json(payload))
            .await
            .into_response();

        assert_eq!(second_response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    // try inserting another token
    async fn test_different_token_insertion() {
        let cred_repo = Arc::new(RwLock::new(HashMap::new()));
        let status_list_repo = Arc::new(RwLock::new(HashMap::new()));
        let app_state = test_setup(cred_repo, status_list_repo);

        let first_token_id = "token1";
        let first_payload = create_test_token(first_token_id, "test-issuer12");

        let second_token_id = "token2";
        let second_payload = create_test_token(second_token_id, "test-issuer122");

        let first_response = publish_token_status(State(app_state.clone()), Json(first_payload))
            .await
            .into_response();
        assert_eq!(first_response.status(), StatusCode::CREATED);

        let second_response = publish_token_status(State(app_state.clone()), Json(second_payload))
            .await
            .into_response();

        assert_eq!(second_response.status(), StatusCode::CREATED);

        let repository = app_state
            .repository
            .as_ref()
            .unwrap()
            .status_list_token_repository
            .clone();

        let first_result = repository
            .find_one_by(first_token_id.to_string())
            .await
            .unwrap();
        assert!(first_result.is_some());
        assert_eq!(first_result.unwrap().list_id, first_token_id.to_string());

        let second_result = repository
            .find_one_by(second_token_id.to_string())
            .await
            .unwrap();
        assert!(second_result.is_some());
        assert_eq!(second_result.unwrap().list_id, second_token_id.to_string());
    }
}
