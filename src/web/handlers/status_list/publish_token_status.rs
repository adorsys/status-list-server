use crate::{
    model::{StatusEntry, StatusList, StatusListToken},
    utils::{bits_validation::BitFlag, errors::Error, lst_gen::update_or_create_status_list, state::AppState},
    web::handlers::status_list::error::StatusListError,
};
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing;

// Request payload for publishing a status list token
#[derive(Deserialize, Serialize, Clone)]
pub struct PublishTokenStatusRequest {
    pub list_id: String,
    pub updates: Vec<StatusEntry>,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub ttl: Option<String>,
    pub bits: u8,
}

// Handler to create a new status list token
pub async fn publish_token_status(
    State(appstate): State<AppState>,
    Json(payload): Json<PublishTokenStatusRequest>,
) -> Result<impl IntoResponse, StatusListError> {
    // Ensure the repository is available
    let store = appstate
        .repository
        .as_ref()
        .ok_or(StatusListError::InternalServerError)?;

    let bitflag = if let Some(bits) = BitFlag::new(payload.bits) {
        Ok(bits)
    } else {
        Err(StatusListError::Generic(format!(
            "Invalid 'bits' value: {}. Allowed values are 1, 2, 4, 8.",
            payload.bits
        )))
    };
    let bits = bitflag?;

    // Generate the compressed status list; use empty encoding if no updates
    let lst = if payload.updates.is_empty() {
        base64url::encode([])
    } else {
        update_or_create_status_list(None, payload.updates, bits).map_err(|e| {
            tracing::error!("lst_from failed: {:?}", e);
            match e {
                Error::Generic(msg) => StatusListError::Generic(msg),
                Error::InvalidIndex => StatusListError::InvalidIndex,
                Error::UnsupportedBits => StatusListError::UnsupportedBits,
                _ => StatusListError::Generic(e.to_string()),
            }
        })?
    };

    // Check for existing token to prevent duplicates
    match store
        .status_list_token_repository
        .find_one_by(payload.list_id.clone())
        .await
    {
        Ok(Some(_)) => {
            tracing::info!("Status list {} already exists", payload.list_id);
            Err(StatusListError::StatusListAlreadyExists)
        }
        Ok(None) => {
            // Calculate issuance and expiration timestamps
            let iat = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let exp = match payload.ttl.as_ref() {
                Some(ttl) => match ttl.parse::<i64>() {
                    Ok(ttl_seconds) => Some(iat.saturating_add(ttl_seconds)),
                    Err(_) => {
                        return Err(StatusListError::Generic("Invalid TTL format".to_string()))
                    }
                },
                None => None,
            };

            // Build the new status list token
            let new_status_list_token = StatusListToken {
                list_id: payload.list_id.clone(),
                exp: exp.map(|e| e as i32),
                iat: iat as i32,
                status_list: StatusList {
                    bits: payload.bits as i8,
                    lst,
                },
                sub: payload.sub.unwrap_or_default(),
                ttl: payload.ttl,
            };

            // Insert the token into the repository
            store
                .status_list_token_repository
                .insert_one(new_status_list_token)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to insert token: {:?}", e);
                    StatusListError::InternalServerError
                })?;
            Ok(StatusCode::CREATED.into_response()) // Return 201 Created on success
        }
        Err(e) => {
            tracing::error!(error = ?e, list_id = ?payload.list_id, "Database query failed for status list.");
            Err(StatusListError::InternalServerError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::test_resources::setup::test_setup;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::RwLock;

    // Helper to create a test request payload with customizable bits
    fn create_test_token(
        list_id: &str,
        updates: Vec<StatusEntry>,
        bits: u8,
    ) -> PublishTokenStatusRequest {
        PublishTokenStatusRequest {
            list_id: list_id.to_string(),
            updates,
            sub: Some("issuer".to_string()),
            ttl: Some("3600".to_string()),
            bits,
        }
    }

    // Test successful token creation and insertion
    #[tokio::test]
    async fn test_successful_token_insertion() {
        let cred_repo = Arc::new(RwLock::new(HashMap::new()));
        let status_list_repo = Arc::new(RwLock::new(HashMap::new()));
        let app_state = test_setup(cred_repo, status_list_repo);
        let new_token_id = "token1";
        let payload = create_test_token(
            new_token_id,
            vec![
                StatusEntry {
                    index: 0,
                    status: Status::VALID,
                },
                StatusEntry {
                    index: 1,
                    status: Status::INVALID,
                },
            ],
            2,
        );

        let response = publish_token_status(State(app_state.clone()), Json(payload))
            .await
            .unwrap()
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
        let token = result.unwrap();
        assert_eq!(token.list_id, new_token_id);
        assert_eq!(token.status_list.bits, 2);
        assert_eq!(token.sub, "issuer");
        assert!(token.exp.is_some());
    }

    // Test conflict when inserting a duplicate token
    #[tokio::test]
    async fn test_token_conflict() {
        let cred_repo = Arc::new(RwLock::new(HashMap::new()));
        let status_list_repo = Arc::new(RwLock::new(HashMap::new()));
        let app_state = test_setup(cred_repo, status_list_repo);
        let token_id = "token1";
        let payload = create_test_token(
            token_id,
            vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }],
            1,
        );

        let first_response = publish_token_status(State(app_state.clone()), Json(payload.clone()))
            .await
            .unwrap()
            .into_response();
        assert_eq!(first_response.status(), StatusCode::CREATED);

        let second_response = match publish_token_status(State(app_state), Json(payload)).await {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(second_response.status(), StatusCode::CONFLICT);
    }

    // Test handling of empty updates
    #[tokio::test]
    async fn test_empty_updates() {
        let cred_repo = Arc::new(RwLock::new(HashMap::new()));
        let status_list_repo = Arc::new(RwLock::new(HashMap::new()));
        let app_state = test_setup(cred_repo, status_list_repo);
        let token_id = "token_empty";
        let payload = create_test_token(token_id, vec![], 1);

        let response = publish_token_status(State(app_state.clone()), Json(payload))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let repository = app_state
            .repository
            .as_ref()
            .unwrap()
            .status_list_token_repository
            .clone();
        let result = repository.find_one_by(token_id.to_string()).await.unwrap();
        assert!(result.is_some());
        let token = result.unwrap();
        assert_eq!(token.list_id, token_id);
        assert_eq!(token.status_list.lst, base64url::encode([]));
    }

    // Test rejection of invalid bits values
    #[tokio::test]
    async fn test_invalid_bits() {
        let cred_repo = Arc::new(RwLock::new(HashMap::new()));
        let status_list_repo = Arc::new(RwLock::new(HashMap::new()));
        let app_state = test_setup(cred_repo, status_list_repo);
        let token_id = "token_invalid_bits";
        let payload = create_test_token(
            token_id,
            vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }],
            3, // Invalid bits value
        );

        let response = match publish_token_status(State(app_state), Json(payload)).await {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // Test error when repository is unavailable
    #[tokio::test]
    async fn test_repository_unavailable() {
        let app_state = AppState { repository: None };
        let token_id = "token_no_repo";
        let payload = create_test_token(
            token_id,
            vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }],
            1,
        );

        let response = match publish_token_status(State(app_state), Json(payload)).await {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Test rejection of invalid index in updates
    #[tokio::test]
    async fn test_invalid_index() {
        let cred_repo = Arc::new(RwLock::new(HashMap::new()));
        let status_list_repo = Arc::new(RwLock::new(HashMap::new()));
        let app_state = test_setup(cred_repo, status_list_repo);
        let token_id = "token_invalid_index";
        let payload = create_test_token(
            token_id,
            vec![StatusEntry {
                index: -1,
                status: Status::VALID,
            }],
            1,
        );

        let response = match publish_token_status(State(app_state), Json(payload)).await {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
