use crate::{
    model::{StatusEntry, StatusList, StatusListToken},
    utils::{
        bits_validation::BitFlag, errors::Error, lst_gen::update_or_create_status_list,
        state::AppState,
    },
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
    pub ttl: Option<i64>,
    pub bits: u8,
}

// Handler to create a new status list token
pub async fn publish_token_status(
    State(appstate): State<AppState>,
    Json(payload): Json<PublishTokenStatusRequest>,
) -> Result<impl IntoResponse, StatusListError> {
    let store = &appstate.status_list_token_repository;

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
    match store.find_one_by(payload.list_id.clone()).await {
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
            let exp = payload.ttl.map(|ttl| iat.saturating_add(ttl));

            // Serialize the status list before constructing the token
            let status_list = StatusList {
                bits: payload.bits as usize,
                lst,
            };

            // Build the new status list token
            let new_status_list_token = StatusListToken {
                list_id: payload.list_id.clone(),
                exp,
                iat,
                status_list,
                sub: payload.sub.unwrap_or_default(),
                ttl: payload.ttl,
            };

            // Insert the token into the repository
            store.insert_one(new_status_list_token).await.map_err(|e| {
                tracing::error!("Failed to insert token: {:?}", e);
                StatusListError::InternalServerError
            })?;
            Ok(StatusCode::CREATED.into_response())
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
    use crate::utils::state::MockSecretCache;
    use crate::{
        database::queries::SeaOrmStore,
        model::{status_list_tokens, Status, StatusListToken},
        utils::state::AppState,
    };
    use axum::{extract::State, Json};
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::sync::Arc;

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
            ttl: Some(3600),
            bits,
        }
    }

    // Helper to generate a test server key
    // Note: It does nothing, it's just use to build the AppState
    // fn server_key() -> Keypair {
    //     Keypair::generate().unwrap()
    // }

    fn test_app_state(db_conn: Arc<sea_orm::DatabaseConnection>) -> AppState {
        AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            secret_cache: Arc::new(MockSecretCache {
                value: Some("test-key".to_string()),
            }),
            server_secret_name: "test-server-key".to_string(),
        }
    }

    #[tokio::test]
    async fn test_publish_status_creates_token() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token1";
        let payload = create_test_token(
            token_id,
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
        let bits = BitFlag::new(2).unwrap();
        let status_list = StatusList {
            bits: 2,
            lst: update_or_create_status_list(None, payload.updates.clone(), bits).unwrap(),
        };
        let new_token = StatusListToken {
            list_id: token_id.to_string(),
            exp: Some(
                (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64)
                    .saturating_add(3600),
            ),
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            status_list,
            sub: "issuer".to_string(),
            ttl: Some(3600),
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // insert_one return
                ])
                .into_connection(),
        );

        let app_state = test_app_state(db_conn.clone());

        let response = publish_token_status(State(app_state), Json(payload))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_token_is_stored_after_publish() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token1";
        let payload = create_test_token(
            token_id,
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
        let bits = BitFlag::new(2).unwrap();

        let status_list = StatusList {
            bits: 2,
            lst: update_or_create_status_list(None, payload.updates.clone(), bits).unwrap(),
        };
        let new_token = StatusListToken {
            list_id: token_id.to_string(),
            exp: Some(
                (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64)
                    .saturating_add(3600),
            ),
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            status_list,
            sub: "issuer".to_string(),
            ttl: Some(3600),
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // insert_one return
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .into_connection(),
        );

        let app_state = test_app_state(db_conn.clone());

        // Perform the insertion
        let _ = publish_token_status(State(app_state.clone()), Json(payload))
            .await
            .unwrap();

        // Verify the token is stored
        let result = app_state
            .status_list_token_repository
            .find_one_by(token_id.to_string())
            .await
            .unwrap();
        assert!(result.is_some());
        let token = result.unwrap();
        assert_eq!(token.list_id, token_id);
        assert_eq!(token.status_list.bits, 2);
        assert_eq!(token.sub, "issuer");
        assert!(token.exp.is_some());
    }

    #[tokio::test]
    async fn test_token_conflict() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token1";
        let payload = create_test_token(
            token_id,
            vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }],
            1,
        );
        let bits = BitFlag::new(2).unwrap();

        let existing_token = StatusListToken {
            list_id: token_id.to_string(),
            exp: None,
            iat: 1234567890,
            status_list: StatusList {
                bits: 1,
                lst: update_or_create_status_list(None, payload.updates.clone(), bits).unwrap(),
            },
            sub: "issuer".to_string(),
            ttl: Some(3600),
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![
                    existing_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(db_conn.clone());

        let response = match publish_token_status(State(app_state), Json(payload)).await {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_empty_updates() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token_empty";
        let payload = create_test_token(token_id, vec![], 1);
        let status_list = StatusList {
            bits: 1,
            lst: base64url::encode([]),
        };
        let new_token = StatusListToken {
            list_id: token_id.to_string(),
            exp: Some(
                (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64)
                    .saturating_add(3600),
            ),
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            status_list,
            sub: "issuer".to_string(),
            ttl: Some(3600),
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // insert_one return
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .into_connection(),
        );

        let app_state = test_app_state(db_conn.clone());

        let response = publish_token_status(State(app_state.clone()), Json(payload))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let result = app_state
            .status_list_token_repository
            .find_one_by(token_id.to_string())
            .await
            .unwrap();
        assert!(result.is_some());
        let token = result.unwrap();
        assert_eq!(token.list_id, token_id);
        assert_eq!(token.status_list.lst, base64url::encode([]));
    }

    #[tokio::test]
    async fn test_invalid_bits() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let db_conn = Arc::new(mock_db.into_connection());
        let app_state = test_app_state(db_conn.clone());
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

    #[tokio::test]
    async fn test_repository_unavailable() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token_no_repo";
        let payload = create_test_token(
            token_id,
            vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }],
            1,
        );
        let bits = BitFlag::new(2).unwrap();

        let status_list = StatusList {
            bits: 1,
            lst: update_or_create_status_list(None, payload.updates.clone(), bits).unwrap(),
        };
        let new_token = StatusListToken {
            list_id: token_id.to_string(),
            exp: Some(
                (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64)
                    .saturating_add(3600),
            ),
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            status_list,
            sub: "issuer".to_string(),
            ttl: Some(3600),
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // insert_one return
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .into_connection(),
        );
        let app_state = test_app_state(db_conn.clone());

        let response = publish_token_status(State(app_state), Json(payload))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_invalid_index() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token_invalid_index";
        let payload = create_test_token(
            token_id,
            vec![StatusEntry {
                index: -1,
                status: Status::VALID,
            }],
            1,
        );
        let db_conn = Arc::new(mock_db.into_connection());
        let app_state = test_app_state(db_conn.clone());

        let response = match publish_token_status(State(app_state), Json(payload)).await {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
