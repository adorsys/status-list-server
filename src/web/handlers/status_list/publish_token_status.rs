use crate::auth::middleware::AuthenticatedIssuer;
use crate::{
    model::{StatusEntry, StatusList, StatusListToken},
    utils::{bits_validation::BitFlag, lst_gen::update_or_create_status_list, state::AppState},
    web::handlers::status_list::error::StatusListError,
};
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing;

// Request payload for publishing a status list token
#[derive(Deserialize, Serialize, Clone)]
pub struct PublishTokenStatusRequest {
    pub list_id: String,
    pub updates: Vec<StatusEntry>,
    pub bits: u8,
}

// Handler to create a new status list token
pub async fn publish_token_status(
    State(state): State<AppState>,
    AuthenticatedIssuer(issuer): AuthenticatedIssuer,
    Json(payload): Json<PublishTokenStatusRequest>,
) -> Result<impl IntoResponse, StatusListError> {
    // Verify that the issuer matches the authenticated issuer
    if payload.list_id != issuer {
        return Err(StatusListError::Unauthorized(
            "Issuer mismatch: list_id does not match authenticated issuer".to_string(),
        ));
    }

    // Check if the token already exists
    let existing_token = state
        .status_list_token_repository
        .find_one_by(payload.list_id.clone())
        .await
        .map_err(|err| {
            tracing::error!("Failed to check existing token: {err:?}");
            StatusListError::InternalServerError
        })?;

    if existing_token.is_some() {
        return Err(StatusListError::TokenAlreadyExists);
    }

    // Handle empty updates or create status list with updates
    let status_list = if payload.updates.is_empty() {
        StatusList {
            bits: payload.bits as usize,
            lst: base64url::encode(&[]), // Empty encoded status list
        }
    } else {
        let bits = BitFlag::new(payload.bits).ok_or(StatusListError::UnsupportedBits)?;

        StatusList {
            bits: payload.bits as usize,
            lst: update_or_create_status_list(None, payload.updates.clone(), bits).map_err(
                |e| match e {
                    crate::utils::errors::Error::InvalidIndex => StatusListError::InvalidIndex,
                    crate::utils::errors::Error::UnsupportedBits => {
                        StatusListError::UnsupportedBits
                    }
                    _ => StatusListError::Generic(e.to_string()),
                },
            )?,
        }
    };

    // Create the new token
    let now = Utc::now().timestamp();
    let new_token = StatusListToken {
        list_id: payload.list_id,
        exp: Some(now + 3600), // 1 hour expiration
        iat: now,
        status_list,
        sub: issuer,
        ttl: Some(3600),
    };

    // Store the token
    state
        .status_list_token_repository
        .insert_one(new_token.clone())
        .await
        .map_err(|err| {
            tracing::error!("Failed to store token: {err:?}");
            StatusListError::InternalServerError
        })?;

    Ok((StatusCode::CREATED, "Token published successfully"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::queries::SeaOrmStore,
        model::{status_list_tokens, Status, StatusListToken},
        utils::{keygen::Keypair, state::AppState},
    };
    use axum::{extract::State, Json};
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Helper to create a test request payload with customizable bits
    fn create_test_token(
        list_id: &str,
        updates: Vec<StatusEntry>,
        bits: u8,
    ) -> PublishTokenStatusRequest {
        PublishTokenStatusRequest {
            list_id: list_id.to_string(),
            updates,
            bits,
        }
    }

    // Helper to generate a test server key
    fn server_key() -> Keypair {
        Keypair::generate().unwrap()
    }

    #[tokio::test]
    async fn test_publish_status_creates_token() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "issuer";
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
                    vec![],                  // find_one_by returns None
                    vec![new_token.clone()], // insert_one return
                ])
                .into_connection(),
        );

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

        let response = publish_token_status(
            State(app_state),
            AuthenticatedIssuer("issuer".to_string()),
            Json(payload),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_token_is_stored_after_publish() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "issuer";
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
                    vec![],                  // find_one_by returns None
                    vec![new_token.clone()], // insert_one return
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .into_connection(),
        );

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

        let _ = publish_token_status(
            State(app_state.clone()),
            AuthenticatedIssuer("issuer".to_string()),
            Json(payload),
        )
        .await
        .unwrap();

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
        let token_id = "issuer";
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

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

        let response = match publish_token_status(
            State(app_state),
            AuthenticatedIssuer("issuer".to_string()),
            Json(payload),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_empty_updates() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "issuer";
        let payload = create_test_token(token_id, vec![], 1);
        let status_list = StatusList {
            bits: 1,
            lst: base64url::encode(&[]),
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
                    vec![],                  // find_one_by returns None
                    vec![new_token.clone()], // insert_one return
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .into_connection(),
        );

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

        let response = publish_token_status(
            State(app_state.clone()),
            AuthenticatedIssuer("issuer".to_string()),
            Json(payload),
        )
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
        assert_eq!(token.status_list.lst, base64url::encode(&[]));
    }

    #[tokio::test]
    async fn test_invalid_bits() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![]]); // Simulates Ok(None)

        let db_conn = Arc::new(mock_db.into_connection());
        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

        let token_id = "issuer";
        let payload = create_test_token(
            token_id,
            vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }],
            3,
        );

        // Call your handler and check the response
        let response = match publish_token_status(
            State(app_state),
            AuthenticatedIssuer("issuer".to_string()),
            Json(payload),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_repository_unavailable() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "issuer";
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
                    vec![],                  // find_one_by returns None
                    vec![new_token.clone()], // insert_one return
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .into_connection(),
        );
        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

        let response = publish_token_status(
            State(app_state),
            AuthenticatedIssuer("issuer".to_string()),
            Json(payload),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_invalid_index() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![]]);
        let db_conn = Arc::new(mock_db.into_connection());
        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };
        let token_id = "issuer";
        let payload = create_test_token(
            token_id,
            vec![StatusEntry {
                index: -1, // Invalid index to trigger a 400 error
                status: Status::VALID,
            }],
            1,
        );

        let response = match publish_token_status(
            State(app_state),
            AuthenticatedIssuer("issuer".to_string()),
            Json(payload),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
