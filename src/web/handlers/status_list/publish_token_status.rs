use crate::{
    model::{StatusList, StatusListToken, StatusRequest},
    utils::{errors::Error, lst_gen::create_status_list, state::AppState},
    web::handlers::status_list::error::StatusListError,
    web::midlw::AuthenticatedIssuer,
};
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing;

// Handler to create a new status list token
pub async fn publish_token_status(
    State(appstate): State<AppState>,
    AuthenticatedIssuer(issuer): AuthenticatedIssuer,
    Json(payload): Json<StatusRequest>,
) -> Result<impl IntoResponse, StatusListError> {
    let store = &appstate.status_list_token_repository;

    let stl = create_status_list(payload.status).map_err(|e| {
        tracing::error!("lst_from failed: {:?}", e);
        match e {
            Error::Generic(msg) => StatusListError::Generic(msg),
            Error::InvalidIndex => StatusListError::InvalidIndex,
            Error::UnsupportedBits => StatusListError::UnsupportedBits,
            _ => StatusListError::Generic(e.to_string()),
        }
    })?;

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

            // Serialize the status list before constructing the token
            let status_list = StatusList {
                bits: stl.bits,
                lst: stl.lst,
            };

            // TODO: This field is used elsewhere to link status list tokens
            // to issuers, hence the existence of a Foreign Key. We'll maybe
            // have to switch to another field for this purpose.
            //
            // let sub = format!(
            //     "https://{}/statuslist/{}",
            //     appstate.server_public_domain, payload.list_id
            // );
            let sub = issuer.clone();

            // Build the new status list token
            let new_status_list_token = StatusListToken {
                list_id: payload.list_id.clone(),
                issuer,
                exp: None,
                iat,
                status_list,
                sub,
                ttl: None,
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
    use crate::{
        model::{status_list_tokens, Status, StatusEntry, StatusListToken},
        test_resources::helper::publish_test_token,
        test_utils::test::test_app_state,
    };
    use axum::{extract::State, Json};
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_publish_status_creates_token() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token1";
        let payload = publish_test_token(
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
        );

        let status_list = StatusList {
            bits: 2,
            lst: create_status_list(payload.status.clone()).unwrap().lst,
        };
        let new_token = StatusListToken {
            list_id: token_id.to_string(),
            issuer: "issuer".to_string(),
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
        let token_id = "token1";
        let payload = publish_test_token(
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
        );

        let status_list = StatusList {
            bits: 2,
            lst: create_status_list(payload.status.clone()).unwrap().lst,
        };
        let new_token = StatusListToken {
            list_id: token_id.to_string(),
            issuer: "issuer".to_string(),
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
        let _ = publish_token_status(
            State(app_state.clone()),
            AuthenticatedIssuer("issuer".to_string()),
            Json(payload),
        )
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
        let payload = publish_test_token(
            token_id,
            vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }],
        );

        let existing_token = StatusListToken {
            list_id: token_id.to_string(),
            issuer: "issuer".to_string(),
            exp: None,
            iat: 1234567890,
            status_list: StatusList {
                bits: 1,
                lst: create_status_list(payload.status.clone()).unwrap().lst,
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
        let token_id = "token_empty";
        let payload = publish_test_token(token_id, vec![]);
        let status_list = StatusList {
            bits: 1,
            lst: base64url::encode([]),
        };
        let new_token = StatusListToken {
            list_id: token_id.to_string(),
            issuer: "issuer".to_string(),
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
        assert_eq!(token.status_list.lst, base64url::encode([]));
    }

    #[tokio::test]
    async fn test_repository_unavailable() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token_no_repo";
        let payload = publish_test_token(
            token_id,
            vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }],
        );

        let status_list = StatusList {
            bits: 1,
            lst: create_status_list(payload.status.clone()).unwrap().lst,
        };
        let new_token = StatusListToken {
            list_id: token_id.to_string(),
            issuer: "issuer".to_string(),
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
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token_invalid_index";
        let payload = publish_test_token(
            token_id,
            vec![StatusEntry {
                index: -1,
                status: Status::VALID,
            }],
        );
        let db_conn = Arc::new(mock_db.into_connection());
        let app_state = test_app_state(db_conn.clone());

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
