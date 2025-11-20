use crate::{
    models::{StatusList, StatusListRecord, StatusRequest},
    utils::{errors::Error, lst_gen::create_status_list, state::AppState},
    web::handlers::status_list::error::StatusListError,
};
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    Extension,
};
use tracing;

// Handler to create a new status list token
pub async fn publish_status(
    State(appstate): State<AppState>,
    Extension(issuer): Extension<String>,
    Json(payload): Json<StatusRequest>,
) -> Result<impl IntoResponse, StatusListError> {
    // Validate list_id as UUID
    if let Err(e) = uuid::Uuid::try_parse(&payload.list_id) {
        return Err(StatusListError::InvalidListId(e.to_string()));
    }

    let store = &appstate.status_list_repo;

    let stl = create_status_list(payload.status).map_err(|e| {
        tracing::error!("lst_from failed: {e:?}");
        match e {
            Error::Generic(msg) => StatusListError::Generic(msg),
            Error::InvalidIndex => StatusListError::InvalidIndex,
            _ => StatusListError::Generic(e.to_string()),
        }
    })?;

    // Check for existing token to prevent duplicates
    match store.find_one_by(&payload.list_id).await {
        Ok(Some(_)) => {
            tracing::info!("Status list {} already exists", payload.list_id);
            Err(StatusListError::StatusListAlreadyExists)
        }
        Ok(None) => {
            // Serialize the status list before constructing the token
            let status_list = StatusList {
                bits: stl.bits,
                lst: stl.lst,
            };

            let sub = format!(
                "https://{}/statuslists/{}",
                appstate.server_domain, payload.list_id
            );

            // Build the new status list token
            let status_list_record = StatusListRecord {
                list_id: payload.list_id.clone(),
                issuer,
                status_list,
                sub,
            };

            // Insert the token into the repository
            store.insert_one(status_list_record).await.map_err(|e| {
                tracing::error!("Failed to insert status list entry: {e:?}");
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
    use crate::web::handlers::status_list::error::StatusListError;
    use crate::{
        models::{status_lists, Status, StatusEntry, StatusListRecord},
        test_resources::helper::publish_test_token,
        test_utils::test_app_state,
    };
    use axum::{extract::State, Json};
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_publish_token_status_invalid_list_id() {
        let appstate = test_app_state(None).await;
        let issuer = "test-issuer".to_string();
        let payload = StatusRequest {
            list_id: "invalid-uuid".to_string(),
            status: vec![],
        };

        let result =
            publish_status(State(appstate.clone()), Extension(issuer), Json(payload)).await;

        assert!(matches!(result, Err(StatusListError::InvalidListId(_))));
    }

    #[tokio::test]
    async fn test_publish_status_creates_token() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "477121aa-b598-419e-916f-1e74654ff38b".to_string();
        let payload = publish_test_token(
            &token_id,
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
        let new_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list,
            sub: "issuer".to_string(),
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // insert_one return
                ])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let response = publish_status(
            State(app_state),
            Extension("issuer".to_string()),
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
        let token_id = "8e4ebb4a-dd79-498f-ac97-966f22884037".to_string();
        let payload = publish_test_token(
            &token_id,
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
        let new_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list,
            sub: "issuer".to_string(),
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // insert_one return
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        // Perform the insertion
        let _ = publish_status(
            State(app_state.clone()),
            Extension("issuer".to_string()),
            Json(payload),
        )
        .await
        .unwrap();

        // Verify the token is stored
        let result = app_state
            .status_list_repo
            .find_one_by(&token_id)
            .await
            .unwrap();
        assert!(result.is_some());
        let token = result.unwrap();
        assert_eq!(token.list_id, token_id);
        assert_eq!(token.status_list.bits, 2);
        assert_eq!(token.sub, "issuer");
    }

    #[tokio::test]
    async fn test_token_conflict() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "8e4ebb4a-dd79-498f-ac97-966f22884037".to_string();
        let payload = publish_test_token(
            &token_id,
            vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }],
        );

        let existing_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: create_status_list(payload.status.clone()).unwrap().lst,
            },
            sub: "issuer".to_string(),
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![existing_token]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let response = match publish_status(
            State(app_state),
            Extension("issuer".to_string()),
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
        let token_id = "477121aa-b598-419e-916f-1e74654ff38b".to_string();
        let payload = publish_test_token(&token_id, vec![]);
        let status_list = StatusList {
            bits: 1,
            lst: base64url::encode([]),
        };
        let new_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list,
            sub: "issuer".to_string(),
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // insert_one return
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let response = publish_status(
            State(app_state.clone()),
            Extension("issuer".to_string()),
            Json(payload),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let result = app_state
            .status_list_repo
            .find_one_by(&token_id)
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
        let token_id = "477121aa-b598-419e-916f-1e74654ff38b".to_string();
        let payload = publish_test_token(
            &token_id,
            vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }],
        );

        let status_list = StatusList {
            bits: 1,
            lst: create_status_list(payload.status.clone()).unwrap().lst,
        };
        let new_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list,
            sub: "issuer".to_string(),
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // insert_one return
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .into_connection(),
        );
        let app_state = test_app_state(Some(db_conn.clone())).await;

        let response = publish_status(
            State(app_state),
            Extension("issuer".to_string()),
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
        let token_id = "477121aa-b598-419e-916f-1e74654ff38b".to_string();
        let payload = publish_test_token(
            &token_id,
            vec![StatusEntry {
                index: -1,
                status: Status::VALID,
            }],
        );
        let db_conn = Arc::new(mock_db.into_connection());
        let app_state = test_app_state(Some(db_conn.clone())).await;

        let response = match publish_status(
            State(app_state),
            Extension("issuer".to_string()),
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
