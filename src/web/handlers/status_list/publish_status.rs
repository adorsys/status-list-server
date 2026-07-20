use crate::{
    application::UseCaseError, domain, models::StatusesRequest, utils::state::AppState,
    web::handlers::status_list::error::StatusListError,
};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use tracing;

use super::to_domain_entry;

/// Create a new status list.
pub async fn publish_status(
    State(appstate): State<AppState>,
    Extension(issuer): Extension<String>,
    Path(list_id): Path<String>,
    Json(payload): Json<StatusesRequest>,
) -> Result<impl IntoResponse, StatusListError> {
    // Validate list_id as UUID
    if let Err(e) = uuid::Uuid::try_parse(&list_id) {
        return Err(StatusListError::InvalidListId(e.to_string()));
    }

    let statuses = payload
        .statuses
        .into_iter()
        .map(to_domain_entry)
        .collect::<Vec<_>>();
    match appstate
        .status_lists
        .publish_status_list(
            list_id.clone(),
            domain::Issuer(issuer),
            format!(
                "https://{}/api/v1/status-lists/{list_id}",
                appstate.server_domain
            ),
            statuses,
        )
        .await
    {
        Ok(()) => Ok(StatusCode::CREATED.into_response()),
        Err(UseCaseError::AlreadyExists) => Err(StatusListError::StatusListAlreadyExists),
        Err(UseCaseError::Domain(domain::DomainError::InvalidIndex)) => {
            Err(StatusListError::InvalidIndex)
        }
        Err(UseCaseError::Domain(domain::DomainError::InvalidStatusList(msg))) => {
            Err(StatusListError::Generic(msg))
        }
        Err(error) => {
            tracing::error!(?error, list_id, "Failed to publish status list");
            Err(StatusListError::InternalServerError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::handlers::status_list::error::StatusListError;
    use crate::{
        models::{Status, StatusEntry, StatusList, StatusListRecord, status_lists},
        test_utils::test_app_state,
        utils::lst_gen::create_status_list,
    };
    use axum::{Json, extract::State};
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use std::sync::Arc;

    const LIMITS: AbuseLimits = AbuseLimits::unlimited();

    #[tokio::test]
    async fn test_publish_token_status_invalid_list_id() {
        let appstate = test_app_state(None).await;
        let issuer = "test-issuer".to_string();
        let payload = StatusesRequest { statuses: vec![] };

        let result = publish_status(
            State(appstate.clone()),
            Extension(issuer),
            Path("invalid-uuid".to_string()),
            Json(payload),
        )
        .await;

        assert!(matches!(result, Err(StatusListError::InvalidListId(_))));
    }

    #[tokio::test]
    async fn test_publish_status_creates_token() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "477121aa-b598-419e-916f-1e74654ff38b".to_string();
        let status_entries = vec![
            StatusEntry {
                index: 0,
                status: Status::VALID,
            },
            StatusEntry {
                index: 1,
                status: Status::INVALID,
            },
        ];

        let status_list = StatusList {
            bits: 2,
            lst: create_status_list(status_entries.clone(), &LIMITS)
                .unwrap()
                .lst,
        };
        let new_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list,
            sub: format!("https://example.com/api/v1/status-lists/{token_id}"),
            updated_at: 0,
        };
        let _ = &new_token;
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![], // find_one_by in handler returns None
                ])
                .append_exec_results(vec![
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // status_lists insert
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // status_list_history insert
                ])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let response = publish_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
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
        let status_entries = vec![
            StatusEntry {
                index: 0,
                status: Status::VALID,
            },
            StatusEntry {
                index: 1,
                status: Status::INVALID,
            },
        ];

        let status_list = StatusList {
            bits: 2,
            lst: create_status_list(status_entries.clone(), &LIMITS)
                .unwrap()
                .lst,
        };
        let new_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list,
            sub: format!("https://example.com/api/v1/status-lists/{token_id}"),
            updated_at: 0,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .append_exec_results(vec![
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // status_lists insert
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // status_list_history insert
                ])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let _ = publish_status(
            State(app_state.clone()),
            Extension("issuer".to_string()),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
        )
        .await
        .unwrap();

        let token = app_state
            .status_lists
            .get_status_list(&token_id)
            .await
            .unwrap();
        assert_eq!(token.list_id, token_id);
        assert_eq!(token.status_list.bits, 2);
        assert_eq!(
            token.sub,
            format!("https://example.com/api/v1/status-lists/{token_id}")
        );
    }

    #[tokio::test]
    async fn test_token_conflict() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "8e4ebb4a-dd79-498f-ac97-966f22884037".to_string();
        let status_entries = vec![StatusEntry {
            index: 0,
            status: Status::VALID,
        }];

        let existing_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: create_status_list(status_entries.clone(), &LIMITS)
                    .unwrap()
                    .lst,
            },
            sub: "issuer".to_string(),
            updated_at: 0,
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
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
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
        let status_list = StatusList {
            bits: 1,
            lst: base64url::encode([]),
        };
        let new_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list,
            sub: format!("https://example.com/api/v1/status-lists/{token_id}"),
            updated_at: 0,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .append_exec_results(vec![
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // status_lists insert
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // status_list_history insert
                ])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let response = publish_status(
            State(app_state.clone()),
            Extension("issuer".to_string()),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let token = app_state
            .status_lists
            .get_status_list(&token_id)
            .await
            .unwrap();
        assert_eq!(token.list_id, token_id);
        assert_eq!(token.status_list.lst, base64url::encode([]));
    }

    #[tokio::test]
    async fn test_repository_unavailable() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "477121aa-b598-419e-916f-1e74654ff38b".to_string();
        let status_entries = vec![StatusEntry {
            index: 0,
            status: Status::VALID,
        }];

        let status_list = StatusList {
            bits: 1,
            lst: create_status_list(status_entries.clone(), &LIMITS)
                .unwrap()
                .lst,
        };
        let new_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list,
            sub: format!("https://example.com/api/v1/status-lists/{token_id}"),
            updated_at: 0,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![],                  // find_one_by in handler returns None
                    vec![new_token.clone()], // find_one_by in test verification
                ])
                .append_exec_results(vec![
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // status_lists insert
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // status_list_history insert
                ])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let response = publish_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
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
        let status_entries = vec![StatusEntry {
            index: -1,
            status: Status::VALID,
        }];
        let db_conn = Arc::new(mock_db.into_connection());
        let app_state = test_app_state(Some(db_conn.clone())).await;

        let response = match publish_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Exceeding `max_statuses_per_request` returns 400 (#171).
    #[tokio::test]
    async fn test_publish_status_rejects_too_many_statuses() {
        let token_id = "477121aa-b598-419e-916f-1e74654ff38b".to_string();
        let status_entries = vec![
            StatusEntry {
                index: 0,
                status: Status::VALID,
            },
            StatusEntry {
                index: 1,
                status: Status::INVALID,
            },
        ];
        let mut app_state = test_app_state(None).await;
        app_state.max_statuses_per_request = 1;

        let response = match publish_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: status_entries.clone(),
            }),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Index exceeding `max_status_index` returns 400 (#171).
    #[tokio::test]
    async fn test_publish_status_rejects_index_too_large() {
        let token_id = "477121aa-b598-419e-916f-1e74654ff38b".to_string();
        let status_entries = vec![StatusEntry {
            index: 999_999,
            status: Status::VALID,
        }];
        let mut app_state = test_app_state(None).await;
        app_state.max_status_index = 1;

        let response = match publish_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Serialized list exceeding `max_serialized_list_size` returns 422 (#171).
    #[tokio::test]
    async fn test_publish_status_rejects_serialized_list_too_large() {
        let token_id = "477121aa-b598-419e-916f-1e74654ff38b".to_string();
        // Enough entries that the gzip+base64 encoding exceeds 16 bytes.
        let mut status_entries = Vec::new();
        for i in 0..200u32 {
            status_entries.push(StatusEntry {
                index: i as i32,
                status: Status::INVALID,
            });
        }
        let mut app_state = test_app_state(None).await;
        app_state.max_serialized_list_size = 8;

        let response = match publish_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
