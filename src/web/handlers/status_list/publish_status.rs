use crate::{
    models::{StatusList, StatusListHistoryRecord, StatusListRecord, StatusesRequest},
    utils::{errors::Error, lst_gen::create_status_list, state::AppState},
    web::handlers::status_list::error::StatusListError,
};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use time::OffsetDateTime;
use tracing;

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

    let store = &appstate.status_list_repo;

    let stl = create_status_list(payload.statuses).map_err(|e| {
        tracing::error!("lst_from failed: {e:?}");
        match e {
            Error::Generic(msg) => StatusListError::Generic(msg),
            Error::InvalidIndex => StatusListError::InvalidIndex,
            _ => StatusListError::Generic(e.to_string()),
        }
    })?;

    // Check for existing token to prevent duplicates
    match store.find_one_by(&list_id).await {
        Ok(Some(_)) => {
            tracing::info!("Status list {list_id} already exists");
            Err(StatusListError::StatusListAlreadyExists)
        }
        Ok(None) => {
            // Serialize the status list before constructing the token
            let status_list = StatusList {
                bits: stl.bits,
                lst: stl.lst,
            };

            let sub = format!(
                "https://{}/api/v1/status-lists/{}",
                appstate.server_domain, list_id
            );

            let updated_at = OffsetDateTime::now_utc().unix_timestamp();

            // Build the new status list token
            let status_list_record = StatusListRecord {
                list_id: list_id.clone(),
                issuer,
                status_list,
                sub,
                updated_at,
            };

            // Insert the token into the repository
            store
                .insert_one(status_list_record.clone())
                .await
                .map_err(|e| {
                    tracing::error!("Failed to insert status list entry: {e:?}");
                    StatusListError::InternalServerError
                })?;

            persist_historical_snapshot(&appstate, &status_list_record).await?;
            Ok(StatusCode::CREATED.into_response())
        }
        Err(e) => {
            tracing::error!(error = ?e, list_id = ?list_id, "Database query failed for status list.");
            Err(StatusListError::InternalServerError)
        }
    }
}

/// Records the exact payload and validity window issued at each state change.
/// This retention is privacy-sensitive: §12.7 recommends enabling it only
/// where historical resolution is justified and its privacy impact is known.
///
/// If `history_retention_secs` is 0, this function returns immediately without
/// creating a snapshot, effectively disabling historical resolution.
pub(super) async fn persist_historical_snapshot(
    appstate: &AppState,
    status_list_record: &StatusListRecord,
) -> Result<(), StatusListError> {
    // Skip snapshot creation if historical resolution is disabled
    if appstate.history_retention_secs == 0 {
        tracing::debug!(
            "Historical snapshots are disabled, skipping snapshot for list {}",
            status_list_record.list_id
        );
        return Ok(());
    }

    let iat = OffsetDateTime::now_utc().unix_timestamp();
    let snapshot = StatusListHistoryRecord {
        snapshot_id: uuid::Uuid::new_v4().to_string(),
        list_id: status_list_record.list_id.clone(),
        issuer: status_list_record.issuer.clone(),
        status_list: status_list_record.status_list.clone(),
        sub: status_list_record.sub.clone(),
        iat,
        exp: iat + appstate.token_exp_secs as i64,
    };
    appstate
        .status_list_history_repo
        .insert_one(snapshot)
        .await
        .map_err(|e| {
            tracing::error!("Failed to persist status list history: {e:?}");
            StatusListError::InternalServerError
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::handlers::status_list::error::StatusListError;
    use crate::{
        models::{Status, StatusEntry, StatusListRecord, status_lists},
        test_utils::test_app_state,
    };
    use axum::{Json, extract::State};
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use std::sync::Arc;

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
            lst: create_status_list(status_entries.clone()).unwrap().lst,
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
            lst: create_status_list(status_entries.clone()).unwrap().lst,
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

        let result = app_state
            .status_list_repo
            .find_one_by(&token_id)
            .await
            .unwrap();
        assert!(result.is_some());
        let token = result.unwrap();
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
                lst: create_status_list(status_entries.clone()).unwrap().lst,
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
        let status_entries = vec![StatusEntry {
            index: 0,
            status: Status::VALID,
        }];

        let status_list = StatusList {
            bits: 1,
            lst: create_status_list(status_entries.clone()).unwrap().lst,
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
}
