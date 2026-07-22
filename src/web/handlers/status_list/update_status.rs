use axum::{
    Extension,
    extract::{Json, Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;

use crate::{application::UseCaseError, domain, state::AppState};

use crate::web::errors::ApiError;

use super::{
    StatusesRequest, error::StatusListError, map_domain_error, to_domain_entry,
    validate_status_request_limits,
};

/// Update status entries in an existing status list.
pub async fn update_status(
    State(appstate): State<AppState>,
    Extension(issuer): Extension<String>,
    Path(list_id): Path<String>,
    Json(payload): Json<StatusesRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate list_id as UUID
    if let Err(e) = uuid::Uuid::try_parse(&list_id) {
        return Err(StatusListError::InvalidListId(e.to_string()).into());
    }

    validate_status_request_limits(
        &payload.statuses,
        appstate.max_statuses_per_request,
        appstate.max_status_index,
    )?;

    let statuses = payload
        .statuses
        .into_iter()
        .map(to_domain_entry)
        .collect::<Vec<_>>();

    match appstate
        .status_lists
        .update_statuses(&domain::Issuer(issuer), &list_id, statuses)
        .await
    {
        Ok(()) => {}
        Err(UseCaseError::NotFound) => return Err(StatusListError::StatusListNotFound.into()),
        Err(UseCaseError::IssuerMismatch) => return Err(StatusListError::IssuerMismatch.into()),
        Err(UseCaseError::Domain(domain::DomainError::InvalidIndex)) => {
            return Err(StatusListError::InvalidIndex.into());
        }
        Err(UseCaseError::Domain(domain::DomainError::InvalidStatusList(msg))) => {
            return Err(StatusListError::Generic(msg).into());
        }
        Err(UseCaseError::Domain(domain::DomainError::CorruptStoredList(detail))) => {
            // The stored `lst` failed to decode: corrupt persisted state, not a
            // caller error. Log the detail at error level (this is the alert)
            // and return 500 — never blame the client for our data corruption.
            tracing::error!(list_id = ?list_id, %detail, "Corrupt stored status list");
            return Err(StatusListError::InternalServerError.into());
        }
        Err(UseCaseError::Domain(error)) => return Err(map_domain_error(error).into()),
        Err(UseCaseError::StatusListTooLarge) => return Err(StatusListError::StatusTooLarge.into()),
        Err(UseCaseError::Conflict) => {
            // The optimistic guard in the use case did not match: a concurrent
            // writer won the race (or the row was deleted). The use case returns
            // before recording a snapshot or invalidating the cache, so nothing
            // is persisted for a write that never landed.
            //
            // Logged at info, not warn: under contention an optimistic conflict
            // is the expected, correct outcome, not an anomaly — warn would
            // pollute dashboards and trip alerting during exactly the high-load
            // bursts where conflicts are normal.
            tracing::info!(list_id = ?list_id, "Concurrent update conflict; write rejected");
            return Err(StatusListError::UpdateConflict.into());
        }
        Err(error) => {
            tracing::error!(?error, "Failed to update status list");
            return Err(StatusListError::InternalServerError.into());
        }
    }
    tracing::info!("Invalidated cache for status list: {}", list_id);

    Ok(StatusCode::OK.into_response())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Arc;

    // `next_updated_at` moved to the application layer with the optimistic
    // guard it serves; the test below stays here, where the merge left it.
    use crate::application::next_updated_at;

    use axum::{
        Extension,
        extract::{Path, State},
        response::IntoResponse,
    };
    use hyper::StatusCode;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    // models types below seed the MockDatabase (persistence side); the request
    // wire types come from this handler module.
    use crate::{
        adapters::sea_orm::models::{StatusList, StatusListRecord, status_lists},
        test_utils::{test_app_state, test_app_state_with_max_serialized_list_size},
        web::handlers::status_list::{Status, StatusEntry, test_support::create_status_list},
    };

    #[tokio::test]
    async fn test_update_token_status_invalid_list_id() {
        let appstate = test_app_state(None).await;
        let issuer = "test-issuer".to_string();
        let payload = StatusesRequest { statuses: vec![] };

        let result = update_status(
            State(appstate.clone()),
            Extension(issuer),
            Path("invalid-uuid".to_string()),
            Json(payload),
        )
        .await;

        match result {
            Err(err) => {
                assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
            }
            Ok(_) => panic!("Expected error but got Ok"),
        }
    }

    #[tokio::test]
    async fn test_update_status_modifies_existing_token() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = uuid::Uuid::new_v4().to_string();
        let initial_bits = 2;

        // Initial token setup
        let original_status_list = StatusList {
            bits: initial_bits,
            lst: create_status_list(vec![
                StatusEntry {
                    index: 0,
                    status: Status::VALID,
                },
                StatusEntry {
                    index: 1,
                    status: Status::VALID,
                },
            ])
            .unwrap()
            .lst,
        };

        let existing_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: original_status_list,
            sub: "issuer".to_string(),
            updated_at: 0,
        };

        // Update payload that flips status at index 1 to INVALID
        let update_payload = StatusesRequest {
            statuses: vec![StatusEntry {
                index: 1,
                status: Status::INVALID,
            }],
        };

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![existing_token.clone()], // for find_one_by
                ])
                .append_exec_results(vec![
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // guarded update_many
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // status_list_history insert
                ])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;
        let response = update_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(update_payload),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Exceeding `max_statuses_per_request` returns 400 (#171).
    #[tokio::test]
    async fn test_update_status_rejects_too_many_statuses() {
        let appstate = test_app_state(None).await;
        let mut appstate = appstate;
        appstate.max_statuses_per_request = 1;
        let token_id = uuid::Uuid::new_v4().to_string();
        let payload = StatusesRequest {
            statuses: vec![
                StatusEntry {
                    index: 0,
                    status: Status::VALID,
                },
                StatusEntry {
                    index: 1,
                    status: Status::INVALID,
                },
            ],
        };

        let response = match update_status(
            State(appstate),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(payload),
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
    async fn test_update_status_rejects_index_too_large() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = uuid::Uuid::new_v4().to_string();
        let initial_bits = 1;

        let original_status_list = StatusList {
            bits: initial_bits,
            lst: create_status_list(vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }])
            .unwrap()
            .lst,
        };
        let existing_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: original_status_list,
            sub: "issuer".to_string(),
            updated_at: 0,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![existing_token],
                    vec![],
                ])
                .into_connection(),
        );
        let mut appstate = test_app_state(Some(db_conn.clone())).await;
        appstate.max_status_index = 1;
        let payload = StatusesRequest {
            statuses: vec![StatusEntry {
                index: 999_999,
                status: Status::INVALID,
            }],
        };

        let response = match update_status(
            State(appstate),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(payload),
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
    async fn test_update_status_rejects_serialized_list_too_large() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = uuid::Uuid::new_v4().to_string();
        let initial_bits = 1;

        let original_status_list = StatusList {
            bits: initial_bits,
            lst: create_status_list(vec![StatusEntry {
                index: 0,
                status: Status::VALID,
            }])
            .unwrap()
            .lst,
        };
        let existing_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: original_status_list,
            sub: "issuer".to_string(),
            updated_at: 0,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![existing_token],
                    vec![],
                ])
                .into_connection(),
        );
        let appstate = test_app_state_with_max_serialized_list_size(Some(db_conn.clone()), 1).await;
        let payload = StatusesRequest {
            statuses: vec![StatusEntry {
                index: 9999,
                status: Status::INVALID,
            }],
        };

        let response = match update_status(
            State(appstate),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(payload),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Pins the load-bearing monotonicity of the optimistic stamp. If someone
    /// "simplifies" `next_updated_at` down to `now` (dropping the `+ 1`), the
    /// same-second case below fails here instead of silently reintroducing the
    /// lost-update bug in production.
    #[test]
    fn test_next_updated_at_strictly_advances_within_same_second() {
        // Same wall-clock second as the previous write: must still advance.
        assert_eq!(next_updated_at(1000, 1000), 1001);
        // Clock went backwards / equal: never emit a stale-or-equal stamp.
        assert_eq!(next_updated_at(1000, 999), 1001);
        // Clock advanced normally: use the real time.
        assert_eq!(next_updated_at(1000, 2000), 2000);
    }

    #[tokio::test]
    async fn test_update_status_conflict_returns_409() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = uuid::Uuid::new_v4().to_string();

        let existing_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: StatusList {
                bits: 2,
                lst: create_status_list(vec![StatusEntry {
                    index: 0,
                    status: Status::VALID,
                }])
                .unwrap()
                .lst,
            },
            sub: "issuer".to_string(),
            updated_at: 0,
        };

        let update_payload = StatusesRequest {
            statuses: vec![StatusEntry {
                index: 0,
                status: Status::INVALID,
            }],
        };

        // find_one_by sees the row, but the guarded UPDATE affects 0 rows: a
        // concurrent writer already moved `updated_at`.
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    existing_token.clone(),
                ]])
                .append_exec_results(vec![MockExecResult {
                    rows_affected: 0,
                    last_insert_id: 0,
                }])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;
        let response = match update_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(update_payload),
        )
        .await
        {
            Ok(_) => panic!("conflicting write must not report success"),
            Err(err) => err.into_response(),
        };

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// A well-formed update against a list whose stored `lst` is corrupt must
    /// return 500 (state error), not 400 (client error) — so data corruption is
    /// alerted, not blamed on the caller.
    #[tokio::test]
    async fn test_update_status_corrupt_stored_list_returns_500() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = uuid::Uuid::new_v4().to_string();

        let corrupt_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "not valid base64!!".to_string(),
            },
            sub: "issuer".to_string(),
            updated_at: 0,
        };

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    corrupt_token.clone(),
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;
        let response = match update_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(StatusesRequest {
                statuses: vec![StatusEntry {
                    index: 0,
                    status: Status::INVALID,
                }],
            }),
        )
        .await
        {
            Ok(_) => panic!("update over corrupt stored list must not succeed"),
            Err(err) => err.into_response(),
        };

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
