use axum::{
    Extension,
    extract::{Json, Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;

use crate::{application::UseCaseError, domain, models::StatusesRequest, utils::state::AppState};

use crate::web::errors::ApiError;

use super::{
    error::StatusListError, map_domain_error, to_domain_entry, validate_status_request_limits,
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
        .update_statuses_with_max_serialized_list_size(
            &domain::Issuer(issuer),
            &list_id,
            statuses,
            appstate.max_serialized_list_size,
        )
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
        Err(UseCaseError::Domain(error)) => return Err(map_domain_error(error).into()),
        Err(UseCaseError::StatusListTooLarge) => return Err(StatusListError::StatusTooLarge.into()),
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

    use axum::{
        Extension,
        extract::{Path, State},
        response::IntoResponse,
    };
    use hyper::StatusCode;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use crate::{
        models::{
            Status, StatusEntry, StatusList, StatusListRecord, StatusesRequest, status_lists,
        },
        test_utils::test_app_state,
        utils::lst_gen::{AbuseLimits, create_status_list},
    };

    const LIMITS: AbuseLimits = AbuseLimits::unlimited();

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
            lst: create_status_list(
                vec![
                    StatusEntry {
                        index: 0,
                        status: Status::VALID,
                    },
                    StatusEntry {
                        index: 1,
                        status: Status::VALID,
                    },
                ],
                &LIMITS,
            )
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
                    vec![],
                ])
                .append_exec_results(vec![MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                }])
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
            lst: create_status_list(
                vec![StatusEntry {
                    index: 0,
                    status: Status::VALID,
                }],
                &LIMITS,
            )
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
            lst: create_status_list(
                vec![StatusEntry {
                    index: 0,
                    status: Status::VALID,
                }],
                &LIMITS,
            )
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
        appstate.max_serialized_list_size = 1;
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
}
