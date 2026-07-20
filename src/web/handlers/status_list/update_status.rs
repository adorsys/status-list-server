use axum::{
    Extension, Json,
    extract::{Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;

use crate::{application::UseCaseError, domain, models::StatusesRequest, utils::state::AppState};

use super::{error::StatusListError, to_domain_entry};

/// Update status entries in an existing status list.
pub async fn update_status(
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
        .update_statuses(&domain::Issuer(issuer), &list_id, statuses)
        .await
    {
        Ok(()) => {}
        Err(UseCaseError::NotFound) => return Err(StatusListError::StatusListNotFound),
        Err(UseCaseError::IssuerMismatch) => return Err(StatusListError::IssuerMismatch),
        Err(UseCaseError::Domain(domain::DomainError::InvalidIndex)) => {
            return Err(StatusListError::InvalidIndex);
        }
        Err(UseCaseError::Domain(domain::DomainError::InvalidStatusList(msg))) => {
            return Err(StatusListError::Generic(msg));
        }
        Err(error) => {
            tracing::error!(?error, "Failed to update status list");
            return Err(StatusListError::InternalServerError);
        }
    }
    tracing::info!("Invalidated cache for status list: {}", list_id);

    Ok(StatusCode::OK.into_response())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::web::handlers::status_list::error::StatusListError;
    use std::sync::Arc;

    use axum::{
        Extension, Json,
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
        utils::lst_gen::create_status_list,
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

        assert!(matches!(result, Err(StatusListError::InvalidListId(_))));
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
}
