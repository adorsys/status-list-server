use axum::{
    Extension,
    extract::{Json, Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;
use time::OffsetDateTime;

use crate::{
    models::StatusesRequest,
    utils::{
        bits_validation::BitFlag, errors::Error, lst_gen::update_status_list, state::AppState,
    },
    web::errors::ApiError,
};

use super::error::StatusListError;
use super::publish_status::persist_historical_snapshot;

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

    let store = &appstate.status_list_repo;

    // Fetch the existing token
    let record = store
        .find_one_by(&list_id)
        .await?
        .ok_or(StatusListError::StatusListNotFound)?;

    // Check if the request issuer matches the token issuer
    if record.issuer != issuer {
        tracing::error!(
            "Issuer mismatch: expected {}, got {}",
            record.issuer,
            issuer
        );
        return Err(StatusListError::IssuerMismatch.into());
    }

    let bits = if let Some(bits) = BitFlag::new(record.status_list.bits) {
        Ok(bits)
    } else {
        Err(StatusListError::Generic(format!(
            "Invalid 'bits' value: {}. Allowed values are 1, 2, 4, 8.",
            record.status_list.bits
        )))
    }?;

    // Update the status list
    let updated_lst = update_status_list(
        record.status_list.lst.clone(),
        payload.statuses,
        bits.value(),
    )
    .map_err(|e| {
        tracing::error!("update_status_list failed: {e:?}");
        match e {
            Error::Generic(msg) => StatusListError::Generic(msg),
            Error::InvalidIndex => StatusListError::InvalidIndex,
            _ => StatusListError::Generic(e.to_string()),
        }
    })?;

    let mut exact_status_list = record;
    exact_status_list.status_list.lst = updated_lst.lst;
    exact_status_list.status_list.bits = updated_lst.bits;
    exact_status_list.updated_at = OffsetDateTime::now_utc().unix_timestamp();

    // Save the updated token
    store
        .update_one(&exact_status_list.list_id, exact_status_list.clone())
        .await?;

    persist_historical_snapshot(&appstate, &exact_status_list).await?;

    // Invalidate cache entry to ensure next read fetches the updated record
    appstate.cache.invalidate(&exact_status_list.list_id).await;
    tracing::info!(
        "Invalidated cache for status list: {}",
        exact_status_list.list_id
    );

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
