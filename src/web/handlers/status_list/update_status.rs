use axum::{extract::State, response::IntoResponse, Extension, Json};
use hyper::StatusCode;

use crate::{
    models::StatusRequest,
    utils::{
        bits_validation::BitFlag, errors::Error, lst_gen::update_status_list, state::AppState,
    },
};

use super::error::StatusListError;

// Handler to update an existing status list token
pub async fn update_status(
    State(appstate): State<AppState>,
    Extension(issuer): Extension<String>,
    Json(payload): Json<StatusRequest>,
) -> Result<impl IntoResponse, StatusListError> {
    // Validate list_id as UUID
    if let Err(e) = uuid::Uuid::try_parse(&payload.list_id) {
        return Err(StatusListError::InvalidListId(e.to_string()));
    }

    let store = &appstate.status_list_repo;

    // Fetch the existing token
    let record = store.find_one_by(payload.list_id.clone()).await.map_err(|e| {
            tracing::error!(error = ?e, list_id = ?payload.list_id, "Database query failed for status list.");
            StatusListError::InternalServerError
        })?.ok_or(StatusListError::StatusListNotFound)?;

    // check if the request issuer matches the token issuer
    if record.issuer != issuer {
        tracing::error!(
            "Issuer mismatch: expected {}, got {}",
            record.issuer,
            issuer
        );
        return Err(StatusListError::IssuerMismatch);
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
        payload.status.clone(),
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

    // Save the updated token
    store
        .update_one(exact_status_list.list_id.clone(), exact_status_list.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to update token: {e:?}");
            StatusListError::InternalServerError
        })?;

    Ok(StatusCode::OK.into_response())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::web::handlers::status_list::error::StatusListError;
    use std::sync::Arc;

    use axum::{extract::State, response::IntoResponse, Extension, Json};
    use hyper::StatusCode;
    use sea_orm::{DatabaseBackend, MockDatabase};

    use crate::{
        models::{status_lists, Status, StatusEntry, StatusList, StatusListRecord, StatusRequest},
        test_utils::test_app_state,
        utils::lst_gen::create_status_list,
    };

    #[tokio::test]
    async fn test_update_token_status_invalid_list_id() {
        let appstate = test_app_state(None).await;
        let issuer = "test-issuer".to_string();
        let payload = StatusRequest {
            list_id: "invalid-uuid".to_string(),
            status: vec![],
        };

        let result = update_status(State(appstate.clone()), Extension(issuer), Json(payload)).await;

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
        };

        // Update payload that flips status at index 1 to INVALID
        let update_payload = StatusRequest {
            list_id: token_id,
            status: vec![StatusEntry {
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
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;
        let response = update_status(
            State(app_state),
            Extension("issuer".to_string()),
            Json(update_payload),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
