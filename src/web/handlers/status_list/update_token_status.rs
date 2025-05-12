use axum::{extract::State, response::IntoResponse, Extension, Json};
use hyper::StatusCode;

use crate::{
    model::StatusListTokenPayload,
    utils::{
        bits_validation::BitFlag, errors::Error, lst_gen::update_status_list, state::AppState,
    },
};

use super::error::StatusListError;

// Handler to update an existing status list token
pub async fn update_token_status(
    State(appstate): State<AppState>,
    Extension(issuer): Extension<String>,
    Json(payload): Json<StatusListTokenPayload>,
) -> Result<impl IntoResponse, StatusListError> {
    let store = &appstate.status_list_token_repository;

    let bits = BitFlag::new(payload.bits).ok_or_else(|| {
        StatusListError::Generic(format!(
            "Invalid 'bits' value: {}. Allowed values are 1, 2, 4, 8.",
            payload.bits
        ))
    })?;

    // Fetch the existing token
    let token = match store.find_all_by(issuer).await {
        Ok(tokens) => tokens,
        Err(e) => {
            tracing::error!(error = ?e, list_id = ?payload.list_id, "Database query failed for status list.");
            return Err(StatusListError::InternalServerError);
        }
    };

    let exact_token = token
        .into_iter()
        .find(|t| t.list_id == payload.list_id)
        .ok_or(StatusListError::StatusListNotFound)?
        .clone();

    // Update the status list
    let updated_lst = update_status_list(
        exact_token.status_list.lst.clone(),
        payload.status.clone(),
        bits,
    )
    .map_err(|e| {
        tracing::error!("update_status_list failed: {:?}", e);
        match e {
            Error::Generic(msg) => StatusListError::Generic(msg),
            Error::InvalidIndex => StatusListError::InvalidIndex,
            Error::UnsupportedBits => StatusListError::UnsupportedBits,
            _ => StatusListError::Generic(e.to_string()),
        }
    })?;

    let mut exact_token = exact_token;
    exact_token.status_list.lst = updated_lst;
    exact_token.status_list.bits = payload.bits;
    exact_token.status_list.bits = payload.bits;

    // Save the updated token

    store
        .update_one(exact_token.list_id.clone(), exact_token.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to update token: {:?}", e);
            StatusListError::InternalServerError
        })?;

    Ok(StatusCode::OK.into_response())
}

#[cfg(test)]
mod test {
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use axum::{extract::State, response::IntoResponse, Extension, Json};
    use hyper::StatusCode;
    use sea_orm::{DatabaseBackend, MockDatabase};

    use crate::{
        database::queries::SeaOrmStore,
        model::{
            status_list_tokens, Status, StatusEntry, StatusList, StatusListToken,
            StatusListTokenPayload,
        },
        test_resources::helper::server_key,
        utils::{bits_validation::BitFlag, lst_gen::create_status_list, state::AppState},
        web::handlers::status_list::update_token_status::update_token_status,
    };

    #[tokio::test]
    async fn test_update_status_modifies_existing_token() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token1";
        let initial_bits = 2;
        let bits = BitFlag::new(initial_bits).unwrap();

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
                bits,
            )
            .unwrap(),
        };

        let existing_token = StatusListToken {
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
            status_list: original_status_list,
            sub: "issuer".to_string(),
            ttl: Some(3600),
        };

        // Update payload that flips status at index 1 to INVALID
        let update_payload = StatusListTokenPayload {
            list_id: token_id.to_string(),
            status: vec![StatusEntry {
                index: 1,
                status: Status::INVALID,
            }],
            sub: Some("issuer".to_string()),
            ttl: Some(3600),
            bits: initial_bits,
        };

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![existing_token.clone()], // for find_one_by
                    vec![],
                ])
                .into_connection(),
        );

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

        let response = update_token_status(
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
