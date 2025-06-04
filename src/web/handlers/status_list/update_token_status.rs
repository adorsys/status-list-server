use axum::{extract::State, response::IntoResponse, Json};
use hyper::StatusCode;

use crate::{
    model::StatusRequest,
    utils::{
        bits_validation::BitFlag, errors::Error, lst_gen::update_status_list, state::AppState,
    }, web::midlw::AuthenticatedIssuer,
};

use super::error::StatusListError;

// Handler to update an existing status list token
pub async fn update_token_status(
    State(appstate): State<AppState>,
    AuthenticatedIssuer(issuer): AuthenticatedIssuer,
    Json(payload): Json<StatusRequest>,
) -> Result<impl IntoResponse, StatusListError> {
    let store = &appstate.status_list_token_repository;

    // Fetch the existing token
    let token = match store.find_one_by(payload.list_id.clone()).await {
        Ok(tokens) => tokens,
        Err(e) => {
            tracing::error!(error = ?e, list_id = ?payload.list_id, "Database query failed for status list.");
            return Err(StatusListError::InternalServerError);
        }
    };
    let token = match token {
        Some(token) => token,
        None => {
            tracing::error!("Token not found in the database.");
            return Err(StatusListError::StatusListNotFound);
        }
    };

    // check if the request issuer matches the token issuer
    if token.issuer != issuer {
        tracing::error!("Issuer mismatch: expected {}, got {}", token.issuer, issuer);
        return Err(StatusListError::IssuerMismatch);
    }

    let bits = if let Some(bits) = BitFlag::new(token.status_list.bits) {
        Ok(bits)
    } else {
        Err(StatusListError::Generic(format!(
            "Invalid 'bits' value: {}. Allowed values are 1, 2, 4, 8.",
            token.status_list.bits
        )))
    };
    let bits = bits?;

    // Update the status list
    let updated_lst = update_status_list(
        token.status_list.lst.clone(),
        payload.status.clone(),
        bits.value(),
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

    let mut exact_token = token;
    exact_token.status_list.lst = updated_lst.lst;
    exact_token.status_list.bits = updated_lst.bits;

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

    use axum::{extract::State, response::IntoResponse, Json};
    use hyper::StatusCode;
    use sea_orm::{DatabaseBackend, MockDatabase};

    use crate::{
        model::{
            status_list_tokens, Status, StatusEntry, StatusList, StatusListToken, StatusRequest,
        },
        test_utils::test::test_app_state,
        utils::lst_gen::create_status_list,
        web::{handlers::status_list::update_token_status::update_token_status, midlw::AuthenticatedIssuer},
    };

    #[tokio::test]
    async fn test_update_status_modifies_existing_token() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = "token1";
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
        let update_payload = StatusRequest {
            list_id: token_id.to_string(),
            status: vec![StatusEntry {
                index: 1,
                status: Status::INVALID,
            }],
        };

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![existing_token.clone()], // for find_one_by
                    vec![],
                ])
                .into_connection(),
        );

        let app_state = test_app_state(db_conn.clone());
        let response = update_token_status(
            State(app_state),
            AuthenticatedIssuer("issuer".to_string()),
            Json(update_payload),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
