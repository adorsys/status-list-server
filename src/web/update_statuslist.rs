use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;
use serde_json::Value;
use std::sync::Arc;

use crate::{
    database::repository::Repository,
    model::{Status, StatusList, StatusListToken, StatusUpdate},
    utils::state::AppState,
};

use super::error::StatusError;

//#[axum::debug_handler]
pub async fn update_statuslist(
    State(appstate): State<Arc<AppState>>,
    Path(list_id): Path<String>,
    body: Value,
) -> impl IntoResponse {
    let body = body
        .as_object()
        .and_then(|body| body.get("updates"))
        .and_then(|statuslist| statuslist.as_array())
        .unwrap();

    let updates_json = serde_json::to_vec(&body).unwrap();

    let updates: Vec<StatusUpdate> = match serde_json::from_slice(&updates_json) {
        Ok(updates) => updates,
        Err(e) => {
            tracing::error!("error: {e}");
            return (StatusCode::BAD_REQUEST, "malformed request body").into_response();
        }
    };

    // Fetch the status list from the database
    if let Some(store) = &appstate.repository {
        let status_list_token_result = store
            .status_list_token_repository
            .find_one_by(list_id)
            .await;

        match status_list_token_result {
            Ok(status_list_token) => {
                let lst = status_list_token.status_list.lst;
                // Update token status
                for update in updates {
                    let result = update_status(lst.clone(), update);
                    match result {
                        Ok(lst) => {
                            // construct new statuslist
                            let status_list = StatusList {
                                bits: status_list_token.status_list.bits,
                                lst,
                            };

                            let statuslisttoken = StatusListToken::new(
                                status_list_token.exp,
                                status_list_token.iat,
                                status_list,
                                status_list_token.sub,
                                status_list_token.ttl,
                            );
                            // store updated list
                            match store
                                .status_list_token_repository
                                .update_one(list_id, statuslisttoken)
                                .await
                            {
                                Ok(b) => {
                                    if b {
                                        Ok(StatusCode::ACCEPTED);
                                    } else {
                                        Ok(StatusCode::BAD_REQUEST);
                                    }
                                }
                                Err(err) => {
                                    tracing::error!("error: {err:?}");
                                    Err((StatusCode::BAD_REQUEST, "failed to update status"));
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("error: {e:?}");
                            Err::<StatusCode, _>((
                                StatusCode::BAD_REQUEST,
                                "failed to update status",
                            ))
                            .into_response();
                        }
                    }
                }
            }
            Err(err) => {
                tracing::error!("error: {err:?}");
                return (StatusCode::BAD_REQUEST, "failed to fetch status list").into_response();
            }
        }
    }

    StatusCode::CREATED.into_response()
}

fn encode_lst(bits: Vec<i32>) -> String {
    let encoded_status = base64url::encode(
        &bits
            .iter()
            .flat_map(|&n| n.to_be_bytes())
            .collect::<Vec<u8>>(),
    );
    encoded_status
}
pub fn update_status(lst: String, updates: StatusUpdate) -> Result<String, StatusError> {
    let decoded_lst = base64url::decode(&lst).map_err(|e| StatusError::Generic(e.to_string()))?;
    let mut bits: Vec<i32> = std::str::from_utf8(&decoded_lst)
        .map_err(|e| StatusError::Generic(e.to_string()))?
        .chars()
        .map(|c| c.to_digit(10).unwrap_or_default() as i32)
        .collect();
    let index = updates.index;
    let status = updates.status;

    match status {
        // bits value is 1. find way to handle multiple bit values
        Status::VALID => {
            if let Some(_) = bits.get(index as usize) {
                bits[index as usize] = 0;
                // Encode the updated status list
                Ok(encode_lst(bits))
            } else {
                Err(StatusError::InvalidIndex)?
            }
        }
        Status::INVALID => {
            if let Some(_) = bits.get(index as usize) {
                bits[index as usize] = 1;
                Ok(encode_lst(bits))
            } else {
                Err(StatusError::InvalidIndex)?
            }
        }
        Status::SUSPENDED => {
            if let Some(_) = bits.get(index as usize) {
                bits[index as usize] = 2;
                Ok(encode_lst(bits))
            } else {
                Err(StatusError::InvalidIndex)?
            }
        }
        Status::APPLICATIONSPECIFIC => {
            if let Some(_) = bits.get(index as usize) {
                bits[index as usize] = 3;
                Ok(encode_lst(bits))
            } else {
                Err(StatusError::InvalidIndex)?
            }
        }
    }
}
