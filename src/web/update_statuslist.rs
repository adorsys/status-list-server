use anyhow::Ok;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;
use serde_json::Value;
use std::sync::Arc;

use crate::{database::repository::Repository, model::StatusUpdate, utils::state::AppState};

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

    let updates = serde_json::to_vec(&body).unwrap();
    let updates: Vec<StatusUpdate> = match serde_json::from_slice(&updates) {
        Ok(updates) => updates,
        Err(e) => {
            tracing::error!("error: {e}");
            return (StatusCode::BAD_REQUEST, "malformed request body").into_response();
        }
    };

    // fetch the statuslist from the database
    if let Some(store) = appstate.repository {
        let status_list = match store
            .status_list_token_repository
            .find_one_by(list_id)
            .await
        {
            Ok(status_list_token) => {
                let lst = status_list_token.status_list.lst;
                // base64url decode lst for status update
             
            }
            Err(err) => {
                tracing::error!("error: {err:?}");
                return (StatusCode::BAD_REQUEST, "failed to fetch status list").into_response();
            }
        };
    };

}

pub fn update(lst: String, updates: Vec<StatusUpdate>) -> anyhow::Result<bool>{
    let decoded_lst = base64url::decode(&lst)?;
    

    Ok(true)
}