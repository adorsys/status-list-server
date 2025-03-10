use serde_json::Value;
use std::sync::Arc;

use axum::{extract::State, response::IntoResponse};
use hyper::StatusCode;

use crate::{
    model::StatusUpdate, utils::state::AppState
};

//#[axum::debug_handler]
pub async fn update_statuslist(
    State(appstate): State<Arc<AppState>>,
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
            return (StatusCode::BAD_REQUEST, "malformed request body").into_response()
        },
    };
    for update in updates {
        let index = update.index;
    }
}
