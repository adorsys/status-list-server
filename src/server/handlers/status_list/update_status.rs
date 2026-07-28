use axum::{
    Extension,
    extract::{Json, Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;

use crate::{
    domain::models::credential::Issuer,
    server::{AppState, error::ApiError},
};

use super::{request::StatusesRequest, to_domain_entry};

pub async fn update_status(
    State(appstate): State<AppState>,
    Extension(issuer): Extension<String>,
    Path(list_id): Path<String>,
    Json(payload): Json<StatusesRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Err(e) = uuid::Uuid::try_parse(&list_id) {
        return Err(ApiError::bad_request(
            "invalid_list_id",
            format!("Invalid list_id format: {e}"),
        ));
    }

    let statuses = payload
        .statuses
        .into_iter()
        .map(to_domain_entry)
        .collect::<Vec<_>>();

    appstate
        .service
        .update_statuses(
            &Issuer(issuer),
            &list_id,
            statuses,
            appstate.token_exp_secs,
            appstate.max_status_index,
            appstate.max_statuses_per_request,
            appstate.max_serialized_list_size,
        )
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
