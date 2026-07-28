use axum::{
    Extension,
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::{
    domain::models::credential::Issuer,
    server::{AppState, error::ApiError},
};

use super::{request::StatusesRequest, to_domain_entry};

pub async fn publish_status(
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

    let sub = format!(
        "https://{}/api/v1/status-lists/{list_id}",
        appstate.server_domain
    );

    use crate::domain::models::status_list::StatusListRecord;
    StatusListRecord::publish(
        appstate.service.status_list_repo(),
        appstate.service.history_repo(),
        list_id,
        Issuer(issuer),
        sub,
        statuses,
        appstate.token_exp_secs,
        appstate.max_serialized_list_size,
    )
    .await?;

    Ok(StatusCode::CREATED.into_response())
}
