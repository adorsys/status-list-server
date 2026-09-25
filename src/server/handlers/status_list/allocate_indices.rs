use axum::{
    Json,
    extract::rejection::JsonRejection,
    extract::{Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};

use crate::server::{AppState, auth::AuthenticatedIssuer, error::ApiError};

#[derive(Debug, Deserialize)]
pub struct AllocationRequest {
    pub count: u32,
}

#[derive(Debug, Serialize)]
pub(super) struct AllocationResponse {
    pub indices: Vec<i32>,
}

#[tracing::instrument(skip_all, fields(list_id = %list_id, issuer = %principal), err(level = "info", Debug))]
pub async fn allocate_indices(
    State(appstate): State<AppState>,
    principal: AuthenticatedIssuer,
    Path(list_id): Path<String>,
    Json(payload): Json<AllocationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Err(e) = uuid::Uuid::try_parse(&list_id) {
        return Err(ApiError::bad_request(
            "invalid_list_id",
            format!("Invalid list_id format: {e}"),
        ));
    }

    let issuer = principal.into();
    let indices = appstate
        .service
        .allocate_indices(&issuer, &list_id, payload.count)
        .await?;

    Ok((StatusCode::CREATED, Json(AllocationResponse { indices })).into_response())
}

pub async fn allocate_indices_route(
    state: State<AppState>,
    principal: AuthenticatedIssuer,
    path: Path<String>,
    payload: Result<Json<AllocationRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let payload = payload.map_err(|err| {
        ApiError::bad_request(
            "invalid_request_body",
            format!("Invalid allocation request body: {err}"),
        )
    })?;
    allocate_indices(state, principal, path, payload).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::domain::models::status_list::{Status, StatusList, StatusListRecord};
    use crate::test_utils::{authenticated_issuer, test_app_state};
    use axum::{Router, body::Body, body::to_bytes, routing::post};
    use tower::ServiceExt;

    #[tokio::test]
    async fn allocation_route_returns_fresh_indices_and_records_them() {
        let list_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        app_state
            .service
            .status_list_repo()
            .insert(
                StatusListRecord {
                    list_id: list_id.clone(),
                    issuer: Issuer("issuer".to_string()),
                    status_list: StatusList::create_with_options(
                        vec![],
                        Some(2),
                        Status::ApplicationSpecific(15),
                    )
                    .unwrap(),
                    sub: format!("https://example.test/{list_id}"),
                    updated_at: 1,
                },
                u64::MAX,
            )
            .await
            .unwrap();

        let router = Router::new()
            .route(
                "/status-lists/{list_id}/allocations",
                post(allocate_indices_route),
            )
            .with_state(app_state);

        let call = |count: u32| {
            let list_id = list_id.clone();
            let mut request = axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri(format!("/status-lists/{list_id}/allocations"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"count":{count}}}"#)))
                .unwrap();
            request
                .extensions_mut()
                .insert(authenticated_issuer("issuer"));
            router.clone().oneshot(request)
        };

        let first = call(1).await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let body = to_bytes(first.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["indices"], serde_json::json!([0]));

        let second = call(1).await.unwrap();
        assert_eq!(second.status(), StatusCode::CREATED);
        let body = to_bytes(second.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["indices"], serde_json::json!([1]));

        let exhausted = call(1).await.unwrap();
        assert_eq!(exhausted.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(exhausted.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "allocation_exhausted");
    }
}
