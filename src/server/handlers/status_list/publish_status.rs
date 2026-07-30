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

use super::utils::request::StatusesRequest;

/// Publish a new status list.
///
/// Handle PUT /status-lists/{list_id}/statuses request.
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
        .map(Into::into)
        .collect::<Vec<_>>();

    let sub = format!(
        "https://{}/api/v1/status-lists/{list_id}",
        appstate.server_domain
    );

    appstate
        .service
        .publish_status_list(
            list_id,
            Issuer(issuer),
            sub,
            statuses,
            appstate.token_exp_secs,
            appstate.max_status_index,
            appstate.max_statuses_per_request,
            appstate.max_serialized_list_size,
        )
        .await?;

    Ok(StatusCode::CREATED.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::handlers::status_list::utils::request::{
        Status as RequestStatus, StatusEntry as RequestStatusEntry,
    };
    use crate::test_utils::test_app_state;

    #[tokio::test]
    async fn test_publish_token_status_invalid_list_id() {
        let appstate = test_app_state(None).await;
        let issuer = "test-issuer".to_string();
        let payload = StatusesRequest { statuses: vec![] };

        let result = publish_status(
            State(appstate),
            Extension(issuer),
            Path("not-a-uuid".to_string()),
            Json(payload),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_publish_status_creates_token() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        let response = publish_status(
            State(app_state.clone()),
            Extension("issuer".to_string()),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::CREATED);

        let token = app_state.service.get_status_list(&token_id).await.unwrap();
        assert_eq!(token.list_id, token_id);
    }

    #[tokio::test]
    async fn test_token_conflict() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        let res1 = publish_status(
            State(app_state.clone()),
            Extension("issuer".to_string()),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::CREATED);

        let res2 = publish_status(
            State(app_state.clone()),
            Extension("issuer".to_string()),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await;

        assert!(res2.is_err());
    }

    #[tokio::test]
    async fn test_publish_status_rejects_too_many_statuses() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.max_statuses_per_request = 1;

        let status_entries = vec![
            RequestStatusEntry {
                index: 0,
                status: RequestStatus::VALID,
            },
            RequestStatusEntry {
                index: 1,
                status: RequestStatus::INVALID,
            },
        ];

        let result = publish_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_publish_status_rejects_index_too_large() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.max_status_index = 10;

        let status_entries = vec![RequestStatusEntry {
            index: 999_999,
            status: RequestStatus::VALID,
        }];

        let result = publish_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_publish_status_rejects_serialized_list_too_large() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.max_serialized_list_size = 4;

        let mut status_entries = Vec::new();
        for i in 0..200 {
            status_entries.push(RequestStatusEntry {
                index: i,
                status: RequestStatus::INVALID,
            });
        }

        let result = publish_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY);
    }
}
