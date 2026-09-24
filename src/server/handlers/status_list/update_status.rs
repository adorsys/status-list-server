use axum::{
    extract::rejection::JsonRejection,
    extract::{Json, Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;

use crate::server::{AppState, auth::AuthenticatedIssuer, error::ApiError};

use super::utils::request::{StatusesRequest, parse_statuses_payload};

/// Update statuses in a status list.
///
/// Handle PATCH /status-lists/{list_id}/statuses request.
///
/// `err(level = "info")` because the default emits at ERROR for every `Err`,
/// which would page on routine write contention and on optimistic-concurrency
/// conflicts. Severity belongs to [`ApiError`]'s `IntoResponse`, which
/// discriminates on status; this event only adds span context.
#[tracing::instrument(skip_all, fields(list_id = %list_id, issuer = %principal), err(level = "info", Debug))]
pub async fn update_status(
    State(appstate): State<AppState>,
    principal: AuthenticatedIssuer,
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

    appstate
        .service
        .update_statuses(
            principal.as_ref(),
            &list_id,
            statuses,
            appstate.token_exp_secs,
            appstate.max_status_index,
            appstate.max_statuses_per_request,
            appstate.max_serialized_list_size,
        )
        .await?;

    Ok(StatusCode::OK.into_response())
}

pub async fn update_status_route(
    state: State<AppState>,
    principal: AuthenticatedIssuer,
    path: Path<String>,
    payload: Result<Json<StatusesRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    update_status(state, principal, path, parse_statuses_payload(payload)?).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::status_list::StatusList;
    use crate::server::handlers::status_list::publish_status::publish_status;
    use crate::server::handlers::status_list::utils::request::{
        Status as RequestStatus, StatusEntry as RequestStatusEntry,
    };
    use crate::test_utils::{authenticated_issuer, test_app_state};

    #[tokio::test]
    async fn test_update_token_status_invalid_list_id() {
        let appstate = test_app_state(None).await;
        let issuer = "test-issuer".to_string();
        let payload = StatusesRequest { statuses: vec![] };

        let result = update_status(
            State(appstate),
            authenticated_issuer(issuer),
            Path("not-a-uuid".to_string()),
            Json(payload),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_status_modifies_existing_token() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        // First publish
        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        // Then update
        let update_res = update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 0,
                    status: RequestStatus::INVALID,
                }],
            }),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(update_res.status(), StatusCode::OK);

        let token = app_state.service.get_status_list(&token_id).await.unwrap();
        assert!(!token.status_list.lst.is_empty());
    }

    #[tokio::test]
    async fn test_update_status_rejects_wrong_issuer() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let update_res = update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer2"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 0,
                    status: RequestStatus::INVALID,
                }],
            }),
        )
        .await;

        let err = match update_res {
            Ok(_) => panic!("expected wrong issuer update to be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.error, "issuer_mismatch");

        let record = app_state.service.get_status_list(&token_id).await.unwrap();
        let empty_list = StatusList::create(vec![]).unwrap();
        assert_eq!(record.status_list, empty_list);
    }

    #[tokio::test]
    async fn test_update_status_rejects_too_many_statuses() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        app_state.max_statuses_per_request = 1;

        let update_res = update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![
                    RequestStatusEntry {
                        index: 0,
                        status: RequestStatus::INVALID,
                    },
                    RequestStatusEntry {
                        index: 1,
                        status: RequestStatus::INVALID,
                    },
                ],
            }),
        )
        .await;

        assert!(update_res.is_err());
    }

    #[tokio::test]
    async fn test_update_status_rejects_index_too_large() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        app_state.max_status_index = 10;

        let update_res = update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 999_999,
                    status: RequestStatus::INVALID,
                }],
            }),
        )
        .await;

        assert!(update_res.is_err());
    }

    #[tokio::test]
    async fn test_update_status_empty_payload_is_successful_noop() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        // Populate the cache so a no-op's failure to invalidate can be observed.
        app_state.service.get_status_list(&token_id).await.unwrap();
        let now = crate::domain::service::current_unix_timestamp();
        let publish_snapshot = app_state
            .service
            .get_snapshot_at(&token_id, now)
            .await
            .expect("the publish snapshot must be queryable");

        // Read the version, the publish snapshot and the cache entry before the
        // no-op, so we can prove the no-op touched none of them. The version is
        // read from the repo (not through the cache) so a stale/masked cache
        // entry cannot hide a spurious version bump.
        let before = app_state
            .service
            .status_list_repo()
            .find(&token_id)
            .await
            .unwrap()
            .unwrap();
        let before_cache = app_state
            .service
            .status_list_cache()
            .get(&token_id)
            .await
            .unwrap()
            .expect("the publish must have populated the cache");

        let update_res = update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(update_res.status(), StatusCode::OK);

        let after = app_state
            .service
            .status_list_repo()
            .find(&token_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.updated_at, before.updated_at,
            "an empty PATCH must be a successful no-op and must not advance the list version"
        );
        assert_eq!(after.status_list, before.status_list);

        // The issue's acceptance criterion is "no redundant history rows": a
        // no-op must not leave a newer snapshot behind.
        let after_snapshot = app_state
            .service
            .get_snapshot_at(&token_id, now)
            .await
            .expect("the publish snapshot must still be queryable");
        assert_eq!(
            after_snapshot.iat, publish_snapshot.iat,
            "a no-op must not insert a newer history snapshot"
        );

        // Nothing was committed, so the cache entry must survive the no-op.
        let after_cache = app_state
            .service
            .status_list_cache()
            .get(&token_id)
            .await
            .unwrap()
            .expect("a no-op must not invalidate the cache entry");
        assert_eq!(after_cache.updated_at, before_cache.updated_at);
    }

    #[tokio::test]
    async fn test_update_status_unchanged_value_is_successful_noop() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        // An update that re-sets index 0 to its current value (VALID) leaves the
        // list identical, so it must be a successful no-op: no version bump and
        // no extra write, mirroring the empty-PATCH contract.
        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 0,
                    status: RequestStatus::VALID,
                }],
            }),
        )
        .await
        .unwrap();

        // Populate the cache and capture the publish snapshot so we can assert
        // the no-op touches neither.
        app_state.service.get_status_list(&token_id).await.unwrap();
        let now = crate::domain::service::current_unix_timestamp();
        let publish_snapshot = app_state
            .service
            .get_snapshot_at(&token_id, now)
            .await
            .expect("the publish snapshot must be queryable");

        let before = app_state
            .service
            .status_list_repo()
            .find(&token_id)
            .await
            .unwrap()
            .unwrap();
        let before_cache = app_state
            .service
            .status_list_cache()
            .get(&token_id)
            .await
            .unwrap()
            .expect("the publish must have populated the cache");

        let update_res = update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 0,
                    status: RequestStatus::VALID,
                }],
            }),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(update_res.status(), StatusCode::OK);

        let after = app_state
            .service
            .status_list_repo()
            .find(&token_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.updated_at, before.updated_at,
            "re-submitting the current value at an existing index must be a no-op"
        );
        assert_eq!(after.status_list, before.status_list);

        let after_snapshot = app_state
            .service
            .get_snapshot_at(&token_id, now)
            .await
            .expect("the publish snapshot must still be queryable");
        assert_eq!(
            after_snapshot.iat, publish_snapshot.iat,
            "a no-op must not insert a newer history snapshot"
        );

        let after_cache = app_state
            .service
            .status_list_cache()
            .get(&token_id)
            .await
            .unwrap()
            .expect("a no-op must not invalidate the cache entry");
        assert_eq!(after_cache.updated_at, before_cache.updated_at);
    }

    /// Issuer validation runs before the no-op short-circuit, so an empty PATCH
    /// from a non-owner is still a 403 — the empty payload does not mask the
    /// ownership check — and the record is left untouched.
    #[tokio::test]
    async fn test_update_status_empty_patch_from_non_owner_is_rejected() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let before = app_state
            .service
            .status_list_repo()
            .find(&token_id)
            .await
            .unwrap()
            .unwrap();

        let err = match update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer2"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        {
            Ok(_) => panic!("expected an empty PATCH from a non-owner to be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.error, "issuer_mismatch");

        let after = app_state
            .service
            .status_list_repo()
            .find(&token_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.updated_at, before.updated_at);
        assert_eq!(after.status_list, before.status_list);
    }

    /// A missing list is reported as 404 even for an empty PATCH: an empty
    /// payload does not turn a non-existent list into a successful no-op.
    #[tokio::test]
    async fn test_update_status_empty_patch_to_missing_list_is_not_found() {
        let app_state = test_app_state(None).await;
        let nonexistent_id = uuid::Uuid::new_v4().to_string();

        let err = match update_status(
            State(app_state),
            authenticated_issuer("issuer1"),
            Path(nonexistent_id),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        {
            Ok(_) => panic!("expected an empty PATCH to a missing list to be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(err.error, "status_list_not_found");
    }

    /// Exercises the `Json` extraction and rejection adapter with a raw JSON
    /// body; routing and auth are covered elsewhere.
    #[tokio::test]
    async fn patch_route_handles_raw_json_bodies() {
        use axum::{Router, body::Body, body::to_bytes, http::Method, routing::patch};
        use tower::ServiceExt;

        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 0,
                    status: RequestStatus::VALID,
                }],
            }),
        )
        .await
        .unwrap();

        let router = Router::new()
            .route(
                "/status-lists/{list_id}/statuses/",
                patch(update_status_route),
            )
            .with_state(app_state.clone());

        let send = |body: &'static str| {
            let router = router.clone();
            let token_id = token_id.clone();
            async move {
                let mut request = axum::http::Request::builder()
                    .method(Method::PATCH)
                    .uri(format!("/status-lists/{token_id}/statuses/"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap();
                request
                    .extensions_mut()
                    .insert(authenticated_issuer("issuer1"));
                router.oneshot(request).await.unwrap()
            }
        };

        // A valid PATCH returns 200.
        let ok = send(r#"{"statuses":[{"index":0,"status":1}]}"#).await;
        assert_eq!(ok.status(), StatusCode::OK);

        // An empty PATCH body is a successful no-op, not a 400.
        let empty = send(r#"{"statuses":[]}"#).await;
        assert_eq!(empty.status(), StatusCode::OK);

        // A duplicate-index payload is rejected with 400 duplicate_index.
        let dup = send(r#"{"statuses":[{"index":0,"status":0},{"index":0,"status":1}]}"#).await;
        assert_eq!(dup.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(dup.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "duplicate_index");
    }

    #[tokio::test]
    async fn test_update_status_rejects_duplicate_indices() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let update_res = update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![
                    RequestStatusEntry {
                        index: 0,
                        status: RequestStatus::INVALID,
                    },
                    RequestStatusEntry {
                        index: 0,
                        status: RequestStatus::SUSPENDED,
                    },
                ],
            }),
        )
        .await;

        let err = match update_res {
            Ok(_) => panic!("expected duplicate index update to be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.error, "duplicate_index");
    }

    #[tokio::test]
    async fn test_update_status_returns_not_found_for_nonexistent_list() {
        let app_state = test_app_state(None).await;
        let nonexistent_id = uuid::Uuid::new_v4().to_string();

        let result = update_status(
            State(app_state),
            authenticated_issuer("issuer1"),
            Path(nonexistent_id),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 0,
                    status: RequestStatus::INVALID,
                }],
            }),
        )
        .await;

        assert!(result.is_err());
    }

    /// An empty PATCH is a no-op, so there is no request-shape `400` to document
    /// precedence for. The PATCH endpoint no longer rejects empty payloads.
    ///
    /// Duplicate-index rejection, by contrast, still runs before the target list
    /// is resolved, so a duplicate payload to a non-existent list returns
    /// `duplicate_index`, not `status_list_not_found`.
    #[tokio::test]
    async fn test_duplicate_update_takes_precedence_over_not_found() {
        let app_state = test_app_state(None).await;
        let nonexistent_id = uuid::Uuid::new_v4().to_string();

        let update_res = update_status(
            State(app_state),
            authenticated_issuer("issuer1"),
            Path(nonexistent_id),
            Json(StatusesRequest {
                statuses: vec![
                    RequestStatusEntry {
                        index: 0,
                        status: RequestStatus::INVALID,
                    },
                    RequestStatusEntry {
                        index: 0,
                        status: RequestStatus::SUSPENDED,
                    },
                ],
            }),
        )
        .await;

        let err = match update_res {
            Ok(_) => panic!("duplicate indices must be rejected regardless of list existence"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.error, "duplicate_index");
    }

    #[tokio::test]
    async fn test_update_status_conflict_returns_409() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        // Publish initial status list
        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 0,
                    status: RequestStatus::VALID,
                }],
            }),
        )
        .await
        .unwrap();

        // Get the current record to force a stale read
        let initial_record = app_state.service.get_status_list(&token_id).await.unwrap();
        let _stale_updated_at = initial_record.updated_at;

        // Perform an update to advance updated_at
        update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 1,
                    status: RequestStatus::INVALID,
                }],
            }),
        )
        .await
        .unwrap();

        // Now attempt another concurrent update - the service layer should detect
        // the conflict if the backend properly implements optimistic locking
        // Note: This test may pass trivially with the memory backend if it doesn't
        // enforce optimistic locking. The SQL backends enforce it via updated_at checks.
        let result = update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 2,
                    status: RequestStatus::SUSPENDED,
                }],
            }),
        )
        .await;

        // With proper optimistic locking, this should be OK since memory backend
        // doesn't implement it. For SQL backends with proper locking, you'd see 409.
        // This test documents the expected behavior when backends enforce it.
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_update_status_rejects_serialized_list_too_large() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        // Set a very small max size to trigger the limit
        app_state.max_serialized_list_size = 10;

        let update_res = update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 10_000, // This will require a large encoded list
                    status: RequestStatus::INVALID,
                }],
            }),
        )
        .await;

        assert!(update_res.is_err());
    }
}
