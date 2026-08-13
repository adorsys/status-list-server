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
///
/// `err(level = "info")` for the reason on `update_status`: the default ERROR
/// level would page on write contention and on a racing publish, both 409s the
/// response layer already logs at the right severity.
#[tracing::instrument(skip_all, fields(list_id = %list_id, issuer = %issuer), err(level = "info", Debug))]
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

        let err = match result {
            Ok(_) => panic!("expected error for invalid list_id"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
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

        let err = match res2 {
            Ok(_) => panic!("expected conflict error for duplicate list_id"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::CONFLICT);
    }

    /// The losing publisher of a `list_id` race gets 409, not 500 — end to end,
    /// on a real backend.
    ///
    /// `test_token_conflict` above proves the same thing over the in-memory
    /// adapter, where `AlreadyExists` is returned by a `HashMap` lookup. That
    /// says nothing about a relational backend, where the conflict surfaces as a
    /// driver error raised *inside* an open transaction and has to survive the
    /// rollback with its classification intact:
    ///
    /// `sql_err()` → `RepositoryError::DuplicateEntry` (`sql::store::map_insert_err`)
    /// → `StatusListError::AlreadyExists` (`impl From<RepositoryError>` in `outbound::sql`)
    /// → **409** (`server::error`).
    ///
    /// Only the first hop can vary by backend, so the store's own
    /// `assert_duplicate_list_id_is_conflict` carries the
    /// per-backend burden — including the proof that the rolled-back publish
    /// leaves neither a snapshot nor a modified row. What *this* test adds is
    /// that the remaining hops are wired up at all: that the classification the
    /// store produces actually reaches the client as a status code.
    #[cfg(any(feature = "postgres-tests", feature = "mysql"))]
    async fn assert_publish_duplicate_is_conflict(
        db: std::sync::Arc<sea_orm::DatabaseConnection>,
        issuer: &str,
        backend: &str,
    ) {
        use crate::domain::models::credential::{Credential, Issuer, PublicJwk};
        use crate::test_fixtures::TEST_EC_PUBLIC_JWK;
        use crate::test_utils::test_app_state;

        let app_state = test_app_state(Some(db)).await;

        // status_lists.issuer is a foreign key onto credentials.issuer. Seeded
        // through the service rather than the store so this test depends only on
        // the domain API, not on the persistence schema.
        app_state
            .service
            .publish_credential(Credential {
                issuer: Issuer(issuer.to_string()),
                public_key: PublicJwk::try_new(TEST_EC_PUBLIC_JWK.as_bytes().to_vec()).unwrap(),
            })
            .await
            .unwrap();

        // The handler rejects a non-UUID list_id before reaching the service.
        let list_id = uuid::Uuid::new_v4().to_string();
        let publish = || {
            let state = app_state.clone();
            let list_id = list_id.clone();
            async move {
                publish_status(
                    State(state),
                    Extension(issuer.to_string()),
                    Path(list_id),
                    Json(StatusesRequest {
                        statuses: vec![RequestStatusEntry {
                            index: 0,
                            status: RequestStatus::VALID,
                        }],
                    }),
                )
                .await
            }
        };

        let created = publish()
            .await
            .unwrap_or_else(|e| panic!("first publish should succeed on {backend}: {e:?}"))
            .into_response();
        assert_eq!(
            created.status(),
            StatusCode::CREATED,
            "first publish should create the list on {backend}"
        );

        let err = match publish().await {
            Ok(_) => panic!("the losing publisher must not report success on {backend}"),
            Err(e) => e,
        };
        assert_eq!(
            err.status,
            StatusCode::CONFLICT,
            "a duplicate publish must map to 409, not 500, on {backend}"
        );
        // The status code alone does not pin the contract: 409 is also the
        // credential-conflict code. Assert the documented error identity too.
        assert_eq!(
            err.error, "status_list_already_exists",
            "the 409 must carry the status-list conflict code on {backend}"
        );
    }

    /// Postgres is the production backend, and the one where this could
    /// plausibly diverge: a failed statement poisons the transaction (`25P02`),
    /// so a classification read from the rollback rather than from the original
    /// `23505` would degrade to a 500 here and nowhere else.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn test_postgres_publish_duplicate_returns_409_not_500() {
        let test_db =
            crate::outbound::sql::test_containers::postgres_helpers::postgres_connection().await;
        assert_publish_duplicate_is_conflict(
            test_db.db.clone(),
            "issuer-race-postgres",
            "Postgres",
        )
        .await;
    }

    /// The same end-to-end proof on MySQL, whose driver reports duplicate keys
    /// in a different wire format (`1062`) that `sql_err()` has to normalise.
    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_publish_duplicate_returns_409_not_500() {
        let test_db =
            crate::outbound::sql::test_containers::mysql_helpers::MysqlTestDb::start().await;
        assert_publish_duplicate_is_conflict(
            test_db.connection().await,
            "issuer-race-mysql",
            "MySQL",
        )
        .await;
    }

    /// The snapshot-disabled publish path must also return 409, not 500.
    ///
    /// `snapshot_retention_secs = 0` builds a `Service` with no snapshot repo,
    /// so `publish_status_list` takes its `None` branch into the plain
    /// non-transactional `insert` — a different duplicate-classification call
    /// site from `insert_with_snapshot`, and the one no other end-to-end test
    /// covers. This matters more since `publish_status_list` stopped
    /// pre-checking with `find`: the constraint is now the only thing standing
    /// between a duplicate publish and a 500.
    #[tokio::test]
    async fn test_publish_duplicate_without_snapshots_returns_409() {
        use crate::domain::models::credential::{Credential, Issuer, PublicJwk};
        use crate::test_fixtures::TEST_EC_PUBLIC_JWK;
        use crate::test_utils::test_app_state_without_snapshots;

        let app_state = test_app_state_without_snapshots().await;
        assert!(
            app_state.service.snapshot_repo().is_none(),
            "this test is meaningless unless the snapshot repo is actually absent"
        );

        let issuer = "issuer-no-snapshots";
        app_state
            .service
            .publish_credential(Credential {
                issuer: Issuer(issuer.to_string()),
                public_key: PublicJwk::try_new(TEST_EC_PUBLIC_JWK.as_bytes().to_vec()).unwrap(),
            })
            .await
            .unwrap();

        let list_id = uuid::Uuid::new_v4().to_string();
        let publish = || {
            let state = app_state.clone();
            let list_id = list_id.clone();
            async move {
                publish_status(
                    State(state),
                    Extension(issuer.to_string()),
                    Path(list_id),
                    Json(StatusesRequest {
                        statuses: vec![RequestStatusEntry {
                            index: 0,
                            status: RequestStatus::VALID,
                        }],
                    }),
                )
                .await
            }
        };

        assert_eq!(
            publish()
                .await
                .expect("first publish should succeed")
                .into_response()
                .status(),
            StatusCode::CREATED
        );

        let err = publish()
            .await
            .err()
            .expect("the duplicate publish must not report success");
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.error, "status_list_already_exists");
    }

    /// Registering an issuer twice is a 409.
    ///
    /// `publish_credential` no longer pre-checks with `find`, so this pins that
    /// the primary key on `credentials.issuer` carries the conflict on its own
    /// and still reaches the client as `credentials_already_exist`.
    #[tokio::test]
    async fn test_duplicate_credential_registration_returns_409() {
        use crate::domain::models::credential::{Credential, Issuer, PublicJwk};
        use crate::server::error::ApiError;
        use crate::test_fixtures::TEST_EC_PUBLIC_JWK;

        let app_state = test_app_state(None).await;
        let credential = || Credential {
            issuer: Issuer("issuer-dup-registration".to_string()),
            public_key: PublicJwk::try_new(TEST_EC_PUBLIC_JWK.as_bytes().to_vec()).unwrap(),
        };

        app_state
            .service
            .publish_credential(credential())
            .await
            .expect("first registration should succeed");

        let err: ApiError = app_state
            .service
            .publish_credential(credential())
            .await
            .expect_err("the second registration must be rejected")
            .into();
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.error, "credentials_already_exist");
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
