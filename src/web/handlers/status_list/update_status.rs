use axum::{
    Extension,
    extract::{Json, Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;
use time::OffsetDateTime;

use crate::{
    models::StatusesRequest,
    utils::{
        bits_validation::BitFlag,
        errors::Error,
        lst_gen::{AbuseLimits, update_status_list},
        state::AppState,
    },
    web::errors::ApiError,
};

use super::error::StatusListError;
use super::publish_status::persist_historical_snapshot;

/// Computes the next `updated_at` for an optimistic-concurrency write.
///
/// Two distinct concerns, both required — do not drop either:
///   * the `WHERE updated_at = previous` guard in `update_one` handles
///     *concurrency* (a racing writer loses the race);
///   * the `.max(previous + 1)` here handles *clock granularity*.
///
/// `updated_at` is unix seconds, so two writers in the same second both read the
/// same `previous` and both see `now == previous`. If the stamp did not advance,
/// the first write would leave `updated_at` unchanged and the second writer's
/// guard would still match — both would succeed, silently losing a flip. Forcing
/// the value to strictly increase guarantees the guard moves, so the loser's
/// `WHERE` misses. Dropping the `+ 1` reintroduces the same-second lost update.
fn next_updated_at(previous: i64, now: i64) -> i64 {
    now.max(previous + 1)
}

/// Update status entries in an existing status list.
pub async fn update_status(
    State(appstate): State<AppState>,
    Extension(issuer): Extension<String>,
    Path(list_id): Path<String>,
    Json(payload): Json<StatusesRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate list_id as UUID
    if let Err(e) = uuid::Uuid::try_parse(&list_id) {
        return Err(StatusListError::InvalidListId(e.to_string()).into());
    }

    let count = payload.statuses.len();
    if count > appstate.max_statuses_per_request {
        tracing::warn!(
            "Rejecting update: {count} statuses exceeds maximum {}",
            appstate.max_statuses_per_request
        );
        return Err(StatusListError::TooManyStatuses {
            count,
            max: appstate.max_statuses_per_request,
        }
        .into());
    }

    let store = &appstate.status_list_repo;

    // Fetch the existing token
    let record = store
        .find_one_by(&list_id)
        .await?
        .ok_or(StatusListError::StatusListNotFound)?;

    // Check if the request issuer matches the token issuer
    if record.issuer != issuer {
        tracing::error!(
            "Issuer mismatch: expected {}, got {}",
            record.issuer,
            issuer
        );
        return Err(StatusListError::IssuerMismatch.into());
    }

    let bits = if let Some(bits) = BitFlag::new(record.status_list.bits) {
        Ok(bits)
    } else {
        Err(StatusListError::Generic(format!(
            "Invalid 'bits' value: {}. Allowed values are 1, 2, 4, 8.",
            record.status_list.bits
        )))
    }?;

    let limits = AbuseLimits::new(appstate.max_status_index, appstate.max_serialized_list_size);

    // Update the status list
    let updated_lst = update_status_list(
        record.status_list.lst.clone(),
        payload.statuses,
        bits.value(),
        &limits,
    )
    .map_err(|e| {
        tracing::error!("update_status_list failed: {e:?}");
        match e {
            Error::Generic(msg) => StatusListError::Generic(msg),
            Error::InvalidIndex => StatusListError::InvalidIndex,
            Error::IndexTooLarge(idx) => StatusListError::IndexTooLarge(idx),
            Error::SerializedListTooLarge { .. } => StatusListError::StatusTooLarge,
            _ => StatusListError::Generic(e.to_string()),
        }
    })?;

    // The timestamp read here is the optimistic-concurrency guard: the write
    // below only lands if `updated_at` is still this value, so a racing writer
    // that already moved it is rejected instead of silently overwritten.
    let previous_updated_at = record.updated_at;

    let mut exact_status_list = record;
    exact_status_list.status_list.lst = updated_lst.lst;
    exact_status_list.status_list.bits = updated_lst.bits;
    // Strictly-advancing stamp so the optimistic guard always moves; see
    // `next_updated_at` for why the `+ 1` is load-bearing.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    exact_status_list.updated_at = next_updated_at(previous_updated_at, now);

    // Save the updated token under the optimistic guard.
    let updated = store
        .update_one(
            &exact_status_list.list_id,
            exact_status_list.clone(),
            previous_updated_at,
        )
        .await?;

    if !updated {
        // Guard did not match: a concurrent writer won the race (or the row was
        // deleted). Return 409 *before* recording a snapshot or invalidating the
        // cache, so nothing is persisted for a write that never landed.
        //
        // Logged at info, not warn: under contention an optimistic conflict is
        // the expected, correct outcome, not an anomaly — warn would pollute
        // dashboards and trip alerting during exactly the high-load bursts where
        // conflicts are normal.
        tracing::info!(
            list_id = ?exact_status_list.list_id,
            "Concurrent update conflict; write rejected"
        );
        return Err(StatusListError::UpdateConflict.into());
    }

    persist_historical_snapshot(&appstate, &exact_status_list).await?;

    // Invalidate cache entry to ensure next read fetches the updated record
    appstate.cache.invalidate(&exact_status_list.list_id).await;
    tracing::info!(
        "Invalidated cache for status list: {}",
        exact_status_list.list_id
    );

    Ok(StatusCode::OK.into_response())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Arc;

    use axum::{
        Extension,
        extract::{Path, State},
        response::IntoResponse,
    };
    use hyper::StatusCode;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use crate::{
        models::{
            Status, StatusEntry, StatusList, StatusListRecord, StatusesRequest, status_lists,
        },
        test_utils::test_app_state,
        utils::lst_gen::{AbuseLimits, create_status_list},
    };

    const LIMITS: AbuseLimits = AbuseLimits::unlimited();

    #[tokio::test]
    async fn test_update_token_status_invalid_list_id() {
        let appstate = test_app_state(None).await;
        let issuer = "test-issuer".to_string();
        let payload = StatusesRequest { statuses: vec![] };

        let result = update_status(
            State(appstate.clone()),
            Extension(issuer),
            Path("invalid-uuid".to_string()),
            Json(payload),
        )
        .await;

        match result {
            Err(err) => {
                assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
            }
            Ok(_) => panic!("Expected error but got Ok"),
        }
    }

    #[tokio::test]
    async fn test_update_status_modifies_existing_token() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = uuid::Uuid::new_v4().to_string();
        let initial_bits = 2;

        // Initial token setup
        let original_status_list = StatusList {
            bits: initial_bits,
            lst: create_status_list(
                vec![
                    StatusEntry {
                        index: 0,
                        status: Status::VALID,
                    },
                    StatusEntry {
                        index: 1,
                        status: Status::VALID,
                    },
                ],
                &LIMITS,
            )
            .unwrap()
            .lst,
        };

        let existing_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: original_status_list,
            sub: "issuer".to_string(),
            updated_at: 0,
        };

        // Update payload that flips status at index 1 to INVALID
        let update_payload = StatusesRequest {
            statuses: vec![StatusEntry {
                index: 1,
                status: Status::INVALID,
            }],
        };

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![existing_token.clone()], // for find_one_by
                ])
                .append_exec_results(vec![
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // guarded update_many
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    }, // status_list_history insert
                ])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;
        let response = update_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(update_payload),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Exceeding `max_statuses_per_request` returns 400 (#171).
    #[tokio::test]
    async fn test_update_status_rejects_too_many_statuses() {
        let appstate = test_app_state(None).await;
        let mut appstate = appstate;
        appstate.max_statuses_per_request = 1;
        let token_id = uuid::Uuid::new_v4().to_string();
        let payload = StatusesRequest {
            statuses: vec![
                StatusEntry {
                    index: 0,
                    status: Status::VALID,
                },
                StatusEntry {
                    index: 1,
                    status: Status::INVALID,
                },
            ],
        };

        let response = match update_status(
            State(appstate),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(payload),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Index exceeding `max_status_index` returns 400 (#171).
    #[tokio::test]
    async fn test_update_status_rejects_index_too_large() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = uuid::Uuid::new_v4().to_string();
        let initial_bits = 1;

        let original_status_list = StatusList {
            bits: initial_bits,
            lst: create_status_list(
                vec![StatusEntry {
                    index: 0,
                    status: Status::VALID,
                }],
                &LIMITS,
            )
            .unwrap()
            .lst,
        };
        let existing_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: original_status_list,
            sub: "issuer".to_string(),
            updated_at: 0,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![existing_token],
                    vec![],
                ])
                .into_connection(),
        );
        let mut appstate = test_app_state(Some(db_conn.clone())).await;
        appstate.max_status_index = 1;
        let payload = StatusesRequest {
            statuses: vec![StatusEntry {
                index: 999_999,
                status: Status::INVALID,
            }],
        };

        let response = match update_status(
            State(appstate),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(payload),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Serialized list exceeding `max_serialized_list_size` returns 422 (#171).
    #[tokio::test]
    async fn test_update_status_rejects_serialized_list_too_large() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = uuid::Uuid::new_v4().to_string();
        let initial_bits = 1;

        let original_status_list = StatusList {
            bits: initial_bits,
            lst: create_status_list(
                vec![StatusEntry {
                    index: 0,
                    status: Status::VALID,
                }],
                &LIMITS,
            )
            .unwrap()
            .lst,
        };
        let existing_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: original_status_list,
            sub: "issuer".to_string(),
            updated_at: 0,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![
                    vec![existing_token],
                    vec![],
                ])
                .into_connection(),
        );
        let mut appstate = test_app_state(Some(db_conn.clone())).await;
        appstate.max_serialized_list_size = 1;
        let payload = StatusesRequest {
            statuses: vec![StatusEntry {
                index: 9999,
                status: Status::INVALID,
            }],
        };

        let response = match update_status(
            State(appstate),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(payload),
        )
        .await
        {
            Ok(_) => panic!("Expected an error but got Ok"),
            Err(err) => err.into_response(),
        };
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Pins the load-bearing monotonicity of the optimistic stamp. If someone
    /// "simplifies" `next_updated_at` down to `now` (dropping the `+ 1`), the
    /// same-second case below fails here instead of silently reintroducing the
    /// lost-update bug in production.
    #[test]
    fn test_next_updated_at_strictly_advances_within_same_second() {
        // Same wall-clock second as the previous write: must still advance.
        assert_eq!(next_updated_at(1000, 1000), 1001);
        // Clock went backwards / equal: never emit a stale-or-equal stamp.
        assert_eq!(next_updated_at(1000, 999), 1001);
        // Clock advanced normally: use the real time.
        assert_eq!(next_updated_at(1000, 2000), 2000);
    }

    #[tokio::test]
    async fn test_update_status_conflict_returns_409() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token_id = uuid::Uuid::new_v4().to_string();

        let existing_token = StatusListRecord {
            list_id: token_id.clone(),
            issuer: "issuer".to_string(),
            status_list: StatusList {
                bits: 2,
                lst: create_status_list(
                    vec![StatusEntry {
                        index: 0,
                        status: Status::VALID,
                    }],
                    &LIMITS,
                )
                .unwrap()
                .lst,
            },
            sub: "issuer".to_string(),
            updated_at: 0,
        };

        let update_payload = StatusesRequest {
            statuses: vec![StatusEntry {
                index: 0,
                status: Status::INVALID,
            }],
        };

        // find_one_by sees the row, but the guarded UPDATE affects 0 rows: a
        // concurrent writer already moved `updated_at`.
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    existing_token.clone(),
                ]])
                .append_exec_results(vec![MockExecResult {
                    rows_affected: 0,
                    last_insert_id: 0,
                }])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;
        let response = match update_status(
            State(app_state),
            Extension("issuer".to_string()),
            Path(token_id),
            Json(update_payload),
        )
        .await
        {
            Ok(_) => panic!("conflicting write must not report success"),
            Err(err) => err.into_response(),
        };

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
