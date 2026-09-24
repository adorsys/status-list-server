use axum::{
    Json,
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::server::{AppState, error::ApiError};

use super::utils::constants::{AGGREGATION_DEFAULT_LIMIT, AGGREGATION_MAX_LIMIT};

#[derive(Debug, Deserialize)]
pub struct AggregationQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct AggregationResponse {
    pub(super) status_lists: Vec<String>,
    /// Opaque cursor for the next page; `null` on the last page.
    pub(super) next_cursor: Option<String>,
}

/// Lets a future change of paging key tell old cursors from new ones.
const CURSOR_VERSION: &str = "v1:";

/// Bounds decoding work; far above the length of any stored `list_id`.
const MAX_CURSOR_LEN: usize = 2048;

/// Handle GET /aggregation: one page of at most `AGGREGATION_MAX_LIMIT` status
/// list URIs. No total count is returned, as counting every row is unbounded.
///
/// Errors log at INFO: on this public endpoint they are mostly malformed queries.
#[tracing::instrument(skip_all, err(level = "info", Debug))]
pub async fn get_aggregation(
    State(state): State<AppState>,
    query_result: Result<Query<AggregationQuery>, QueryRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let query = match query_result {
        Ok(Query(q)) => q,
        Err(e) => {
            return Err(ApiError::bad_request(
                "invalid_query",
                format!("Failed to parse query parameters: {e}"),
            ));
        }
    };

    let limit = query.limit.unwrap_or(AGGREGATION_DEFAULT_LIMIT);
    if !(1..=AGGREGATION_MAX_LIMIT).contains(&limit) {
        return Err(ApiError::bad_request(
            "invalid_query",
            format!("limit must be between 1 and {AGGREGATION_MAX_LIMIT}, got {limit}"),
        ));
    }
    let after = query.cursor.as_deref().map(decode_cursor).transpose()?;

    let page = state.service.list_uris(after.as_deref(), limit).await?;
    let next_cursor = page.next_after.as_deref().map(encode_cursor);

    let mut headers = HeaderMap::new();
    if let Some(cursor) = &next_cursor {
        // RFC 8288 next link; the base64url cursor needs no percent-encoding.
        let link = format!("<?limit={limit}&cursor={cursor}>; rel=\"next\"");
        headers.insert(
            header::LINK,
            HeaderValue::from_str(&link).map_err(ApiError::internal)?,
        );
    }

    tracing::info!(
        "Serving status list aggregation page with {} list(s)",
        page.status_lists.len()
    );

    Ok((
        StatusCode::OK,
        headers,
        Json(AggregationResponse {
            status_lists: page.status_lists,
            next_cursor,
        }),
    ))
}

/// Encodes the last `list_id` of a page as an opaque cursor. The `list_id` is
/// kept exactly as stored; normalising it would shift the page boundary.
fn encode_cursor(list_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{CURSOR_VERSION}{list_id}"))
}

/// Deliberately not restricted to UUIDs: rows stored before `list_id` was
/// validated would otherwise produce a `next_cursor` that strands the walk.
fn decode_cursor(cursor: &str) -> Result<String, ApiError> {
    (cursor.len() <= MAX_CURSOR_LEN)
        .then_some(cursor)
        .and_then(|cursor| URL_SAFE_NO_PAD.decode(cursor).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|decoded| {
            decoded
                .strip_prefix(CURSOR_VERSION)
                .filter(|list_id| !list_id.is_empty())
                .map(str::to_string)
        })
        .ok_or_else(|| {
            ApiError::bad_request(
                "invalid_query",
                "cursor is not a value returned by this endpoint",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::test_utils::test_app_state;
    use axum::body::to_bytes;
    use axum::response::Response;
    use std::collections::BTreeSet;

    /// Publishes a list with a fresh `list_id` and returns its URI.
    async fn publish(state: &AppState, issuer: &str) -> String {
        let list_id = uuid::Uuid::new_v4().to_string();
        let sub = format!("https://example.com/api/v1/status-lists/{list_id}");
        state
            .service
            .publish_status_list(
                list_id,
                Issuer(issuer.into()),
                sub.clone(),
                vec![],
                900,
                100_000,
                5_000,
                1_048_576,
                u64::MAX,
            )
            .await
            .unwrap();
        sub
    }

    fn query(
        limit: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<Query<AggregationQuery>, QueryRejection> {
        Ok(Query(AggregationQuery {
            limit,
            cursor: cursor.map(str::to_string),
        }))
    }

    async fn get(
        state: &AppState,
        limit: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<Response, ApiError> {
        get_aggregation(State(state.clone()), query(limit, cursor))
            .await
            .map(IntoResponse::into_response)
    }

    async fn body(response: Response) -> AggregationResponse {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_aggregation_empty_when_no_lists() {
        let state = test_app_state(None).await;
        let response = get(&state, None, None).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::LINK).is_none());

        let page = body(response).await;
        assert!(page.status_lists.is_empty());
        assert_eq!(page.next_cursor, None);
    }

    #[tokio::test]
    async fn test_aggregation_last_page_serializes_null_cursor() {
        let state = test_app_state(None).await;
        let response = get(&state, None, None).await.unwrap();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["next_cursor"].is_null());
        assert!(json.as_object().unwrap().contains_key("next_cursor"));
    }

    #[tokio::test]
    async fn test_aggregation_returns_uris_from_multiple_issuers() {
        let state = test_app_state(None).await;
        let sub1 = publish(&state, "issuer1").await;
        let sub2 = publish(&state, "issuer2").await;

        let page = body(get(&state, None, None).await.unwrap()).await;
        let got: BTreeSet<_> = page.status_lists.into_iter().collect();
        assert_eq!(got, BTreeSet::from([sub1, sub2]));
        assert_eq!(page.next_cursor, None);
    }

    /// Asserts completeness, not order, which differs by backend.
    #[tokio::test]
    async fn test_aggregation_cursor_walk_returns_every_list_once() {
        let state = test_app_state(None).await;
        let mut expected = BTreeSet::new();
        for _ in 0..5 {
            expected.insert(publish(&state, "issuer1").await);
        }

        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let response = get(&state, Some(2), cursor.as_deref()).await.unwrap();
            let link = response
                .headers()
                .get(header::LINK)
                .map(|v| v.to_str().unwrap().to_string());
            let page = body(response).await;
            pages += 1;
            seen.extend(page.status_lists);

            match (&page.next_cursor, link) {
                (Some(next), Some(link)) => {
                    assert_eq!(link, format!("<?limit=2&cursor={next}>; rel=\"next\""));
                }
                (None, None) => {}
                (body_cursor, link) => {
                    panic!("body cursor {body_cursor:?} and Link {link:?} disagree")
                }
            }

            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        assert_eq!(pages, 3);
        let unique: BTreeSet<_> = seen.iter().cloned().collect();
        assert_eq!(unique.len(), seen.len(), "no list may appear twice");
        assert_eq!(unique, expected, "every list must appear");
    }

    #[tokio::test]
    async fn test_aggregation_without_limit_returns_default_page() {
        let state = test_app_state(None).await;
        for _ in 0..3 {
            publish(&state, "issuer1").await;
        }

        let page = body(get(&state, None, None).await.unwrap()).await;
        assert_eq!(page.status_lists.len(), 3);
        assert_eq!(page.next_cursor, None);
    }

    #[tokio::test]
    async fn test_aggregation_rejects_out_of_range_limit() {
        let state = test_app_state(None).await;
        for limit in [0, AGGREGATION_MAX_LIMIT + 1] {
            let err = get(&state, Some(limit), None).await.unwrap_err();
            assert_eq!(err.status, StatusCode::BAD_REQUEST, "limit={limit}");
            assert_eq!(err.error, "invalid_query", "limit={limit}");
        }
        assert!(get(&state, Some(AGGREGATION_MAX_LIMIT), None).await.is_ok());
    }

    #[tokio::test]
    async fn test_aggregation_rejects_malformed_cursor() {
        let state = test_app_state(None).await;
        for cursor in [
            "not base64!",
            // A bare list_id, without the version tag.
            URL_SAFE_NO_PAD
                .encode("477121aa-b598-419e-916f-1e74654ff38b")
                .as_str(),
            URL_SAFE_NO_PAD
                .encode("v2:477121aa-b598-419e-916f-1e74654ff38b")
                .as_str(),
            URL_SAFE_NO_PAD.encode(CURSOR_VERSION).as_str(),
            URL_SAFE_NO_PAD.encode([0xff, 0xfe]).as_str(),
            encode_cursor(&"a".repeat(MAX_CURSOR_LEN)).as_str(),
        ] {
            let err = get(&state, None, Some(cursor)).await.unwrap_err();
            assert_eq!(err.status, StatusCode::BAD_REQUEST, "cursor={cursor}");
            assert_eq!(err.error, "invalid_query", "cursor={cursor}");
        }
    }

    #[tokio::test]
    async fn test_aggregation_rejects_unparsable_query() {
        let state = test_app_state(None).await;
        let rejection =
            Query::<AggregationQuery>::try_from_uri(&"/aggregation?limit=abc".parse().unwrap())
                .unwrap_err();
        let Err(err) = get_aggregation(State(state), Err(rejection)).await else {
            panic!("an unparsable query must be rejected");
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.error, "invalid_query");
    }

    #[test]
    fn test_cursor_round_trips_list_id_verbatim() {
        for list_id in [
            "477121aa-b598-419e-916f-1e74654ff38b",
            "477121AA-B598-419E-916F-1E74654FF38B",
            "{477121aa-b598-419e-916f-1e74654ff38b}",
            "urn:uuid:477121aa-b598-419e-916f-1e74654ff38b",
            "477121aab598419e916f1e74654ff38b",
            // Stored before list_id had to be a UUID.
            "legacy-list",
            "list with spaces/and?query",
        ] {
            let cursor = encode_cursor(list_id);
            assert_eq!(decode_cursor(&cursor).unwrap(), list_id);
        }
    }

    /// Every accepted `list_id` form, plus a legacy non-UUID one, must round-trip
    /// through the cursor under the backend's collation. `limit=1` makes every
    /// ID a cursor.
    #[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
    async fn assert_aggregation_walk_on_sql(
        db: std::sync::Arc<sea_orm::DatabaseConnection>,
        backend: &str,
    ) {
        use crate::domain::models::credential::{Credential, PublicJwk};
        use crate::test_fixtures::TEST_EC_PUBLIC_JWK;

        let state = test_app_state(Some(db)).await;
        state
            .service
            .publish_credential(Credential {
                issuer: Issuer("issuer1".into()),
                public_key: PublicJwk::try_new(TEST_EC_PUBLIC_JWK.as_bytes().to_vec()).unwrap(),
            })
            .await
            .unwrap();

        // Distinct UUIDs: MySQL's case-insensitive collation would treat an
        // uppercase copy as a duplicate key.
        let uuid = || uuid::Uuid::new_v4();
        let list_ids = [
            uuid().hyphenated().to_string(),
            uuid().hyphenated().to_string().to_uppercase(),
            uuid().braced().to_string(),
            uuid().urn().to_string(),
            uuid().simple().to_string(),
            "legacy-list".to_string(),
        ];
        let mut expected = BTreeSet::new();
        for list_id in list_ids {
            let sub = format!("https://example.com/api/v1/status-lists/{list_id}");
            state
                .service
                .publish_status_list(
                    list_id,
                    Issuer("issuer1".into()),
                    sub.clone(),
                    vec![],
                    900,
                    100_000,
                    5_000,
                    1_048_576,
                    u64::MAX,
                )
                .await
                .unwrap();
            expected.insert(sub);
        }

        for limit in [1, 2] {
            let mut seen = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                let response = get(&state, Some(limit), cursor.as_deref())
                    .await
                    .unwrap_or_else(|e| {
                        panic!("page after {cursor:?} (limit={limit}) on {backend}: {e:?}")
                    });
                let has_link = response.headers().contains_key(header::LINK);
                let page = body(response).await;
                assert_eq!(
                    has_link,
                    page.next_cursor.is_some(),
                    "Link and next_cursor must agree (limit={limit}) on {backend}"
                );
                seen.extend(page.status_lists);
                match page.next_cursor {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }

            let unique: BTreeSet<_> = seen.iter().cloned().collect();
            assert_eq!(
                unique.len(),
                seen.len(),
                "no list may appear twice (limit={limit}) on {backend}"
            );
            assert_eq!(
                unique, expected,
                "every list must appear (limit={limit}) on {backend}"
            );
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_aggregation_walk_end_to_end() {
        let db = crate::test_utils::sqlite_test_db(None).await;
        assert_aggregation_walk_on_sql(db, "SQLite").await;
    }

    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_aggregation_walk_end_to_end() {
        let test_db =
            crate::outbound::sql::test_containers::mysql_helpers::MysqlTestDb::start().await;
        assert_aggregation_walk_on_sql(test_db.connection().await, "MySQL").await;
    }

    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn test_postgres_aggregation_walk_end_to_end() {
        let test_db =
            crate::outbound::sql::test_containers::postgres_helpers::postgres_connection().await;
        assert_aggregation_walk_on_sql(test_db.db.clone(), "Postgres").await;
    }

    /// A legacy non-UUID `list_id` must not strand a walk.
    #[tokio::test]
    async fn test_aggregation_walk_passes_legacy_non_uuid_list_ids() {
        let state = test_app_state(None).await;
        let mut expected = BTreeSet::from([
            publish(&state, "issuer1").await,
            publish(&state, "issuer1").await,
        ]);
        let legacy_sub = "https://example.com/api/v1/status-lists/legacy-list".to_string();
        state
            .service
            .publish_status_list(
                "legacy-list".to_string(),
                Issuer("issuer1".into()),
                legacy_sub.clone(),
                vec![],
                900,
                100_000,
                5_000,
                1_048_576,
                u64::MAX,
            )
            .await
            .unwrap();
        expected.insert(legacy_sub);

        let mut seen = BTreeSet::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = body(get(&state, Some(1), cursor.as_deref()).await.unwrap()).await;
            seen.extend(page.status_lists);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert_eq!(seen, expected);
    }
}
