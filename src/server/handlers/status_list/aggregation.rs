use std::sync::OnceLock;

use axum::{
    extract::{
        Path, Query, State,
        rejection::{PathRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use opentelemetry::{KeyValue, global, metrics::Counter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::models::credential::AggregationId;
use crate::domain::models::status_list::{AGGREGATION_DEFAULT_LIMIT, AGGREGATION_MAX_LIMIT};
use crate::server::{AppState, error::ApiError};
use crate::utils::metrics::{InstrumentSlot, cached_instruments};

use super::utils::conditional::{ConditionalResponse, evaluate_if_none_match};

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

fn aggregation_pages() -> Counter<u64> {
    static COUNTER: InstrumentSlot<Counter<u64>> = OnceLock::new();
    cached_instruments(&COUNTER, || {
        global::meter("status-list-server")
            .u64_counter("aggregation_pages")
            .with_description(
                "Aggregation pages served, by scope (issuer|all) and outcome \
                 (complete|truncated|paged).",
            )
            .build()
    })
}

/// Handle GET /aggregation: every issuer's status lists. Deprecated, but
/// tokens issued before aggregation was scoped to one issuer point here.
#[tracing::instrument(skip_all, err(level = "info", Debug))]
pub async fn get_aggregation(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<AggregationQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    aggregation_page(&state, None, &headers, query).await
}

/// Handle GET /aggregation/{aggregation_id}: one issuer's status lists.
#[tracing::instrument(skip_all, err(level = "info", Debug))]
pub async fn get_issuer_aggregation(
    State(state): State<AppState>,
    aggregation_id: Result<Path<AggregationId>, PathRejection>,
    headers: HeaderMap,
    query: Result<Query<AggregationQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Path(aggregation_id) = aggregation_id.map_err(|_| {
        ApiError::bad_request("invalid_aggregation_id", "aggregation_id must be a UUID")
    })?;
    aggregation_page(&state, Some(aggregation_id), &headers, query).await
}

/// One page of at most `AGGREGATION_MAX_LIMIT` status list URIs, from one
/// issuer when `scope` is given. No total count is returned, as counting every
/// row is unbounded.
///
/// The handlers log its errors at INFO: on these public endpoints they are
/// mostly malformed requests.
async fn aggregation_page(
    state: &AppState,
    scope: Option<AggregationId>,
    headers: &HeaderMap,
    query: Result<Query<AggregationQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|e| {
        ApiError::bad_request(
            "invalid_query",
            format!("Failed to parse query parameters: {e}"),
        )
    })?;
    let limit = query.limit.unwrap_or(AGGREGATION_DEFAULT_LIMIT);
    if !(1..=AGGREGATION_MAX_LIMIT).contains(&limit) {
        return Err(ApiError::bad_request(
            "invalid_query",
            format!("limit must be between 1 and {AGGREGATION_MAX_LIMIT}, got {limit}"),
        ));
    }
    let cursor_scope = scope.map_or_else(|| "all".to_string(), |id| id.to_string());
    let after = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor(&cursor_scope, cursor))
        .transpose()?;

    let page = match scope {
        None => state.service.list_uris(after.as_deref(), limit).await?,
        Some(aggregation_id) => state
            .service
            .list_issuer_uris(aggregation_id, after.as_deref(), limit)
            .await?
            .ok_or_else(|| {
                ApiError::not_found("aggregation_not_found", "No issuer has this aggregation ID")
            })?,
    };
    let next_cursor = page
        .next_after
        .as_deref()
        .map(|list_id| encode_cursor(&cursor_scope, list_id));

    aggregation_pages().add(
        1,
        &[
            KeyValue::new("scope", if scope.is_some() { "issuer" } else { "all" }),
            KeyValue::new(
                "outcome",
                page_outcome(
                    query.cursor.is_some(),
                    query.limit.is_some(),
                    next_cursor.is_some(),
                ),
            ),
        ],
    );
    tracing::info!(
        "Serving status list aggregation page with {} list(s)",
        page.status_lists.len()
    );
    // A draft-21 §9.3 client takes one response as the whole aggregation. The
    // quota normally keeps an issuer's in one page, but not while it is off on
    // running pods, so a request that does not page is refused rather than
    // answered in part. Sending `limit` opts in to paging.
    if scope.is_some() && query.limit.is_none() && query.cursor.is_none() && next_cursor.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "paging_required",
            Some(format!(
                "this aggregation has more than {limit} status lists; send limit to page through it"
            )),
        ));
    }

    let mut response_headers = HeaderMap::new();
    if let Some(cursor) = &next_cursor {
        // RFC 8288 next link. Resolved against the request URI, it keeps the
        // path and so the issuer; the base64url cursor needs no percent-encoding.
        let link = format!("<?limit={limit}&cursor={cursor}>; rel=\"next\"");
        response_headers.insert(
            header::LINK,
            HeaderValue::from_str(&link).map_err(ApiError::internal)?,
        );
    }
    let body = serde_json::to_vec(&AggregationResponse {
        status_lists: page.status_lists,
        next_cursor,
    })
    .map_err(ApiError::internal)?;
    let etag = format!("W/\"{}\"", hex::encode(Sha256::digest(&body)));
    response_headers.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(ApiError::internal)?,
    );

    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok());
    if evaluate_if_none_match(if_none_match, &etag) == ConditionalResponse::NotModified {
        return Ok((StatusCode::NOT_MODIFIED, response_headers).into_response());
    }
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok((StatusCode::OK, response_headers, body).into_response())
}

/// `truncated` is a first page with more lists following, for a client that
/// did not page: served by the unscoped endpoint, refused for one issuer's.
fn page_outcome(has_cursor: bool, has_limit: bool, has_next: bool) -> &'static str {
    match (has_cursor, has_limit, has_next) {
        (false, _, false) => "complete",
        (false, false, true) => "truncated",
        _ => "paged",
    }
}

/// Encodes the last `list_id` of a page as an opaque cursor, bound to `scope`
/// (an aggregation ID, or `all`): replayed on another aggregation, it would
/// skip that one's lists that sort before it. The `list_id` is kept exactly as
/// stored; normalising it would shift the page boundary.
fn encode_cursor(scope: &str, list_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{CURSOR_VERSION}{scope}:{list_id}"))
}

/// Deliberately not restricted to UUIDs: rows stored before `list_id` was
/// validated would otherwise produce a `next_cursor` that strands the walk.
///
/// NUL is the one exception: Postgres rejects it in text, so letting it through
/// is a 500. The trade-off is that a pre-validation `list_id` containing NUL,
/// storable only on MySQL or SQLite, ends a walk at its page.
fn decode_cursor(scope: &str, cursor: &str) -> Result<String, ApiError> {
    (cursor.len() <= MAX_CURSOR_LEN)
        .then_some(cursor)
        .and_then(|cursor| URL_SAFE_NO_PAD.decode(cursor).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|decoded| {
            decoded
                .strip_prefix(CURSOR_VERSION)
                .and_then(|rest| rest.strip_prefix(scope))
                .and_then(|rest| rest.strip_prefix(':'))
                .filter(|list_id| !list_id.is_empty() && !list_id.contains('\0'))
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
    use crate::domain::models::status_list::StatusListError;
    use crate::test_utils::{
        metrics_after, publish_list, publish_list_under_quota, register_issuer, test_app_state,
    };
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use std::collections::BTreeSet;
    use tower::ServiceExt;

    /// Publishes a list with a fresh `list_id` and returns its URI.
    async fn publish(state: &AppState, issuer: &str) -> String {
        publish_list(&state.service, issuer, &uuid::Uuid::new_v4().to_string()).await
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

    async fn get_page(
        state: &AppState,
        scope: Option<AggregationId>,
        limit: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<Response, ApiError> {
        let state = State(state.clone());
        match scope {
            None => get_aggregation(state, HeaderMap::new(), query(limit, cursor)).await,
            Some(aggregation_id) => {
                get_issuer_aggregation(
                    state,
                    Ok(Path(aggregation_id)),
                    HeaderMap::new(),
                    query(limit, cursor),
                )
                .await
            }
        }
    }

    async fn get(
        state: &AppState,
        limit: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<Response, ApiError> {
        get_page(state, None, limit, cursor).await
    }

    async fn get_scoped(
        state: &AppState,
        aggregation_id: AggregationId,
        limit: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<Response, ApiError> {
        get_page(state, Some(aggregation_id), limit, cursor).await
    }

    /// Sends `uri` through the aggregation routes as they are mounted.
    async fn send(state: &AppState, uri: &str) -> Response {
        axum::Router::new()
            .route("/api/v1/aggregation", axum::routing::get(get_aggregation))
            .route(
                "/api/v1/aggregation/{aggregation_id}",
                axum::routing::get(get_issuer_aggregation),
            )
            .with_state(state.clone())
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn link(response: &Response) -> Option<String> {
        response
            .headers()
            .get(header::LINK)
            .map(|value| value.to_str().unwrap().to_string())
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
            let link = link(&response);
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
            // The format before cursors named their aggregation.
            URL_SAFE_NO_PAD
                .encode("v1:477121aa-b598-419e-916f-1e74654ff38b")
                .as_str(),
            URL_SAFE_NO_PAD.encode("v1:all:").as_str(),
            encode_cursor("all", &"a".repeat(MAX_CURSOR_LEN)).as_str(),
            encode_cursor("all", "\0").as_str(),
            encode_cursor("all", "477121aa-b598\0-419e-916f-1e74654ff38b").as_str(),
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
        let Err(err) = get_aggregation(State(state), HeaderMap::new(), Err(rejection)).await else {
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
            "legacy\tlist\n",
        ] {
            let cursor = encode_cursor("all", list_id);
            assert_eq!(decode_cursor("all", &cursor).unwrap(), list_id);
        }
    }

    /// The headline guarantee: an issuer at its full quota still fits in the
    /// page a draft-21 §9.3 client gets, and only its own lists are in it.
    async fn assert_full_quota_is_one_page(state: AppState, backend: &str) {
        let quota = AGGREGATION_DEFAULT_LIMIT as u64;
        let aggregation_id = register_issuer(&state.service, "issuer1").await;
        register_issuer(&state.service, "issuer2").await;
        let other = publish(&state, "issuer2").await;
        let publish_under_quota = || {
            let list_id = uuid::Uuid::new_v4().to_string();
            let service = state.service.clone();
            async move { publish_list_under_quota(&service, "issuer1", &list_id, quota).await }
        };
        for _ in 0..quota {
            publish_under_quota().await.unwrap();
        }
        let over = publish_under_quota().await;
        assert!(
            matches!(over, Err(StatusListError::QuotaExceeded { .. })),
            "the quota must hold on {backend}: {over:?}"
        );

        let response = get_scoped(&state, aggregation_id, None, None)
            .await
            .unwrap();
        assert_eq!(link(&response), None, "on {backend}");
        let page = body(response).await;
        assert_eq!(
            page.status_lists.len(),
            AGGREGATION_DEFAULT_LIMIT,
            "on {backend}"
        );
        assert_eq!(page.next_cursor, None, "on {backend}");
        assert!(!page.status_lists.contains(&other), "on {backend}");
    }

    #[tokio::test]
    async fn test_scoped_aggregation_at_full_quota_is_one_complete_page() {
        assert_full_quota_is_one_page(test_app_state(None).await, "memory").await;
    }

    #[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
    async fn assert_full_quota_is_one_page_on_sql(
        db: std::sync::Arc<sea_orm::DatabaseConnection>,
        backend: &str,
    ) {
        crate::outbound::sql::list_quota::enable(&db, AGGREGATION_DEFAULT_LIMIT as u64)
            .await
            .unwrap();
        assert_full_quota_is_one_page(test_app_state(Some(db)).await, backend).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_scoped_aggregation_at_full_quota_is_one_complete_page() {
        let db = crate::test_utils::sqlite_test_db(None).await;
        assert_full_quota_is_one_page_on_sql(db, "SQLite").await;
    }

    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_scoped_aggregation_at_full_quota_is_one_complete_page() {
        let test_db =
            crate::outbound::sql::test_containers::mysql_helpers::MysqlTestDb::start().await;
        assert_full_quota_is_one_page_on_sql(test_db.connection().await, "MySQL").await;
    }

    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn test_postgres_scoped_aggregation_at_full_quota_is_one_complete_page() {
        let test_db =
            crate::outbound::sql::test_containers::postgres_helpers::postgres_connection().await;
        assert_full_quota_is_one_page_on_sql(test_db.db.clone(), "Postgres").await;
    }

    /// Follows `Link` the way a client does, resolving it against the request
    /// URI, so the walk stays on the issuer's path.
    #[tokio::test]
    async fn test_scoped_walk_follows_link() {
        let state = test_app_state(None).await;
        let aggregation_id = register_issuer(&state.service, "issuer1").await;
        let mut expected = BTreeSet::new();
        for _ in 0..3 {
            expected.insert(publish(&state, "issuer1").await);
        }
        publish(&state, "issuer2").await;

        let mut seen = BTreeSet::new();
        let mut next = Some(
            url::Url::parse(&format!(
                "http://localhost/api/v1/aggregation/{aggregation_id}?limit=2"
            ))
            .unwrap(),
        );
        while let Some(url) = next {
            let response = send(&state, &url[url::Position::BeforePath..]).await;
            assert_eq!(response.status(), StatusCode::OK, "{url}");
            next = link(&response).map(|link| {
                let (target, _) = link.strip_prefix('<').unwrap().split_once('>').unwrap();
                url.join(target).unwrap()
            });
            seen.extend(body(response).await.status_lists);
        }
        assert_eq!(seen, expected);
    }

    /// A cursor from one aggregation, replayed on another, would skip that
    /// one's lists that sort before it.
    #[tokio::test]
    async fn test_cursor_is_bound_to_its_aggregation() {
        let state = test_app_state(None).await;
        let first = register_issuer(&state.service, "issuer1").await;
        let second = register_issuer(&state.service, "issuer2").await;
        for issuer in ["issuer1", "issuer1", "issuer2", "issuer2"] {
            publish(&state, issuer).await;
        }
        for (minted, replayed) in [
            (Some(first), Some(second)),
            (Some(first), None),
            (None, Some(first)),
        ] {
            let cursor = body(get_page(&state, minted, Some(1), None).await.unwrap())
                .await
                .next_cursor
                .unwrap();
            let err = get_page(&state, replayed, Some(1), Some(&cursor))
                .await
                .unwrap_err();
            assert_eq!(
                err.status,
                StatusCode::BAD_REQUEST,
                "{minted:?} on {replayed:?}"
            );
            assert_eq!(err.error, "invalid_query", "{minted:?} on {replayed:?}");
        }
    }

    /// A draft-21 client that does not page must not get part of an issuer's
    /// aggregation as if it were all of it; a client that pages still can.
    #[tokio::test]
    async fn test_unpaged_aggregation_over_one_page_is_refused() {
        let state = test_app_state(None).await;
        let aggregation_id = register_issuer(&state.service, "issuer1").await;
        for _ in 0..=AGGREGATION_DEFAULT_LIMIT {
            publish(&state, "issuer1").await;
        }

        let err = get_scoped(&state, aggregation_id, None, None)
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.error, "paging_required");

        let paged = get_scoped(
            &state,
            aggregation_id,
            Some(AGGREGATION_DEFAULT_LIMIT),
            None,
        )
        .await
        .unwrap();
        assert!(body(paged).await.next_cursor.is_some());
        let unscoped = body(get(&state, None, None).await.unwrap()).await;
        assert!(
            unscoped.next_cursor.is_some(),
            "the unscoped endpoint still pages"
        );
    }

    #[tokio::test]
    async fn test_aggregation_id_is_accepted_in_any_uuid_form() {
        let state = test_app_state(None).await;
        let aggregation_id = register_issuer(&state.service, "issuer1").await;
        let expected = vec![publish(&state, "issuer1").await];

        for id in [
            aggregation_id.0.hyphenated().to_string().to_uppercase(),
            aggregation_id.0.simple().to_string(),
            aggregation_id.0.urn().to_string(),
        ] {
            let response = send(&state, &format!("/api/v1/aggregation/{id}")).await;
            assert_eq!(response.status(), StatusCode::OK, "{id}");
            assert_eq!(body(response).await.status_lists, expected, "{id}");
        }
    }

    #[tokio::test]
    async fn test_malformed_aggregation_id_is_rejected() {
        let state = test_app_state(None).await;
        for id in ["not-a-uuid", "%00", "0b8ef1c4-3c6a-4d2e-9f1a"] {
            let response = send(&state, &format!("/api/v1/aggregation/{id}")).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{id}");
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(error["error"], "invalid_aggregation_id", "{id}");
        }
    }

    #[tokio::test]
    async fn test_unknown_aggregation_id_is_not_found() {
        let state = test_app_state(None).await;
        register_issuer(&state.service, "issuer1").await;
        publish(&state, "issuer1").await;

        let err = get_scoped(&state, AggregationId::generate(), None, None)
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(err.error, "aggregation_not_found");
    }

    #[tokio::test]
    async fn test_issuer_without_lists_is_an_empty_page() {
        let state = test_app_state(None).await;
        let aggregation_id = register_issuer(&state.service, "issuer1").await;

        let page = body(
            get_scoped(&state, aggregation_id, None, None)
                .await
                .unwrap(),
        )
        .await;
        assert!(page.status_lists.is_empty());
        assert_eq!(page.next_cursor, None);
    }

    #[tokio::test]
    async fn test_unchanged_page_revalidates_with_304() {
        let state = test_app_state(None).await;
        let aggregation_id = register_issuer(&state.service, "issuer1").await;
        publish(&state, "issuer1").await;
        let revalidate = |etag: HeaderValue| {
            let mut headers = HeaderMap::new();
            headers.insert(header::IF_NONE_MATCH, etag);
            get_issuer_aggregation(
                State(state.clone()),
                Ok(Path(aggregation_id)),
                headers,
                query(None, None),
            )
        };

        let first = get_scoped(&state, aggregation_id, None, None)
            .await
            .unwrap();
        let etag = first.headers()[header::ETAG].clone();

        let unchanged = revalidate(etag.clone()).await.unwrap();
        assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(unchanged.headers()[header::ETAG], etag);

        publish(&state, "issuer1").await;
        let changed = revalidate(etag).await.unwrap();
        assert_eq!(changed.status(), StatusCode::OK);
    }

    #[test]
    fn test_page_outcome() {
        assert_eq!(page_outcome(false, false, false), "complete");
        assert_eq!(page_outcome(false, true, false), "complete");
        assert_eq!(page_outcome(false, false, true), "truncated");
        assert_eq!(page_outcome(false, true, true), "paged");
        assert_eq!(page_outcome(true, false, true), "paged");
        assert_eq!(page_outcome(true, false, false), "paged");
    }

    #[test]
    fn test_aggregation_pages_are_counted_by_scope_and_outcome() {
        let metrics = metrics_after(async {
            let state = test_app_state(None).await;
            let aggregation_id = register_issuer(&state.service, "issuer1").await;
            publish(&state, "issuer1").await;
            for _ in 0..AGGREGATION_DEFAULT_LIMIT {
                publish(&state, "issuer2").await;
            }

            get_scoped(&state, aggregation_id, None, None)
                .await
                .unwrap();
            get(&state, None, None).await.unwrap();
            get(&state, Some(1), None).await.unwrap();
        });

        let pages: Vec<_> = metrics
            .lines()
            .filter(|line| line.starts_with("aggregation_pages_total"))
            .collect();
        for (scope, outcome) in [
            ("issuer", "complete"),
            ("all", "truncated"),
            ("all", "paged"),
        ] {
            assert!(
                pages.iter().any(|line| {
                    line.contains(&format!("scope=\"{scope}\""))
                        && line.contains(&format!("outcome=\"{outcome}\""))
                }),
                "no {scope}/{outcome} series in {pages:#?}"
            );
        }
    }

    /// Every accepted `list_id` form, plus a legacy non-UUID one, must round-trip
    /// through the cursor, scoped and not, under the backend's collation.
    /// `limit=1` makes every ID a cursor.
    #[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]
    async fn assert_aggregation_walk_on_sql(
        db: std::sync::Arc<sea_orm::DatabaseConnection>,
        backend: &str,
    ) {
        let state = test_app_state(Some(db)).await;
        let aggregation_id = register_issuer(&state.service, "issuer1").await;

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
            expected.insert(publish_list(&state.service, "issuer1", &list_id).await);
        }

        for scope in [None, Some(aggregation_id)] {
            for limit in [1, 2] {
                let mut seen = Vec::new();
                let mut cursor: Option<String> = None;
                loop {
                    let response = get_page(&state, scope, Some(limit), cursor.as_deref())
                        .await
                        .unwrap_or_else(|e| {
                            panic!(
                                "page after {cursor:?} (scope={scope:?}, limit={limit}) \
                                 on {backend}: {e:?}"
                            )
                        });
                    let has_link = response.headers().contains_key(header::LINK);
                    let page = body(response).await;
                    assert_eq!(
                        has_link,
                        page.next_cursor.is_some(),
                        "Link and next_cursor must agree (scope={scope:?}, limit={limit}) \
                         on {backend}"
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
                    "no list may appear twice (scope={scope:?}, limit={limit}) on {backend}"
                );
                assert_eq!(
                    unique, expected,
                    "every list must appear (scope={scope:?}, limit={limit}) on {backend}"
                );
            }
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
        let expected = BTreeSet::from([
            publish(&state, "issuer1").await,
            publish(&state, "issuer1").await,
            publish_list(&state.service, "issuer1", "legacy-list").await,
        ]);

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
