use crate::{
    domain::models::{
        credential::{AggregationId, Issuer},
        hosted_issuer::{
            HostedIssuer, HostedIssuerFilter, HostedIssuerKey, HostedIssuerKeyState,
            HostedIssuerReadState,
        },
    },
    server::{
        AppState,
        auth::{
            AuthenticatedAdmin,
            issuer_registry::{IssuerEntry, RegistryKey},
        },
        error::{ApiError, IntoApiError},
    },
};
use axum::{
    Extension, Json,
    extract::{
        Path, Query, State,
        rejection::{PathRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq, Eq)]
struct Filters {
    source: Option<String>,
    tier: Option<String>,
    state: Option<String>,
    owner: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    source: Option<String>,
    tier: Option<String>,
    state: Option<String>,
    owner: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}
#[derive(Debug, Serialize, Clone)]
pub struct IssuerDto {
    id: String,
    aggregation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregation_uri: Option<String>,
    display_name: Option<String>,
    source: String,
    tier: String,
    state: String,
    owner: Option<String>,
    created_at: Option<i64>,
    expires_at: Option<i64>,
    keys: Vec<KeyDto>,
    usage: UsageDto,
}
#[derive(Debug, Serialize, Clone)]
struct KeyDto {
    kid: String,
    alg: String,
    state: String,
    not_before: Option<i64>,
    not_after: Option<i64>,
    created_at: Option<i64>,
    public_key: serde_json::Value,
}
#[derive(Debug, Serialize, Clone)]
struct UsageDto {
    lists: u64,
    lists_limit: u64,
    keys: u64,
    keys_limit: Option<u64>,
}
#[derive(Debug, Serialize)]
pub struct IssuerPage {
    issuers: Vec<IssuerDto>,
    next_cursor: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Cursor {
    after: String,
    filters: Filters,
}

fn error(status: StatusCode, code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError::new(status, code, Some(message.into()))
}
fn require_scope(admin: &AuthenticatedAdmin, needed: &'static str) -> Result<(), ApiError> {
    if admin.scopes.iter().any(|scope| scope == needed) {
        Ok(())
    } else {
        Err(error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            format!("{needed} is required"),
        )
        .with_header(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_str(&format!(
                "Bearer error=\"insufficient_scope\", scope=\"{needed}\""
            ))
            .unwrap(),
        ))
    }
}
fn filter_matches(
    filters: &Filters,
    source: &str,
    tier: &str,
    state: &str,
    owner: Option<&str>,
) -> bool {
    filters.source.as_deref().is_none_or(|v| v == source)
        && filters.tier.as_deref().is_none_or(|v| v == tier)
        && filters.state.as_deref().is_none_or(|v| v == state)
        && filters.owner.as_deref().is_none_or(|v| Some(v) == owner)
}
fn static_state(entry: &IssuerEntry) -> &'static str {
    if entry.disabled {
        "suspended"
    } else {
        "active"
    }
}
fn key_from_registry(k: &RegistryKey) -> KeyDto {
    KeyDto {
        kid: k.kid.clone(),
        alg: k.alg.clone(),
        state: "active".into(),
        not_before: k
            .not_before
            .as_deref()
            .and_then(|v| {
                time::OffsetDateTime::parse(v, &time::format_description::well_known::Rfc3339).ok()
            })
            .map(|v| v.unix_timestamp()),
        not_after: k
            .not_after
            .as_deref()
            .and_then(|v| {
                time::OffsetDateTime::parse(v, &time::format_description::well_known::Rfc3339).ok()
            })
            .map(|v| v.unix_timestamp()),
        created_at: None,
        public_key: k.jwk.clone(),
    }
}
fn key_from_hosted(k: HostedIssuerKey) -> KeyDto {
    let alg = serde_json::from_slice::<serde_json::Value>(k.jwk.as_bytes())
        .ok()
        .and_then(|v| v.get("alg").and_then(|a| a.as_str()).map(str::to_owned))
        .unwrap_or_else(|| format!("{:?}", k.jwk.algorithm()));
    KeyDto {
        kid: k.kid,
        alg,
        state: if k.state == HostedIssuerKeyState::Active {
            "active"
        } else {
            "revoked"
        }
        .into(),
        not_before: k.not_before.map(|v| v.unix_timestamp()),
        not_after: k.not_after.map(|v| v.unix_timestamp()),
        created_at: Some(k.created_at.unix_timestamp()),
        public_key: serde_json::from_slice(k.jwk.as_bytes()).unwrap_or(serde_json::Value::Null),
    }
}
async fn list_count(state: &AppState, id: &str) -> Result<u64, ApiError> {
    state
        .service
        .issuer_status_list_count(id)
        .await
        .map_err(IntoApiError::into_api_error)
}
async fn static_dto(state: &AppState, entry: &IssuerEntry) -> Result<IssuerDto, ApiError> {
    let count = list_count(state, &entry.id).await?;
    Ok(IssuerDto {
        id: entry.id.clone(),
        aggregation_id: entry.aggregation_id.to_string(),
        aggregation_uri: state.aggregation_uri_for(
            &Issuer(entry.id.clone()),
            AggregationId(entry.aggregation_id),
        ),
        display_name: entry.display_name.clone(),
        source: "static".into(),
        tier: entry.tier.clone(),
        state: static_state(entry).into(),
        owner: None,
        created_at: None,
        expires_at: None,
        keys: entry.keys.iter().map(|k| key_from_registry(k)).collect(),
        usage: UsageDto {
            lists: count,
            lists_limit: state.max_lists_per_issuer,
            keys: entry.keys.len() as u64,
            keys_limit: None,
        },
    })
}
async fn hosted_dto(state: &AppState, issuer: HostedIssuer) -> Result<IssuerDto, ApiError> {
    let id = issuer.id.clone();
    let count = list_count(state, &id).await?;
    let keys = if let Some(store) = &state.hosted_issuer_store {
        store
            .issuer_keys(&id)
            .await
            .map_err(|_| {
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    "issuer key store unavailable",
                )
            })?
            .into_iter()
            .map(key_from_hosted)
            .collect()
    } else {
        Vec::new()
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let state_name = if issuer.state.as_str() == "disabled" {
        "suspended"
    } else if issuer.expires_at.is_some_and(|v| v.unix_timestamp() <= now) {
        "expired"
    } else {
        "active"
    };
    Ok(IssuerDto {
        aggregation_uri: state
            .aggregation_uri_for(&Issuer(issuer.id.clone()), issuer.aggregation_id),
        id: issuer.id,
        aggregation_id: issuer.aggregation_id.to_string(),
        display_name: issuer.display_name,
        source: "portal".into(),
        tier: issuer.tier.clone(),
        state: state_name.into(),
        owner: issuer.owner,
        created_at: Some(issuer.created_at.unix_timestamp()),
        expires_at: issuer.expires_at.map(|v| v.unix_timestamp()),
        keys: keys.clone(),
        usage: UsageDto {
            lists: count,
            lists_limit: state.max_lists_per_issuer,
            keys: keys.iter().filter(|k| k.state == "active").count() as u64,
            keys_limit: None,
        },
    })
}
fn cursor_encode(after: String, filters: Filters) -> String {
    URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&Cursor { after, filters }).expect("cursor serializes"))
}
fn cursor_decode(raw: &str, filters: &Filters) -> Result<String, ApiError> {
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "cursor is invalid",
        )
    })?;
    let cursor: Cursor = serde_json::from_slice(&bytes).map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "cursor is invalid",
        )
    })?;
    if &cursor.filters != filters {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "cursor does not match filters",
        ));
    }
    Ok(cursor.after)
}

pub async fn list_issuers(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<(HeaderMap, Json<IssuerPage>), ApiError> {
    require_scope(&admin, "issuers:read")?;
    let Query(query) = query.map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "query parameters are invalid",
        )
    })?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "limit must be between 1 and 100",
        ));
    }
    for (value, allowed, name) in [
        (&query.source, &["static", "portal"][..], "source"),
        (&query.tier, &["standard", "sandbox"][..], "tier"),
        (
            &query.state,
            &["active", "suspended", "expired"][..],
            "state",
        ),
    ] {
        if value.as_deref().is_some_and(|v| !allowed.contains(&v)) {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                format!("invalid {name}"),
            ));
        }
    }
    if query.owner.as_deref().is_some_and(|owner| {
        let chars = owner.chars().count();
        let Some((provider, subject)) = owner.split_once('|') else {
            return true;
        };
        !(3..=255).contains(&chars)
            || provider.is_empty()
            || !provider
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || subject.is_empty()
    }) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "owner must match the <provider>|<subject> format",
        ));
    }
    let filters = Filters {
        source: query.source,
        tier: query.tier,
        state: query.state,
        owner: query.owner,
    };
    let after = query
        .cursor
        .as_deref()
        .map(|c| cursor_decode(c, &filters))
        .transpose()?;
    let snapshot = state.admin_registry.snapshot();
    enum Row<'a> {
        Static(&'a IssuerEntry),
        Hosted(HostedIssuer),
    }
    impl Row<'_> {
        fn id(&self) -> &str {
            match self {
                Self::Static(entry) => &entry.id,
                Self::Hosted(issuer) => &issuer.id,
            }
        }
    }
    let mut rows = Vec::new();
    if filters.source.as_deref() != Some("portal") {
        let mut entries: Vec<_> = snapshot
            .issuers()
            .iter()
            .filter(|entry| {
                after.as_deref().is_none_or(|a| entry.id.as_str() > a)
                    && filter_matches(&filters, "static", &entry.tier, static_state(entry), None)
            })
            .collect();
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        rows.extend(entries.into_iter().take(limit + 1).map(Row::Static));
    }
    if filters.source.as_deref() != Some("static")
        && let Some(store) = &state.hosted_issuer_store
    {
        let hosted_filters = HostedIssuerFilter {
            tier: filters.tier.clone(),
            state: match filters.state.as_deref() {
                Some("active") => Some(HostedIssuerReadState::Active),
                Some("suspended") => Some(HostedIssuerReadState::Suspended),
                Some("expired") => Some(HostedIssuerReadState::Expired),
                _ => None,
            },
            owner: filters.owner.clone(),
        };
        rows.extend(
            store
                .list_issuers_after(
                    after.as_deref(),
                    limit + 1,
                    &hosted_filters,
                    time::OffsetDateTime::now_utc(),
                )
                .await
                .map_err(|_| {
                    error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "service_unavailable",
                        "issuer store unavailable",
                    )
                })?
                .into_iter()
                .map(Row::Hosted),
        );
    }
    rows.sort_by(|a, b| a.id().cmp(b.id()));
    rows.dedup_by(|a, b| a.id() == b.id());
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let mut issuers = Vec::with_capacity(rows.len());
    for row in rows {
        issuers.push(match row {
            Row::Static(entry) => static_dto(&state, entry).await?,
            Row::Hosted(issuer) => hosted_dto(&state, issuer).await?,
        });
    }
    let next_cursor = if has_more {
        issuers
            .last()
            .map(|last| cursor_encode(last.id.clone(), filters.clone()))
    } else {
        None
    };
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(cursor) = &next_cursor {
        let mut params = vec![format!("cursor={cursor}"), format!("limit={limit}")];
        for (k, v) in [
            ("source", filters.source.as_deref()),
            ("tier", filters.tier.as_deref()),
            ("state", filters.state.as_deref()),
            ("owner", filters.owner.as_deref()),
        ] {
            if let Some(v) = v {
                params.push(format!(
                    "{k}={}",
                    url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>()
                ));
            }
        }
        h.insert(
            header::LINK,
            HeaderValue::from_str(&format!(
                "</admin/v1/issuers?{}>; rel=\"next\"",
                params.join("&")
            ))
            .unwrap(),
        );
    }
    Ok((
        h,
        Json(IssuerPage {
            issuers,
            next_cursor,
        }),
    ))
}

pub async fn get_issuer(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    path: Result<Path<String>, PathRejection>,
) -> Result<(HeaderMap, Json<IssuerDto>), ApiError> {
    require_scope(&admin, "issuers:read")?;
    let Path(id) = path.map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "issuer_id must be valid UTF-8",
        )
    })?;
    let snapshot = state.admin_registry.snapshot();
    let dto = if let Some(entry) = snapshot.issuer(&id) {
        static_dto(&state, entry).await?
    } else if let Some(store) = &state.hosted_issuer_store {
        let issuer = store
            .find_issuer(&id)
            .await
            .map_err(|_| {
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    "issuer store unavailable",
                )
            })?
            .ok_or_else(|| {
                error(
                    StatusCode::NOT_FOUND,
                    "issuer_not_found",
                    "no issuer has this id",
                )
            })?;
        hosted_dto(&state, issuer).await?
    } else {
        return Err(error(
            StatusCode::NOT_FOUND,
            "issuer_not_found",
            "no issuer has this id",
        ));
    };
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(&dto).expect("issuer DTO serializes");
    let etag = hex::encode(Sha256::digest(&bytes));
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{etag}\"")).unwrap(),
    );
    Ok((h, Json(dto)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct MutableHostedStore {
        issuers: Arc<Mutex<Vec<HostedIssuer>>>,
        keys: Arc<Mutex<Vec<HostedIssuerKey>>>,
    }

    #[async_trait::async_trait]
    impl crate::domain::ports::HostedIssuerStore for MutableHostedStore {
        async fn list_issuers_after(
            &self,
            after: Option<&str>,
            limit: usize,
            _filters: &HostedIssuerFilter,
            _now: time::OffsetDateTime,
        ) -> Result<Vec<HostedIssuer>, crate::domain::models::hosted_issuer::HostedIssuerError>
        {
            let mut issuers: Vec<_> = self
                .issuers
                .lock()
                .unwrap()
                .iter()
                .filter(|issuer| after.is_none_or(|after| issuer.id.as_str() > after))
                .cloned()
                .collect();
            issuers.sort_by(|a, b| a.id.cmp(&b.id));
            issuers.truncate(limit);
            Ok(issuers)
        }

        async fn issuer_keys(
            &self,
            issuer_id: &str,
        ) -> Result<Vec<HostedIssuerKey>, crate::domain::models::hosted_issuer::HostedIssuerError>
        {
            Ok(self
                .keys
                .lock()
                .unwrap()
                .iter()
                .filter(|key| key.issuer_id == issuer_id)
                .cloned()
                .collect())
        }

        async fn find_key_by_kid(
            &self,
            _kid: &str,
        ) -> Result<
            Option<crate::domain::models::hosted_issuer::HostedIssuerKeyEntry>,
            crate::domain::models::hosted_issuer::HostedIssuerError,
        > {
            unreachable!()
        }

        async fn find_issuer(
            &self,
            id: &str,
        ) -> Result<Option<HostedIssuer>, crate::domain::models::hosted_issuer::HostedIssuerError>
        {
            Ok(self
                .issuers
                .lock()
                .unwrap()
                .iter()
                .find(|issuer| issuer.id == id)
                .cloned())
        }

        async fn create_issuer(
            &self,
            _issuer: HostedIssuer,
        ) -> Result<HostedIssuer, crate::domain::models::hosted_issuer::HostedIssuerError> {
            unreachable!()
        }

        async fn add_key(
            &self,
            _key: HostedIssuerKey,
        ) -> Result<(), crate::domain::models::hosted_issuer::HostedIssuerError> {
            unreachable!()
        }

        async fn all_keys(
            &self,
        ) -> Result<Vec<HostedIssuerKey>, crate::domain::models::hosted_issuer::HostedIssuerError>
        {
            unreachable!()
        }

        async fn find_key_by_material(
            &self,
            _material: &str,
        ) -> Result<Option<HostedIssuerKey>, crate::domain::models::hosted_issuer::HostedIssuerError>
        {
            unreachable!()
        }

        async fn find_issuer_ids(
            &self,
            _ids: &[String],
        ) -> Result<
            std::collections::HashSet<String>,
            crate::domain::models::hosted_issuer::HostedIssuerError,
        > {
            unreachable!()
        }
    }

    fn hosted_issuer(id: &str) -> HostedIssuer {
        HostedIssuer {
            id: id.into(),
            display_name: Some(format!("Portal {id}")),
            tier: "sandbox".into(),
            state: crate::domain::models::hosted_issuer::HostedIssuerState::Active,
            owner: Some("portal|test-user".into()),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            expires_at: None,
            version: 1,
            aggregation_id: AggregationId::generate(),
        }
    }

    fn static_registry() -> Arc<crate::server::auth::issuer_registry::RegistryHandle> {
        Arc::new(
            crate::server::auth::issuer_registry::RegistryHandle::from_yaml(
                "version: 1\nissuers:\n  - id: b\n    aggregation_id: 00000000-0000-4000-8000-000000000001\n    tier: standard\n    keys:\n      - kid: static-key\n        alg: ES256\n        jwk:\n          kty: EC\n          crv: P-256\n          kid: static-key\n          alg: ES256\n          x: NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8\n          y: eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M\nadmins: []\n",
            )
            .unwrap(),
        )
    }

    async fn query_page(
        state: AppState,
        admin: &AuthenticatedAdmin,
        cursor: Option<String>,
        limit: usize,
    ) -> IssuerPage {
        let (_, Json(page)) = list_issuers(
            State(state),
            Extension(admin.clone()),
            Ok(Query(ListQuery {
                source: None,
                tier: None,
                state: None,
                owner: None,
                cursor,
                limit: Some(limit),
            })),
        )
        .await
        .unwrap();
        page
    }

    #[tokio::test]
    async fn mixed_static_and_portal_issuers_are_returned_once_across_pages() {
        let hosted = Arc::new(Mutex::new(vec![hosted_issuer("a"), hosted_issuer("c")]));
        let mut state = crate::test_utils::test_app_state(None).await;
        state.admin_registry = static_registry();
        state.hosted_issuer_store = Some(Arc::new(MutableHostedStore {
            issuers: hosted,
            keys: Arc::default(),
        }));
        let admin = AuthenticatedAdmin {
            id: "operator".into(),
            scopes: vec!["issuers:read".into()],
        };

        let first = query_page(state.clone(), &admin, None, 2).await;
        assert_eq!(
            first
                .issuers
                .iter()
                .map(|issuer| issuer.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        let second = query_page(state.clone(), &admin, first.next_cursor, 2).await;
        assert_eq!(
            second
                .issuers
                .iter()
                .map(|issuer| issuer.id.as_str())
                .collect::<Vec<_>>(),
            ["c"]
        );
        assert!(second.next_cursor.is_none());
    }

    #[tokio::test]
    async fn concurrent_inserts_after_cursor_are_seen_and_before_cursor_are_skipped() {
        let hosted = Arc::new(Mutex::new(vec![hosted_issuer("a"), hosted_issuer("c")]));
        let mut state = crate::test_utils::test_app_state(None).await;
        state.admin_registry = static_registry();
        state.hosted_issuer_store = Some(Arc::new(MutableHostedStore {
            issuers: hosted.clone(),
            keys: Arc::default(),
        }));
        let admin = AuthenticatedAdmin {
            id: "operator".into(),
            scopes: vec!["issuers:read".into()],
        };

        let first = query_page(state.clone(), &admin, None, 2).await;
        assert_eq!(
            first
                .issuers
                .iter()
                .map(|issuer| issuer.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        hosted
            .lock()
            .unwrap()
            .extend([hosted_issuer("aa"), hosted_issuer("bb")]);

        let second = query_page(state.clone(), &admin, first.next_cursor, 2).await;
        assert_eq!(
            second
                .issuers
                .iter()
                .map(|issuer| issuer.id.as_str())
                .collect::<Vec<_>>(),
            ["bb", "c"]
        );
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn read_scope_failure_has_rfc6750_challenge() {
        let admin = AuthenticatedAdmin {
            id: "operator".into(),
            scopes: vec![],
        };
        let response = require_scope(&admin, "issuers:read")
            .unwrap_err()
            .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"insufficient_scope\", scope=\"issuers:read\""
        );
    }

    #[test]
    fn cursor_is_bound_to_filters() {
        let filters = Filters {
            source: Some("static".into()),
            ..Filters::default()
        };
        let cursor = cursor_encode("issuer-1".into(), filters.clone());
        assert_eq!(cursor_decode(&cursor, &filters).unwrap(), "issuer-1");
        assert!(cursor_decode(&cursor, &Filters::default()).is_err());
    }

    #[test]
    fn unavailable_usage_lookup_returns_service_unavailable() {
        let response = crate::domain::models::status_list::StatusListError::Unavailable
            .into_api_error()
            .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn static_issuer_list_and_detail_include_no_store_and_metadata() {
        let id = "issuer-a";
        let aggregation_id = uuid::Uuid::from_u128(1);
        let registry_yaml = format!(
            "version: 1\nissuers:\n  - id: {id}\n    aggregation_id: {aggregation_id}\n    tier: standard\n    keys:\n      - kid: key-a\n        alg: ES256\n        jwk:\n          kty: EC\n          crv: P-256\n          kid: key-a\n          alg: ES256\n          x: NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8\n          y: eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M\nadmins: []\n"
        );
        let mut state = crate::test_utils::test_app_state(None).await;
        state.admin_registry = std::sync::Arc::new(
            crate::server::auth::issuer_registry::RegistryHandle::from_yaml(&registry_yaml)
                .unwrap(),
        );
        let admin = AuthenticatedAdmin {
            id: "operator".into(),
            scopes: vec!["issuers:read".into()],
        };
        let (headers, Json(page)) = list_issuers(
            State(state.clone()),
            Extension(admin.clone()),
            Ok(Query(ListQuery {
                source: Some("static".into()),
                tier: None,
                state: None,
                owner: None,
                cursor: None,
                limit: Some(1),
            })),
        )
        .await
        .unwrap();
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(page.issuers.len(), 1);
        assert_eq!(page.issuers[0].id, id);
        assert_eq!(page.issuers[0].aggregation_id, aggregation_id.to_string());
        assert_eq!(page.issuers[0].keys[0].kid, "key-a");
        assert_eq!(page.issuers[0].usage.lists, 0);
        assert!(page.next_cursor.is_none());

        let (headers, Json(detail)) =
            get_issuer(State(state), Extension(admin), Ok(Path(id.into())))
                .await
                .unwrap();
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert!(headers.contains_key(header::ETAG));
        assert_eq!(detail.id, id);
    }
    fn detail_router(state: AppState) -> axum::Router {
        axum::Router::new()
            .route(
                "/admin/v1/issuers/{issuer_id}",
                axum::routing::get(get_issuer),
            )
            .layer(Extension(AuthenticatedAdmin {
                id: "operator".into(),
                scopes: vec!["issuers:read".into()],
            }))
            .with_state(state)
    }

    async fn detail_response(app: axum::Router, path: &str) -> axum::response::Response {
        use tower::ServiceExt;
        app.oneshot(
            axum::http::Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn invalid_issuer_path_uses_api_error_and_no_store() {
        let app = detail_router(crate::test_utils::test_app_state(None).await);
        let response = detail_response(app, "/admin/v1/issuers/%FF").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-store, max-age=0"
        );
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "invalid_input");
    }

    #[tokio::test]
    async fn detail_etag_tracks_keys_usage_and_expiry_state() {
        let issuers = Arc::new(Mutex::new(vec![hosted_issuer("portal")]));
        let keys = Arc::new(Mutex::new(Vec::new()));
        let mut state = crate::test_utils::test_app_state(None).await;
        state.hosted_issuer_store = Some(Arc::new(MutableHostedStore {
            issuers: issuers.clone(),
            keys: keys.clone(),
        }));
        let app = detail_router(state.clone());
        let uri = "/admin/v1/issuers/portal";
        let first = detail_response(app.clone(), uri).await;
        assert_eq!(first.status(), StatusCode::OK);
        let initial = first.headers()[header::ETAG].clone();
        assert_eq!(
            detail_response(app.clone(), uri).await.headers()[header::ETAG],
            initial
        );
        keys.lock().unwrap().push(HostedIssuerKey {
            issuer_id: "portal".into(),
            kid: "test-key".into(),
            jwk: crate::domain::models::credential::PublicJwk::try_new(
                crate::test_fixtures::TEST_EC_PUBLIC_JWK.as_bytes().to_vec(),
            )
            .unwrap(),
            created_at: time::OffsetDateTime::now_utc(),
            not_before: None,
            not_after: None,
            state: HostedIssuerKeyState::Active,
        });
        let with_key = detail_response(app.clone(), uri).await.headers()[header::ETAG].clone();
        assert_ne!(with_key, initial);
        crate::test_utils::publish_list(&state.service, "portal", "list-1").await;
        let with_list = detail_response(app.clone(), uri).await.headers()[header::ETAG].clone();
        assert_ne!(with_list, with_key);
        issuers.lock().unwrap()[0].expires_at = Some(time::OffsetDateTime::UNIX_EPOCH);
        let expired = detail_response(app.clone(), uri).await;
        assert_ne!(expired.headers()[header::ETAG], with_list);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(expired.into_body(), 16384)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["state"], "expired");
        assert_eq!(body["usage"]["lists"], 1);
        assert_eq!(body["usage"]["keys"], 1);
        assert!(body["usage"]["keys_limit"].is_null());
    }
}
