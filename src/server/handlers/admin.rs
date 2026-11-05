use crate::{
    domain::models::{
        credential::{AggregationId, Issuer, jose_alg_name},
        hosted_issuer::{
            HostedIssuer, HostedIssuerFilter, HostedIssuerKey, HostedIssuerKeyState,
            HostedIssuerReadState,
        },
        tier::IssuerUsage,
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
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum IssuerSource {
    Static,
    Portal,
}

impl IssuerSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Portal => "portal",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum IssuerTier {
    Standard,
    Sandbox,
}

impl IssuerTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Sandbox => "sandbox",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum IssuerReadState {
    Active,
    Suspended,
    Expired,
}

impl IssuerReadState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq, Eq)]
struct Filters {
    source: Option<IssuerSource>,
    tier: Option<IssuerTier>,
    state: Option<IssuerReadState>,
    owner: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    source: Option<IssuerSource>,
    tier: Option<IssuerTier>,
    state: Option<IssuerReadState>,
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
    #[serde(skip)]
    persisted_version: Option<u64>,
}
#[derive(Debug, Serialize, Clone)]
pub struct KeyDto {
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
    keys_limit: u64,
}
impl From<IssuerUsage> for UsageDto {
    fn from(usage: IssuerUsage) -> Self {
        Self {
            lists: usage.lists,
            lists_limit: usage.lists_limit,
            keys: usage.keys as u64,
            keys_limit: usage.keys_limit as u64,
        }
    }
}

#[derive(Serialize)]
struct IssuerWriteVersion<'a> {
    id: &'a str,
    display_name: &'a Option<String>,
    tier: &'a str,
    state: &'a str,
    owner: &'a Option<String>,
    expires_at: Option<i64>,
    keys: Vec<IssuerKeyWriteVersion<'a>>,
}

#[derive(Serialize)]
struct IssuerKeyWriteVersion<'a> {
    kid: &'a str,
    state: &'a str,
    not_before: Option<i64>,
    not_after: Option<i64>,
}

pub(crate) fn issuer_write_version(issuer: &IssuerDto) -> String {
    use sha2::{Digest, Sha256};
    if let Some(version) = issuer.persisted_version {
        return hex::encode(Sha256::digest(
            format!("{}:{version}", issuer.id).as_bytes(),
        ));
    }
    let write_state = IssuerWriteVersion {
        id: &issuer.id,
        display_name: &issuer.display_name,
        tier: &issuer.tier,
        state: if issuer.state == "expired" {
            "active"
        } else {
            &issuer.state
        },
        owner: &issuer.owner,
        expires_at: issuer.expires_at,
        keys: issuer
            .keys
            .iter()
            .map(|key| IssuerKeyWriteVersion {
                kid: &key.kid,
                state: &key.state,
                not_before: key.not_before,
                not_after: key.not_after,
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&write_state).expect("issuer write state serializes");
    hex::encode(Sha256::digest(bytes))
}
#[derive(Debug, Serialize)]
pub struct IssuerPage {
    issuers: Vec<IssuerDto>,
    next_cursor: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Cursor {
    after_static: Option<String>,
    after_portal: Option<String>,
    filters: Filters,
}

pub(crate) fn hosted_store_error(
    err: crate::domain::models::hosted_issuer::HostedIssuerError,
) -> ApiError {
    use crate::domain::models::hosted_issuer::HostedIssuerError;
    match err {
        HostedIssuerError::Backend(source) => {
            tracing::error!(error = %source, "admin issuer storage is unavailable");
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                Some("issuer store unavailable".into()),
            )
            .retry_after(1)
        }
        HostedIssuerError::Corrupt(source) => ApiError::internal(source),
        HostedIssuerError::Unavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            Some("issuer store unavailable".into()),
        )
        .retry_after(1),
        other => ApiError::internal(other),
    }
}
pub(crate) fn require_scope(
    admin: &AuthenticatedAdmin,
    needed: &'static str,
) -> Result<(), ApiError> {
    if admin.scopes.iter().any(|scope| scope == needed) {
        Ok(())
    } else {
        Err(
            ApiError::forbidden("insufficient_scope", format!("{needed} is required")).with_header(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_str(&format!(
                    "Bearer error=\"insufficient_scope\", scope=\"{needed}\""
                ))
                .expect("static scope name is a valid challenge header value"),
            ),
        )
    }
}
fn filter_matches(
    filters: &Filters,
    source: IssuerSource,
    tier: IssuerTier,
    state: IssuerReadState,
    owner: Option<&str>,
) -> bool {
    filters.source.is_none_or(|v| v == source)
        && filters.tier.is_none_or(|v| v == tier)
        && filters.state.is_none_or(|v| v == state)
        && filters.owner.as_deref().is_none_or(|v| Some(v) == owner)
}
fn static_state(entry: &IssuerEntry) -> IssuerReadState {
    if entry.disabled {
        IssuerReadState::Suspended
    } else {
        IssuerReadState::Active
    }
}
fn key_from_registry(
    k: &RegistryKey,
    resolved: &crate::domain::models::credential::ResolvedKey,
) -> KeyDto {
    KeyDto {
        kid: k.kid.clone(),
        alg: jose_alg_name(resolved.public_key.algorithm()).to_owned(),
        state: "active".into(),
        not_before: resolved.not_before.map(|v| v.unix_timestamp()),
        not_after: resolved.not_after.map(|v| v.unix_timestamp()),
        created_at: None,
        public_key: serde_json::to_value(resolved.public_key.jwk())
            .expect("validated JWK serializes"),
    }
}
pub(crate) fn key_from_hosted(k: HostedIssuerKey) -> KeyDto {
    let public_key =
        serde_json::from_slice(k.jwk.as_bytes()).expect("validated JWK bytes remain valid JSON");
    let key_state = match k.state {
        HostedIssuerKeyState::Active => "active",
        HostedIssuerKeyState::Reserved => "reserved",
        HostedIssuerKeyState::Revoked => "revoked",
    };
    KeyDto {
        kid: k.kid,
        alg: jose_alg_name(k.jwk.algorithm()).to_owned(),
        state: key_state.into(),
        not_before: k.not_before.map(|v| v.unix_timestamp()),
        not_after: k.not_after.map(|v| v.unix_timestamp()),
        created_at: Some(k.created_at.unix_timestamp()),
        public_key,
    }
}
async fn list_count(state: &AppState, id: &str) -> Result<u64, ApiError> {
    state
        .service
        .issuer_status_list_count(id)
        .await
        .map_err(IntoApiError::into_api_error)
}
fn static_dto(
    state: &AppState,
    entry: &IssuerEntry,
    snapshot: &crate::server::auth::issuer_registry::ValidatedRegistry,
    count: u64,
    now: time::OffsetDateTime,
) -> IssuerDto {
    IssuerDto {
        id: entry.id.clone(),
        aggregation_id: entry.aggregation_id.to_string(),
        aggregation_uri: state.aggregation_uri_for(
            &Issuer(entry.id.clone()),
            AggregationId(entry.aggregation_id),
        ),
        display_name: entry.display_name.clone(),
        source: "static".into(),
        tier: entry.tier.as_str().to_owned(),
        state: static_state(entry).as_str().to_owned(),
        owner: None,
        created_at: None,
        expires_at: None,
        persisted_version: None,
        keys: entry
            .keys
            .iter()
            .map(|key| {
                let resolved = snapshot
                    .resolve(&key.kid)
                    .expect("every registry key has a validated resolution");
                key_from_registry(key, &resolved)
            })
            .collect(),
        usage: IssuerUsage::new(
            count,
            entry.active_key_count(now),
            state.tiers.get(entry.tier),
        )
        .into(),
    }
}
fn hosted_dto_from_parts(
    state: &AppState,
    issuer: HostedIssuer,
    count: u64,
    keys: Vec<HostedIssuerKey>,
    now: time::OffsetDateTime,
) -> IssuerDto {
    let held_keys = keys
        .iter()
        .filter(|key| key.counts_against_quota(now))
        .count();
    let keys: Vec<_> = keys.into_iter().map(key_from_hosted).collect();
    let issuer_tier = issuer.tier.clone();
    let state_name = match issuer.read_state(now) {
        HostedIssuerReadState::Active => "active",
        HostedIssuerReadState::Suspended => "suspended",
        HostedIssuerReadState::Expired => "expired",
    };
    IssuerDto {
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
        persisted_version: Some(issuer.version),
        keys,
        usage: IssuerUsage::new(
            count,
            held_keys,
            state
                .tiers
                .get(crate::domain::models::tier::IssuerTier::from_name_or_strictest(&issuer_tier)),
        )
        .into(),
    }
}
/// Hosted lifecycle preconditions use the persisted version, not live usage.
pub(crate) fn issuer_etag(dto: &IssuerDto) -> String {
    use sha2::{Digest, Sha256};
    if dto.persisted_version.is_some() {
        return format!("\"{}\"", issuer_write_version(dto));
    }
    let bytes = serde_json::to_vec(dto).expect("issuer DTO serializes");
    format!("\"{}\"", hex::encode(Sha256::digest(bytes)))
}

pub(crate) async fn hosted_dto(
    state: &AppState,
    issuer: HostedIssuer,
) -> Result<IssuerDto, ApiError> {
    let store = state
        .hosted_issuer_store
        .as_ref()
        .expect("hosted store is configured");
    let keys = store
        .issuer_keys(&issuer.id)
        .await
        .map_err(hosted_store_error)?;
    let count = list_count(state, &issuer.id).await?;
    Ok(hosted_dto_from_parts(
        state,
        issuer,
        count,
        keys,
        time::OffsetDateTime::now_utc(),
    ))
}

fn cursor_encode(cursor: Cursor) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor).expect("cursor serializes"))
}
fn cursor_decode(raw: &str, filters: &Filters) -> Result<Cursor, ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| ApiError::bad_request("invalid_query", "cursor is invalid"))?;
    let cursor: Cursor = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::bad_request("invalid_query", "cursor is invalid"))?;
    if &cursor.filters != filters {
        return Err(ApiError::bad_request(
            "invalid_query",
            "cursor does not match filters",
        ));
    }
    if cursor.after_static.as_ref().is_some_and(|id| {
        id.is_empty() || id.chars().count() > 255 || id.chars().any(char::is_control)
    }) || cursor.after_portal.as_ref().is_some_and(|id| {
        id.is_empty() || id.chars().count() > 255 || id.chars().any(char::is_control)
    }) {
        return Err(ApiError::bad_request("invalid_query", "cursor is invalid"));
    }
    Ok(cursor)
}

pub async fn list_issuers(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<(HeaderMap, Json<IssuerPage>), ApiError> {
    require_scope(&admin, "issuers:read")?;
    let Query(query) = query
        .map_err(|_| ApiError::bad_request("invalid_query", "query parameters are invalid"))?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::bad_request(
            "invalid_query",
            "limit must be between 1 and 100",
        ));
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
            || subject.chars().any(char::is_control)
    }) {
        return Err(ApiError::bad_request(
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
    let mut cursor = query
        .cursor
        .as_deref()
        .map(|c| cursor_decode(c, &filters))
        .transpose()?
        .unwrap_or(Cursor {
            after_static: None,
            after_portal: None,
            filters: filters.clone(),
        });
    let now = time::OffsetDateTime::now_utc();
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
    if filters.source != Some(IssuerSource::Portal) {
        let mut entries: Vec<_> = snapshot
            .issuers()
            .iter()
            .filter(|entry| {
                cursor
                    .after_static
                    .as_deref()
                    .is_none_or(|a| entry.id.as_str() > a)
                    && filter_matches(
                        &filters,
                        IssuerSource::Static,
                        match entry.tier.as_str() {
                            "sandbox" => IssuerTier::Sandbox,
                            _ => IssuerTier::Standard,
                        },
                        static_state(entry),
                        None,
                    )
            })
            .collect();
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        rows.extend(entries.into_iter().take(limit + 1).map(Row::Static));
    }
    if filters.source != Some(IssuerSource::Static)
        && let Some(store) = &state.hosted_issuer_store
    {
        let hosted_filters = HostedIssuerFilter {
            tier: filters.tier.map(|tier| tier.as_str().to_owned()),
            state: filters.state.map(|state| match state {
                IssuerReadState::Active => HostedIssuerReadState::Active,
                IssuerReadState::Suspended => HostedIssuerReadState::Suspended,
                IssuerReadState::Expired => HostedIssuerReadState::Expired,
            }),
            owner: filters.owner.clone(),
        };
        rows.extend(
            store
                .list_issuers_after(
                    cursor.after_portal.as_deref(),
                    limit + 1,
                    &hosted_filters,
                    now,
                )
                .await
                .map_err(hosted_store_error)?
                .into_iter()
                .map(Row::Hosted),
        );
    }
    rows.sort_by(|a, b| a.id().cmp(b.id()));
    if rows.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
        return Err(ApiError::internal(
            "static and hosted issuer identifiers are not unique",
        ));
    }
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let issuer_ids: Vec<_> = rows.iter().map(|row| row.id().to_owned()).collect();
    let counts = state
        .service
        .issuer_status_list_counts(&issuer_ids)
        .await
        .map_err(IntoApiError::into_api_error)?;
    let hosted_ids: Vec<_> = rows
        .iter()
        .filter_map(|row| match row {
            Row::Hosted(issuer) => Some(issuer.id.clone()),
            Row::Static(_) => None,
        })
        .collect();
    let hosted_keys = if let Some(store) = &state.hosted_issuer_store {
        store
            .issuer_keys_for(&hosted_ids)
            .await
            .map_err(hosted_store_error)?
    } else {
        std::collections::HashMap::new()
    };
    let mut issuers = Vec::with_capacity(rows.len());
    for row in rows {
        let issuer = match row {
            Row::Static(entry) => {
                let id = entry.id.clone();
                cursor.after_static = Some(id.clone());
                static_dto(
                    &state,
                    entry,
                    &snapshot,
                    counts.get(&id).copied().unwrap_or(0),
                    now,
                )
            }
            Row::Hosted(hosted) => {
                let id = hosted.id.clone();
                cursor.after_portal = Some(id.clone());
                hosted_dto_from_parts(
                    &state,
                    hosted,
                    counts.get(&id).copied().unwrap_or(0),
                    hosted_keys.get(&id).cloned().unwrap_or_default(),
                    now,
                )
            }
        };
        issuers.push(issuer);
    }
    let next_cursor = if has_more {
        Some(cursor_encode(cursor))
    } else {
        None
    };
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(cursor) = &next_cursor {
        let mut params = vec![format!("cursor={cursor}"), format!("limit={limit}")];
        for (k, v) in [
            ("source", filters.source.map(IssuerSource::as_str)),
            ("tier", filters.tier.map(IssuerTier::as_str)),
            ("state", filters.state.map(IssuerReadState::as_str)),
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
            .expect("percent-encoded Link header is valid"),
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
    let Path(id) =
        path.map_err(|_| ApiError::bad_request("invalid_input", "issuer_id must be valid UTF-8"))?;
    if id.is_empty() || id.chars().count() > 255 || id.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "invalid_input",
            "issuer_id must not contain control characters",
        ));
    }
    let snapshot = state.admin_registry.snapshot();
    let now = time::OffsetDateTime::now_utc();
    let dto = if let Some(entry) = snapshot.issuer(&id) {
        let count = list_count(&state, &id).await?;
        static_dto(&state, entry, &snapshot, count, now)
    } else if let Some(store) = &state.hosted_issuer_store {
        let issuer = store
            .find_issuer(&id)
            .await
            .map_err(hosted_store_error)?
            .ok_or_else(|| ApiError::not_found("issuer_not_found", "no issuer has this id"))?;
        let keys = store.issuer_keys(&id).await.map_err(hosted_store_error)?;
        let count = list_count(&state, &id).await?;
        hosted_dto_from_parts(&state, issuer, count, keys, time::OffsetDateTime::now_utc())
    } else {
        return Err(ApiError::not_found(
            "issuer_not_found",
            "no issuer has this id",
        ));
    };
    let etag = issuer_etag(&dto);
    let write_version = issuer_write_version(&dto);
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).expect("hexadecimal ETag is a valid header value"),
    );
    h.insert(
        HeaderName::from_static("issuer-version"),
        HeaderValue::from_str(&write_version)
            .expect("hexadecimal issuer version is a valid header value"),
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
        async fn record_static_key_revocations(
            &self,
            _revocations: &[(String, String)],
        ) -> Result<(), crate::domain::models::hosted_issuer::HostedIssuerError> {
            Ok(())
        }

        async fn static_key_was_revoked(
            &self,
            _kid: &str,
            _material: &str,
        ) -> Result<bool, crate::domain::models::hosted_issuer::HostedIssuerError> {
            Ok(false)
        }

        async fn list_issuers_after(
            &self,
            after: Option<&str>,
            limit: usize,
            filters: &HostedIssuerFilter,
            now: time::OffsetDateTime,
        ) -> Result<Vec<HostedIssuer>, crate::domain::models::hosted_issuer::HostedIssuerError>
        {
            let mut issuers: Vec<_> = self
                .issuers
                .lock()
                .unwrap()
                .iter()
                .filter(|issuer| after.is_none_or(|after| issuer.id.as_str() > after))
                .filter(|issuer| {
                    filters
                        .tier
                        .as_deref()
                        .is_none_or(|tier| issuer.tier == tier)
                })
                .filter(|issuer| {
                    filters
                        .owner
                        .as_deref()
                        .is_none_or(|owner| issuer.owner.as_deref() == Some(owner))
                })
                .filter(|issuer| {
                    filters.state.is_none_or(|state| match state {
                        HostedIssuerReadState::Active => {
                            issuer.read_state(now) == HostedIssuerReadState::Active
                        }
                        HostedIssuerReadState::Suspended => {
                            issuer.read_state(now) == HostedIssuerReadState::Suspended
                        }
                        HostedIssuerReadState::Expired => {
                            issuer.read_state(now) == HostedIssuerReadState::Expired
                        }
                    })
                })
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

        async fn all_issuers(
            &self,
        ) -> Result<Vec<HostedIssuer>, crate::domain::models::hosted_issuer::HostedIssuerError>
        {
            Ok(self.issuers.lock().unwrap().clone())
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
            _actor: &str,
        ) -> Result<HostedIssuer, crate::domain::models::hosted_issuer::HostedIssuerError> {
            unreachable!()
        }

        async fn add_key(
            &self,
            _key: HostedIssuerKey,
            _actor: &str,
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

    fn static_registry_with_id(
        id: &str,
    ) -> Arc<crate::server::auth::issuer_registry::RegistryHandle> {
        let yaml = format!(
            "version: 1\nissuers:\n  - id: {id}\n    aggregation_id: 00000000-0000-4000-8000-000000000001\n    tier: standard\n    keys:\n      - kid: static-key\n        alg: ES256\n        jwk:\n          kty: EC\n          crv: P-256\n          kid: static-key\n          alg: ES256\n          x: NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8\n          y: eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M\nadmins: []\n"
        );
        Arc::new(crate::server::auth::issuer_registry::RegistryHandle::from_yaml(&yaml).unwrap())
    }

    fn static_registry() -> Arc<crate::server::auth::issuer_registry::RegistryHandle> {
        static_registry_with_id("b")
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
    async fn hosted_filters_are_applied_before_link_pagination() {
        let mut other_owner = hosted_issuer("e");
        other_owner.owner = Some("portal|someone-else".into());
        let hosted = Arc::new(Mutex::new(vec![
            hosted_issuer("c"),
            hosted_issuer("d"),
            other_owner,
        ]));
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
        let (headers, Json(page)) = list_issuers(
            State(state),
            Extension(admin),
            Ok(Query(ListQuery {
                source: Some(IssuerSource::Portal),
                tier: Some(IssuerTier::Sandbox),
                state: Some(IssuerReadState::Active),
                owner: Some("portal|test-user".into()),
                cursor: None,
                limit: Some(1),
            })),
        )
        .await
        .unwrap();
        assert_eq!(
            page.issuers
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            ["c"]
        );
        assert!(page.next_cursor.is_some());
        assert!(
            headers[header::LINK]
                .to_str()
                .unwrap()
                .contains("owner=portal%7Ctest-user")
        );
    }

    #[test]
    fn query_filters_reject_unknown_enum_values() {
        assert!(serde_json::from_str::<ListQuery>(r#"{"source":"credential"}"#).is_err());
        assert!(serde_json::from_str::<ListQuery>(r#"{"state":"revoked"}"#).is_err());
    }

    #[test]
    fn issuer_write_version_tracks_persisted_version_not_usage() {
        let mut issuer = IssuerDto {
            id: "issuer-a".into(),
            aggregation_id: "aggregation-a".into(),
            aggregation_uri: None,
            display_name: Some("Issuer A".into()),
            source: "portal".into(),
            tier: "sandbox".into(),
            state: "active".into(),
            owner: Some("portal|alice".into()),
            created_at: Some(1),
            expires_at: Some(2),
            keys: vec![KeyDto {
                kid: "key-a".into(),
                alg: "ES256".into(),
                state: "active".into(),
                not_before: None,
                not_after: None,
                created_at: Some(1),
                public_key: serde_json::Value::Null,
            }],
            usage: UsageDto {
                lists: 1,
                lists_limit: 10,
                keys: 1,
                keys_limit: 2,
            },
            persisted_version: Some(1),
        };
        let original = issuer_write_version(&issuer);
        issuer.usage.lists += 1;
        issuer.aggregation_uri = Some("https://example.test/aggregation".into());
        assert_eq!(issuer_write_version(&issuer), original);
        issuer.state = "expired".into();
        assert_eq!(issuer_write_version(&issuer), original);
        issuer.keys[0].state = "revoked".into();
        assert_eq!(issuer_write_version(&issuer), original);
        issuer.persisted_version = Some(2);
        assert_ne!(issuer_write_version(&issuer), original);
    }

    #[tokio::test]
    async fn concurrent_inserts_do_not_skip_preexisting_issuers_or_repeat_results() {
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
            ["aa", "bb"]
        );
        let third = query_page(state, &admin, second.next_cursor, 2).await;
        assert_eq!(
            third
                .issuers
                .iter()
                .map(|issuer| issuer.id.as_str())
                .collect::<Vec<_>>(),
            ["c"]
        );
        let visited: Vec<_> = first
            .issuers
            .iter()
            .chain(second.issuers.iter())
            .chain(third.issuers.iter())
            .map(|issuer| issuer.id.as_str())
            .collect();
        assert_eq!(visited.iter().filter(|id| **id == "a").count(), 1);
        assert_eq!(visited.iter().filter(|id| **id == "b").count(), 1);
        assert_eq!(visited.iter().filter(|id| **id == "c").count(), 1);
        assert_eq!(visited.len(), 5);
    }

    #[tokio::test]
    async fn portal_cursor_is_not_advanced_by_static_id_collation() {
        let portal_id = "a0000000-0000-4000-8000-000000000001";
        let hosted = Arc::new(Mutex::new(vec![hosted_issuer(portal_id)]));
        let mut state = crate::test_utils::test_app_state(None).await;
        state.admin_registry = static_registry_with_id("Issuer-A");
        state.hosted_issuer_store = Some(Arc::new(MutableHostedStore {
            issuers: hosted,
            keys: Arc::default(),
        }));
        let admin = AuthenticatedAdmin {
            id: "operator".into(),
            scopes: vec!["issuers:read".into()],
        };
        let first = query_page(state.clone(), &admin, None, 1).await;
        assert_eq!(first.issuers[0].id, "Issuer-A");
        let cursor = cursor_decode(
            first
                .next_cursor
                .as_deref()
                .expect("portal issuer is a next page"),
            &Filters::default(),
        )
        .unwrap();
        assert_eq!(cursor.after_static.as_deref(), Some("Issuer-A"));
        assert!(cursor.after_portal.is_none());
        let second = query_page(state, &admin, first.next_cursor, 1).await;
        assert_eq!(second.issuers[0].id, portal_id);
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
            source: Some(IssuerSource::Static),
            ..Filters::default()
        };
        let cursor = cursor_encode(Cursor {
            after_static: Some("issuer-1".into()),
            after_portal: Some("00000000-0000-4000-8000-000000000001".into()),
            filters: filters.clone(),
        });
        let decoded = cursor_decode(&cursor, &filters).unwrap();
        assert_eq!(decoded.after_static.as_deref(), Some("issuer-1"));
        assert_eq!(
            decoded.after_portal.as_deref(),
            Some("00000000-0000-4000-8000-000000000001")
        );
        assert!(cursor_decode(&cursor, &Filters::default()).is_err());
        let control_cursor = cursor_encode(Cursor {
            after_static: None,
            after_portal: Some("issuer\0id".into()),
            filters: filters.clone(),
        });
        assert!(cursor_decode(&control_cursor, &filters).is_err());
    }

    #[test]
    fn unavailable_usage_lookup_returns_service_unavailable() {
        let response = crate::domain::models::status_list::StatusListError::Unavailable
            .into_api_error()
            .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    }

    #[test]
    fn hosted_storage_corruption_is_internal_error_not_unavailable() {
        use crate::domain::models::hosted_issuer::HostedIssuerError;

        let unavailable = hosted_store_error(HostedIssuerError::Backend(Box::new(
            std::io::Error::other("connection failed"),
        )))
        .into_response();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

        let corrupt =
            hosted_store_error(HostedIssuerError::Corrupt("bad row".into())).into_response();
        assert_eq!(corrupt.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
                source: Some(IssuerSource::Static),
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
        assert_eq!(page.issuers[0].usage.keys, 1);
        assert_eq!(
            page.issuers[0].usage.keys_limit,
            state.tiers.standard.max_keys as u64
        );
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
    async fn detail_etag_tracks_write_state_without_usage() {
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
        issuers.lock().unwrap()[0].version += 1;
        let with_key = detail_response(app.clone(), uri).await.headers()[header::ETAG].clone();
        assert_ne!(with_key, initial);
        crate::test_utils::publish_list(&state.service, "portal", "list-1").await;
        let with_list = detail_response(app.clone(), uri).await.headers()[header::ETAG].clone();
        assert_eq!(with_list, with_key);
        issuers.lock().unwrap()[0].expires_at = Some(time::OffsetDateTime::UNIX_EPOCH);
        let expired = detail_response(app.clone(), uri).await;
        assert_eq!(expired.headers()[header::ETAG], with_list);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(expired.into_body(), 16384)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["state"], "expired");
        assert_eq!(body["usage"]["lists"], 1);
        assert_eq!(body["usage"]["keys"], 1);
        assert_eq!(body["usage"]["keys_limit"], state.tiers.sandbox.max_keys);

        // A key past `not_after` frees its slot, as in the store's quota check.
        let ended = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let mut expired_key = keys.lock().unwrap()[0].clone();
        expired_key.kid = "ended-key".into();
        expired_key.not_after = Some(ended);
        keys.lock().unwrap().push(expired_key);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(detail_response(app, uri).await.into_body(), 16384)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["usage"]["keys"], 1);
    }
}
