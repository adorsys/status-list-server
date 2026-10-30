//! Admin API reads on the admin listener (`docs/openapi-admin.yaml`):
//! `listIssuers` and `getIssuer`.
//!
//! Every issuer comes from the registry file, so each is `source: static`:
//! it has no owner, no creation record and no expiry, and its keys are never
//! `revoked` (a key leaves the registry instead). Portal issuers exist only
//! in the hosted profile, which this server does not run, so a `source=portal`
//! or `owner` filter matches nothing.

use axum::{
    Extension, Json,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::domain::models::credential::{AggregationId, Issuer};
use crate::domain::models::tier::{IssuerTier, IssuerUsage};
use crate::server::{
    AppState,
    auth::{AuthenticatedAdmin, issuer_registry::IssuerEntry},
    error::{ApiError, IntoApiError},
};

const READ_SCOPE: &str = "issuers:read";
const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 100;
/// Versions the cursor encoding so it can change without misreading old ones.
const CURSOR_PREFIX: &str = "v1:";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum IssuerSource {
    Static,
    Portal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum IssuerState {
    Active,
    Suspended,
    Expired,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListIssuersQuery {
    source: Option<IssuerSource>,
    tier: Option<IssuerTier>,
    state: Option<IssuerState>,
    owner: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct IssuerView {
    id: String,
    aggregation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregation_uri: Option<String>,
    display_name: Option<String>,
    source: IssuerSource,
    tier: IssuerTier,
    state: IssuerState,
    owner: Option<String>,
    created_at: Option<i64>,
    expires_at: Option<i64>,
    keys: Vec<KeyView>,
    usage: IssuerUsage,
}

#[derive(Debug, Serialize)]
struct KeyView {
    kid: String,
    alg: String,
    state: &'static str,
    not_before: Option<i64>,
    not_after: Option<i64>,
    created_at: Option<i64>,
    public_key: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct IssuerPage {
    issuers: Vec<IssuerView>,
    next_cursor: Option<String>,
}

fn invalid_query(description: impl Into<String>) -> ApiError {
    ApiError::bad_request("invalid_query", description)
}

/// Scopes come from the registry entry of the admin, never from its token,
/// so a reload that removes a scope applies to the next request.
fn require_scope(
    state: &AppState,
    admin: &AuthenticatedAdmin,
    scope: &str,
) -> Result<(), ApiError> {
    if state
        .registry_handle
        .snapshot()
        .has_admin_scope(&admin.id, scope)
    {
        return Ok(());
    }
    let challenge = HeaderValue::try_from(format!(
        "Bearer error=\"insufficient_scope\", scope=\"{scope}\""
    ))
    .map_err(ApiError::internal)?;
    Err(
        ApiError::forbidden("insufficient_scope", format!("{scope} is required"))
            .with_header(header::WWW_AUTHENTICATE, challenge),
    )
}

/// `<provider>|<subject>`, as `Owner` in the admin contract.
fn is_owner(value: &str) -> bool {
    (3..=255).contains(&value.len())
        && value.split_once('|').is_some_and(|(provider, subject)| {
            !provider.is_empty()
                && !subject.is_empty()
                && provider
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn encode_cursor(issuer_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{CURSOR_PREFIX}{issuer_id}"))
}

fn decode_cursor(cursor: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor).ok()?;
    String::from_utf8(bytes)
        .ok()?
        .strip_prefix(CURSOR_PREFIX)
        .map(str::to_owned)
}

fn issuer_state(issuer: &IssuerEntry) -> IssuerState {
    if issuer.disabled {
        IssuerState::Suspended
    } else {
        IssuerState::Active
    }
}

/// The issuer's version for `ETag`: a digest of its registry entry, so it
/// changes whenever the entry does.
fn issuer_etag(issuer: &IssuerEntry) -> Result<HeaderValue, ApiError> {
    let entry = serde_json::to_vec(issuer).map_err(ApiError::internal)?;
    let digest = hex::encode(Sha256::digest(&entry));
    HeaderValue::try_from(format!("\"{}\"", &digest[..32])).map_err(ApiError::internal)
}

async fn list_counts(state: &AppState) -> Result<HashMap<String, u64>, ApiError> {
    state
        .service
        .status_list_repo()
        .list_counts_by_issuer()
        .await
        .map_err(IntoApiError::into_api_error)
}

fn issuer_view(
    state: &AppState,
    issuer: &IssuerEntry,
    lists: u64,
    now: time::OffsetDateTime,
) -> IssuerView {
    let unix = |at: Option<time::OffsetDateTime>| at.map(time::OffsetDateTime::unix_timestamp);
    // Registry keys are appended, so reversing the file order lists the
    // newest first, as the contract asks.
    let keys = issuer
        .keys
        .iter()
        .rev()
        .map(|key| {
            let (not_before, not_after) = key.validity();
            KeyView {
                kid: key.kid.clone(),
                alg: key.alg.clone(),
                state: "active",
                not_before: unix(not_before),
                not_after: unix(not_after),
                created_at: None,
                public_key: key.jwk.clone(),
            }
        })
        .collect();
    IssuerView {
        id: issuer.id.clone(),
        aggregation_id: issuer.aggregation_id,
        aggregation_uri: state.aggregation_uri_for(
            &Issuer(issuer.id.clone()),
            AggregationId(issuer.aggregation_id),
        ),
        display_name: issuer.display_name.clone(),
        source: IssuerSource::Static,
        tier: issuer.tier,
        state: issuer_state(issuer),
        owner: None,
        created_at: None,
        expires_at: None,
        keys,
        usage: IssuerUsage::new(
            lists,
            issuer.active_key_count(now),
            state.tiers.get(issuer.tier),
        ),
    }
}

/// `GET /admin/v1/issuers`
pub async fn list_issuers(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    query: Result<Query<ListIssuersQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    require_scope(&state, &admin, READ_SCOPE)?;
    let Query(query) = query.map_err(|rejection| invalid_query(rejection.body_text()))?;
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(invalid_query(format!(
            "limit must be between 1 and {MAX_PAGE_SIZE}"
        )));
    }
    if query.owner.as_deref().is_some_and(|owner| !is_owner(owner)) {
        return Err(invalid_query("owner must be `<provider>|<subject>`"));
    }
    let after = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor(cursor).ok_or_else(|| invalid_query("cursor is invalid")))
        .transpose()?;

    let registry = state.registry_handle.snapshot();
    let static_only = query
        .source
        .is_none_or(|source| source == IssuerSource::Static);
    let mut matching: Vec<&IssuerEntry> = registry
        .issuers()
        .iter()
        .filter(|_| static_only && query.owner.is_none())
        .filter(|issuer| query.tier.is_none_or(|tier| issuer.tier == tier))
        .filter(|issuer| {
            query
                .state
                .is_none_or(|state| issuer_state(issuer) == state)
        })
        .filter(|issuer| {
            after
                .as_deref()
                .is_none_or(|after| issuer.id.as_str() > after)
        })
        .collect();
    matching.sort_by(|a, b| a.id.cmp(&b.id));
    let has_next = matching.len() > limit;
    matching.truncate(limit);

    let counts = if matching.is_empty() {
        HashMap::new()
    } else {
        list_counts(&state).await?
    };
    let now = time::OffsetDateTime::now_utc();
    let issuers: Vec<IssuerView> = matching
        .iter()
        .map(|issuer| {
            issuer_view(
                &state,
                issuer,
                counts.get(&issuer.id).copied().unwrap_or(0),
                now,
            )
        })
        .collect();
    let next_cursor = has_next
        .then(|| matching.last().map(|issuer| encode_cursor(&issuer.id)))
        .flatten();

    let mut headers = HeaderMap::new();
    if let Some(cursor) = &next_cursor {
        let mut next = url::form_urlencoded::Serializer::new(String::new());
        if let Some(source) = query.source {
            next.append_pair("source", source_name(source));
        }
        if let Some(tier) = query.tier {
            next.append_pair("tier", tier.as_str());
        }
        if let Some(issuer_state) = query.state {
            next.append_pair("state", state_name(issuer_state));
        }
        next.append_pair("limit", &limit.to_string());
        next.append_pair("cursor", cursor);
        let link = HeaderValue::try_from(format!(
            "</admin/v1/issuers?{}>; rel=\"next\"",
            next.finish()
        ))
        .map_err(ApiError::internal)?;
        headers.insert(header::LINK, link);
    }
    Ok((
        headers,
        Json(IssuerPage {
            issuers,
            next_cursor,
        }),
    )
        .into_response())
}

fn source_name(source: IssuerSource) -> &'static str {
    match source {
        IssuerSource::Static => "static",
        IssuerSource::Portal => "portal",
    }
}

fn state_name(state: IssuerState) -> &'static str {
    match state {
        IssuerState::Active => "active",
        IssuerState::Suspended => "suspended",
        IssuerState::Expired => "expired",
    }
}

/// `GET /admin/v1/issuers/{issuer_id}`
pub async fn get_issuer(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    Path(issuer_id): Path<String>,
) -> Result<Response, ApiError> {
    require_scope(&state, &admin, READ_SCOPE)?;
    let registry = state.registry_handle.snapshot();
    let issuer = registry
        .issuer(&issuer_id)
        .ok_or_else(|| ApiError::not_found("issuer_not_found", "no issuer has this id"))?;
    let counts = list_counts(&state).await?;
    let view = issuer_view(
        &state,
        issuer,
        counts.get(&issuer.id).copied().unwrap_or(0),
        time::OffsetDateTime::now_utc(),
    );
    Ok(([(header::ETAG, issuer_etag(issuer)?)], Json(view)).into_response())
}

/// Sets `Cache-Control: no-store` on every admin response, errors included,
/// as the admin contract fixes that exact value.
pub async fn no_store(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::auth::issuer_registry::RegistryHandle;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
    };
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tower::ServiceExt;

    struct TestKey {
        pkcs8: Vec<u8>,
        kid: String,
        jwk: Value,
    }

    fn generate_key() -> TestKey {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        // Uncompressed SEC1 point: 0x04 || x || y.
        let point = pair.public_key().as_ref();
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        });
        TestKey {
            pkcs8: pkcs8.as_ref().to_vec(),
            kid: uuid::Uuid::new_v4().to_string(),
            jwk,
        }
    }

    fn registry_key(key: &TestKey) -> Value {
        json!({ "kid": key.kid, "alg": "ES256", "jwk": key.jwk })
    }

    fn token(key: &TestKey, typ: &str, iss: &str, aud: Option<&str>) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some(typ.to_string());
        header.kid = Some(key.kid.clone());
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut claims = json!({ "iss": iss, "iat": now, "exp": now + 120 });
        if let Some(aud) = aud {
            claims["aud"] = json!(aud);
        }
        jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_ec_der(&key.pkcs8),
        )
        .unwrap()
    }

    struct Fixture {
        router: Router,
        state: AppState,
        reader: TestKey,
        writer: TestKey,
        issuer_a: TestKey,
    }

    /// Admins `reader` (`issuers:read`) and `writer` (`issuers:write`), and
    /// issuers `issuer-a` (standard, two keys, one expired), `issuer-b`
    /// (sandbox) and `issuer-c` (disabled).
    async fn fixture(configure: impl FnOnce(&mut AppState)) -> Fixture {
        let [reader, writer, issuer_a, issuer_a_old, issuer_b, issuer_c] =
            std::array::from_fn(|_| generate_key());
        let mut expired = registry_key(&issuer_a_old);
        expired["not_after"] = json!("2020-01-01T00:00:00Z");
        let registry = serde_saphyr::to_string(&json!({
            "version": 1,
            "issuers": [
                { "id": "issuer-c", "aggregation_id": uuid::Uuid::new_v4(), "disabled": true,
                  "keys": [registry_key(&issuer_c)] },
                { "id": "issuer-a", "aggregation_id": uuid::Uuid::new_v4(),
                  "display_name": "Issuer A", "keys": [expired, registry_key(&issuer_a)] },
                { "id": "issuer-b", "aggregation_id": uuid::Uuid::new_v4(), "tier": "sandbox",
                  "keys": [registry_key(&issuer_b)] },
            ],
            "admins": [
                { "id": "reader", "scopes": ["issuers:read"], "keys": [registry_key(&reader)] },
                { "id": "writer", "scopes": ["issuers:write"], "keys": [registry_key(&writer)] },
            ],
        }))
        .unwrap();
        let mut state = crate::test_utils::test_app_state(None).await;
        state.set_issuer_registry(Arc::new(RegistryHandle::from_yaml(&registry).unwrap()));
        configure(&mut state);
        let config = crate::config::Config::load_from_overrides(&[]).unwrap();
        let router =
            crate::startup::admin_routes(&config, prometheus::Registry::new(), state.clone())
                .with_state(state.clone());
        Fixture {
            router,
            state,
            reader,
            writer,
            issuer_a,
        }
    }

    fn admin_token(key: &TestKey, iss: &str) -> String {
        token(key, "statuslist-admin+jwt", iss, None)
    }

    async fn get(
        router: &Router,
        uri: &str,
        token: Option<&str>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = Request::builder().uri(uri);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (status, headers, body)
    }

    fn ids(body: &Value) -> Vec<&str> {
        body["issuers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|issuer| issuer["id"].as_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn lists_registry_issuers_ordered_by_id_with_their_usage() {
        let fx = fixture(|_| {}).await;
        crate::test_utils::publish_list(
            &fx.state.service,
            "issuer-a",
            &uuid::Uuid::new_v4().to_string(),
        )
        .await;
        let token = admin_token(&fx.reader, "reader");

        let (status, headers, body) = get(&fx.router, "/admin/v1/issuers", Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(ids(&body), ["issuer-a", "issuer-b", "issuer-c"]);
        assert_eq!(body["next_cursor"], Value::Null);
        assert!(headers.get(header::LINK).is_none());

        let a = &body["issuers"][0];
        assert_eq!(a["source"], "static");
        assert_eq!(a["tier"], "standard");
        assert_eq!(a["state"], "active");
        assert_eq!(a["display_name"], "Issuer A");
        assert_eq!(a["owner"], Value::Null);
        assert_eq!(a["created_at"], Value::Null);
        assert_eq!(a["expires_at"], Value::Null);
        assert_eq!(
            a["usage"],
            json!({ "lists": 1, "lists_limit": 1000, "keys": 1, "keys_limit": 5 }),
            "the expired key does not count"
        );
        // Newest key first; every static key is `active`.
        assert_eq!(a["keys"][0]["kid"], fx.issuer_a.kid);
        assert_eq!(a["keys"][1]["not_after"], 1_577_836_800);
        assert_eq!(a["keys"][1]["state"], "active");

        let b = &body["issuers"][1];
        assert_eq!(b["tier"], "sandbox");
        assert_eq!(
            b["usage"],
            json!({ "lists": 0, "lists_limit": 10, "keys": 1, "keys_limit": 2 })
        );
        assert_eq!(body["issuers"][2]["state"], "suspended");
    }

    #[tokio::test]
    async fn pages_follow_the_cursor_and_keep_filters() {
        let fx = fixture(|_| {}).await;
        let token = admin_token(&fx.reader, "reader");

        let (status, headers, body) = get(
            &fx.router,
            "/admin/v1/issuers?state=active&limit=1",
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(ids(&body), ["issuer-a"]);
        let cursor = body["next_cursor"].as_str().unwrap().to_owned();
        let link = headers[header::LINK].to_str().unwrap().to_owned();
        assert!(link.ends_with("; rel=\"next\""), "{link}");
        assert!(
            link.contains("state=active") && link.contains("limit=1"),
            "{link}"
        );

        let next = link
            .trim_start_matches('<')
            .split_once('>')
            .unwrap()
            .0
            .to_owned();
        let (_, headers, body) = get(&fx.router, &next, Some(&token)).await;
        assert_eq!(ids(&body), ["issuer-b"]);
        assert_eq!(body["next_cursor"], Value::Null, "issuer-c is suspended");
        assert!(headers.get(header::LINK).is_none());

        let (_, _, body) = get(
            &fx.router,
            &format!("/admin/v1/issuers?cursor={cursor}"),
            Some(&token),
        )
        .await;
        assert_eq!(ids(&body), ["issuer-b", "issuer-c"]);
    }

    #[tokio::test]
    async fn filters_select_tier_source_and_owner() {
        let fx = fixture(|_| {}).await;
        let token = admin_token(&fx.reader, "reader");
        for (query, expected) in [
            ("tier=sandbox", vec!["issuer-b"]),
            ("source=static&tier=standard", vec!["issuer-a", "issuer-c"]),
            ("source=portal", vec![]),
            ("owner=github%7C5821374", vec![]),
            ("state=expired", vec![]),
        ] {
            let (status, _, body) = get(
                &fx.router,
                &format!("/admin/v1/issuers?{query}"),
                Some(&token),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{query}: {body}");
            assert_eq!(ids(&body), expected, "{query}");
        }
    }

    #[tokio::test]
    async fn invalid_queries_are_rejected() {
        let fx = fixture(|_| {}).await;
        let token = admin_token(&fx.reader, "reader");
        for query in [
            "limit=0",
            "limit=101",
            "limit=many",
            "tier=premium",
            "state=gone",
            "owner=no-separator",
            "owner=Upper%7Cx",
            "cursor=%21%21",
            "cursor=aXNzdWVyLWE",
            "unknown=1",
        ] {
            let (status, headers, body) = get(
                &fx.router,
                &format!("/admin/v1/issuers?{query}"),
                Some(&token),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
            assert_eq!(body["error"], "invalid_query", "{query}");
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        }
    }

    #[tokio::test]
    async fn gets_one_issuer_with_an_etag_that_follows_its_entry() {
        let fx = fixture(|_| {}).await;
        let token = admin_token(&fx.reader, "reader");

        let (status, headers, body) =
            get(&fx.router, "/admin/v1/issuers/issuer-b", Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], "issuer-b");
        assert_eq!(body["usage"]["lists_limit"], 10);
        let etag = headers[header::ETAG].to_str().unwrap().to_owned();
        assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
        let (_, again, _) = get(&fx.router, "/admin/v1/issuers/issuer-b", Some(&token)).await;
        assert_eq!(again[header::ETAG], etag.as_str());
        let (_, other, _) = get(&fx.router, "/admin/v1/issuers/issuer-a", Some(&token)).await;
        assert_ne!(other[header::ETAG], etag.as_str());

        let (status, headers, body) =
            get(&fx.router, "/admin/v1/issuers/nobody", Some(&token)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "issuer_not_found");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn a_principal_without_issuers_read_gets_insufficient_scope() {
        let fx = fixture(|_| {}).await;
        let token = admin_token(&fx.writer, "writer");
        for uri in ["/admin/v1/issuers", "/admin/v1/issuers/issuer-a"] {
            let (status, headers, body) = get(&fx.router, uri, Some(&token)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(body["error"], "insufficient_scope");
            assert_eq!(
                headers[header::WWW_AUTHENTICATE],
                "Bearer error=\"insufficient_scope\", scope=\"issuers:read\""
            );
        }
    }

    #[tokio::test]
    async fn only_admin_tokens_are_accepted() {
        let fx = fixture(|_| {}).await;
        let (status, headers, body) = get(&fx.router, "/admin/v1/issuers", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "missing_token");
        assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");

        for rejected in [
            // A management token, even one signed with an admin key.
            token(&fx.reader, "statuslist-management+jwt", "reader", None),
            // An admin-typed token signed with an issuer key.
            admin_token(&fx.issuer_a, "issuer-a"),
            // An admin key claiming another admin.
            admin_token(&fx.reader, "writer"),
        ] {
            let (status, headers, body) =
                get(&fx.router, "/admin/v1/issuers", Some(&rejected)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
            assert_eq!(body["error"], "invalid_token");
            assert_eq!(
                headers[header::WWW_AUTHENTICATE],
                "Bearer error=\"invalid_token\""
            );
        }
    }

    #[tokio::test]
    async fn configured_audiences_are_required() {
        let fx = fixture(|state| state.admin_auth.audiences = vec!["admin-api".into()]).await;
        let with = |aud| token(&fx.reader, "statuslist-admin+jwt", "reader", aud);
        let (status, _, _) = get(&fx.router, "/admin/v1/issuers", Some(&with(None))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = get(&fx.router, "/admin/v1/issuers", Some(&with(Some("other")))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = get(
            &fx.router,
            "/admin/v1/issuers",
            Some(&with(Some("admin-api"))),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn without_audiences_a_required_audience_rejects_every_token() {
        let fx = fixture(|state| state.admin_auth.audience_required = true).await;
        let (status, _, body) = get(
            &fx.router,
            "/admin/v1/issuers",
            Some(&admin_token(&fx.reader, "reader")),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    #[tokio::test]
    async fn admin_tokens_are_rejected_on_the_management_auth() {
        // The reverse of `only_admin_tokens_are_accepted`, through `auth`.
        let fx = fixture(|_| {}).await;
        let app = Router::new()
            .route("/probe", axum::routing::get(|| async { Json(json!({})) }))
            .route_layer(axum::middleware::from_fn_with_state(
                fx.state.clone(),
                crate::server::auth::auth,
            ))
            .with_state(fx.state.clone());
        for rejected in [
            admin_token(&fx.reader, "reader"),
            token(&fx.reader, "statuslist-management+jwt", "reader", None),
        ] {
            let (status, _, _) = get(&app, "/probe", Some(&rejected)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let issuer = token(&fx.issuer_a, "statuslist-management+jwt", "issuer-a", None);
        let (status, _, _) = get(&app, "/probe", Some(&issuer)).await;
        assert_eq!(status, StatusCode::OK);
    }
}
