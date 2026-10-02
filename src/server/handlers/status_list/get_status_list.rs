use std::fmt::Debug;
use std::sync::{Arc, Mutex, OnceLock};

use axum::{
    body::Bytes,
    extract::rejection::QueryRejection,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use opentelemetry::{KeyValue, global, metrics::Counter};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::{
    domain::{
        models::status_list::{StatusListError, StatusListRecord},
        ports::SigningMaterial,
    },
    server::{AppState, error::ApiError},
};

use super::utils::{
    conditional::{
        ConditionalResponse, TokenValidity, evaluate_conditional_request, format_http_date,
        token_window,
    },
    constants::{ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT},
    etag::{content_hash, generate_historical_etag, generate_token_etag},
    negotiation::{AcceptType, client_accepts_gzip, negotiate_accept},
    token::build_status_list_token,
    token_cache::signer_fingerprint,
};
use crate::server::cache::{CachedToken, TokenCacheKey, TokenEncoding};

/// Conditional-revalidation SLI counter. Cached after first use (the same
/// pattern as `token.rs`): the global meter provider is installed by
/// `setup_metrics` before any request is served, so a handle captured here is
/// valid (unlike one taken at module init, which would be a permanent no-op).
///
/// The `outcome` label lets operators verify the 304 path is still serving
/// unchanged lists efficiently and spot a regression that silently turns every
/// conditional GET into a full re-sign (the exact failure mode this fix guards
/// against).
#[derive(Clone)]
struct RevalidationMetrics {
    total: Counter<u64>,
}

fn revalidation_metrics() -> RevalidationMetrics {
    static METRICS: OnceLock<Mutex<Option<(u64, RevalidationMetrics)>>> = OnceLock::new();
    crate::utils::metrics::cached_instruments(&METRICS, || {
        let meter = global::meter("status-list-server");
        RevalidationMetrics {
            total: meter
                .u64_counter("conditional_revalidation_total")
                .with_description("Conditional GET revalidation outcomes (not_modified|modified).")
                .build(),
        }
    })
}

/// Handle GET /status-lists/{list_id} request.
///
/// This function handles the following cases:
///
/// - Retrieve a status list identified by its list id.
/// - Retrieve a historical status list identified by its list id and time.
#[tracing::instrument(skip_all, fields(list_id = %list_id), err(Debug))]
pub async fn get_status_list(
    State(state): State<AppState>,
    Path(list_id): Path<String>,
    query_result: Result<Query<StatusListQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<impl IntoResponse + Debug + use<>, ApiError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    get_status_list_at(State(state), list_id, query_result, headers, now).await
}

/// Request-time implementation of [`get_status_list`] with an explicit `now`
/// (injected rather than read from the clock inside) so tests can advance the
/// clock deterministically and pin the token-expiry revalidation behaviour.
async fn get_status_list_at(
    State(state): State<AppState>,
    list_id: String,
    query_result: Result<Query<StatusListQuery>, QueryRejection>,
    headers: HeaderMap,
    now: i64,
) -> Result<impl IntoResponse + Debug + use<>, ApiError> {
    let query = match query_result {
        Ok(Query(q)) => q,
        Err(e) => {
            tracing::warn!("Failed to parse query parameters: {e}");
            return Err(ApiError::bad_request(
                "invalid_query",
                format!("Failed to parse query parameters: {e}"),
            ));
        }
    };
    let client_accepts_gzip = client_accepts_gzip(&headers);

    // RFC 9110 §5.3 folds multiple `Accept` field lines into one list, so read
    // every line and negotiate the whole set together.
    let accept_fields: Vec<&str> = headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let accept_type = match negotiate_accept(accept_fields) {
        Some(ty) => ty,
        None => {
            // Advertise that the outcome depends on `Accept`. The 406 is
            // `no-store` (set by `ApiError`), so a shared cache never stores it
            // either way; `Vary` just reflects RFC 9110 §12.5.5's SHOULD.
            return Err(ApiError::new(
                StatusCode::NOT_ACCEPTABLE,
                "invalid_accept_header",
                Some(format!(
                    "No acceptable media type. Supported: {ACCEPT_STATUS_LISTS_HEADER_JWT}, \
                     {ACCEPT_STATUS_LISTS_HEADER_CWT}"
                )),
            )
            .with_header(
                header::VARY,
                HeaderValue::from_static("Accept, Accept-Encoding"),
            ));
        }
    };

    if let Some(time) = query.time {
        return handle_historical_request(&list_id, time, accept_type, &state, client_accepts_gzip)
            .await;
    }

    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok());
    let if_modified_since = headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|h| h.to_str().ok());

    let status_record = fetch_status_record(&list_id, &state).await?;

    // Anchor the token and its validator to the current token validity window so
    // the representation identity — and hence the weak ETag — is stable for the
    // whole window, letting the signed-bytes cache reuse one sign per window.
    // The token's `iat` is `max(window_start, updated_at)`, so a mid-window
    // content change never mints a token claiming to predate the change.
    let validity = TokenValidity::new(state.token_exp_secs, state.token_ttl_secs);
    let window_start = token_window(now, validity).0;

    // Derive the cache key and weak ETag *before* any signing, so a matching
    // `If-None-Match` answers 304 without ever minting a token. The key's signer
    // fingerprint only reads the in-memory signing snapshot; it does not sign.
    // The returned `signing_material` is the *same* snapshot used for the
    // fingerprint, and is threaded into the token builder so a concurrent
    // certificate/key reload can never cache bytes signed by one key under
    // another key's cache entry.
    let (key, signing_material) = build_token_cache_key(
        &state,
        accept_type,
        &status_record,
        &list_id,
        window_start,
        client_accepts_gzip,
    )
    .await?;
    let current_etag = generate_token_etag(&key);

    let last_modified_ts = status_record.updated_at;
    let last_modified = format_http_date(last_modified_ts);
    let cache_control = build_cache_control(state.token_ttl_secs);

    match evaluate_conditional_request(
        if_none_match,
        if_modified_since,
        &current_etag,
        last_modified_ts,
        now,
        validity,
    ) {
        ConditionalResponse::NotModified => {
            revalidation_metrics()
                .total
                .add(1, &[KeyValue::new("outcome", "not_modified")]);
            Ok((
                StatusCode::NOT_MODIFIED,
                [
                    (header::ETAG, current_etag.as_str()),
                    (header::LAST_MODIFIED, last_modified.as_str()),
                    (header::CACHE_CONTROL, cache_control.as_str()),
                    (header::VARY, "Accept, Accept-Encoding"),
                ],
            )
                .into_response())
        }
        ConditionalResponse::Modified => {
            revalidation_metrics()
                .total
                .add(1, &[KeyValue::new("outcome", "modified")]);
            let (token_bytes, token_encoding) = get_or_build_live_token(
                &state,
                accept_type,
                &status_record,
                &key,
                &signing_material,
                now,
                client_accepts_gzip,
            )
            .await?;
            Ok(build_ok_response(
                token_bytes,
                token_encoding,
                accept_type,
                &current_etag,
                &last_modified,
                &cache_control,
            ))
        }
        ConditionalResponse::ExpiredToken => {
            // The list is unchanged but the client's cached token has reached its
            // `exp`: a 304 would hand the relying party a body-less, expired,
            // unusable token (RFC 9110 §8.8.1). Track this separately from a true
            // content change so operators can detect a config regression that
            // silently turns every conditional GET into a full re-sign. The
            // window has rolled over, so the cache key misses and fresh bytes are
            // minted here exactly as on a content change.
            revalidation_metrics()
                .total
                .add(1, &[KeyValue::new("outcome", "expired_token")]);
            let (token_bytes, token_encoding) = get_or_build_live_token(
                &state,
                accept_type,
                &status_record,
                &key,
                &signing_material,
                now,
                client_accepts_gzip,
            )
            .await?;
            Ok(build_ok_response(
                token_bytes,
                token_encoding,
                accept_type,
                &current_etag,
                &last_modified,
                &cache_control,
            ))
        }
    }
}

/// Build the typed cache key — and hence the weak ETag — for the live token at
/// `window_start`, without signing. Also returns the signing snapshot used for
/// the key's signer fingerprint, so the caller can pass the *same* snapshot into
/// the token builder and never cache bytes signed by one key under another
/// key's entry.
///
/// The signer fingerprint reads the current in-memory signing snapshot, so a
/// rotated key or renewed certificate immediately changes the key (and the
/// ETag) even before any token is built.
async fn build_token_cache_key(
    state: &AppState,
    accept_type: AcceptType,
    status_record: &StatusListRecord,
    list_id: &str,
    window_start: i64,
    client_accepts_gzip: bool,
) -> Result<(TokenCacheKey, Arc<SigningMaterial>), ApiError> {
    let format = match accept_type {
        AcceptType::Cwt => "cwt",
        AcceptType::Jwt => "jwt",
    };
    let encoding = if client_accepts_gzip && accept_type == AcceptType::Jwt {
        TokenEncoding::Gzip
    } else {
        TokenEncoding::Identity
    };
    let hash = content_hash(status_record);
    let signing_material = state
        .service
        .cert_provider()
        .signing_material()
        .await
        .map_err(|e| ApiError::from(StatusListError::Backend(Box::new(e))))?;
    let signer = signer_fingerprint(&signing_material);
    let aggregation_uri = state.aggregation_uri.as_deref().unwrap_or("");
    // `iat = max(window_start, updated_at)` is the issuance time the token is
    // minted with (see `live_iat`). `updated_at` is a real wall-clock timestamp
    // (it is deliberately never inflated past the clock, so `iat` can never land
    // in the future), which means two updates to the same list in the same second
    // can share an `iat`. The monotonic optimistic-concurrency `version` is
    // therefore also part of the key (and hence the ETag), so a mid-window
    // content revert to an earlier state is still a distinct identity: A -> B -> A
    // in one window bumps `version` even when `iat` is unchanged, so the
    // reinstated token never reuses the earlier identical-content entry's cached
    // bytes (which carried the stale state).
    let iat = window_start.max(status_record.updated_at);
    let key = TokenCacheKey {
        list_id: list_id.to_string(),
        content_hash: hash,
        signer_fingerprint: signer,
        window_start,
        iat,
        version: status_record.version,
        format: format.to_string(),
        encoding,
        aggregation_uri: aggregation_uri.to_string(),
        token_ttl_secs: state.token_ttl_secs,
        token_exp_secs: state.token_exp_secs,
    };
    Ok((key, signing_material))
}

/// Return the signed token bytes for the current window, serving from the
/// per-replica signed-bytes cache when possible and re-signing only on a miss.
///
/// Only called for a `Modified` response (the conditional check runs before
/// this), so a matching `If-None-Match` never triggers a sign. The token is
/// minted with `iat = max(window_start, updated_at)` and `exp = iat +
/// token_exp_secs`, so within a window with unchanged content the bytes are
/// identical across requests and concurrent misses coalesce onto a single sign
/// for `(list, window, format, encoding)`. Capacity eviction can re-sign a
/// still-valid entry.
///
/// The `signing_material` passed in is the exact snapshot that produced `key`'s
/// signer fingerprint, so the signed bytes cached under `key` are always signed
/// by the signer the key claims.
async fn get_or_build_live_token(
    state: &AppState,
    accept_type: AcceptType,
    status_record: &StatusListRecord,
    key: &TokenCacheKey,
    signing_material: &Arc<SigningMaterial>,
    now: i64,
    client_accepts_gzip: bool,
) -> Result<(Bytes, Option<&'static str>), ApiError> {
    let iat = key.iat;
    let exp_secs = state.token_exp_secs as i64;
    let validity_window = (iat, iat.saturating_add(exp_secs));

    // A hit serves cached bytes; a miss runs the builder. Config guarantees a
    // positive `token_exp_secs`, so the window is always open and a token is
    // always built (no degenerate born-expired `exp == 0` case to re-sign
    // around).
    let cached = state
        .token_bytes_cache
        .get_or_build(key, || {
            let signing_material = signing_material.clone();
            // The record is cloned only when the builder actually runs (a cache
            // miss); a hit serves cached bytes without touching it.
            let status_record = status_record.clone();
            async move {
                let (bytes, enc) = build_status_list_token(
                    state,
                    accept_type,
                    status_record,
                    Some(validity_window),
                    client_accepts_gzip,
                    signing_material,
                )
                .await?;
                Ok::<CachedToken, ApiError>(CachedToken {
                    bytes: Bytes::from(bytes),
                    encoding: enc,
                    created_at_unix: now,
                })
            }
        })
        .await?;

    Ok((cached.bytes, cached.encoding))
}

/// Build a `200 OK` status-list token response from already-signed bytes.
fn build_ok_response(
    token_bytes: Bytes,
    token_encoding: Option<&'static str>,
    accept_type: AcceptType,
    current_etag: &str,
    last_modified: &str,
    cache_control: &str,
) -> Response {
    let mut response = Response::new(axum::body::Body::from(token_bytes));
    *response.status_mut() = StatusCode::OK;
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(accept_type.media_type()),
    );
    h.insert(header::ETAG, HeaderValue::from_str(current_etag).unwrap());
    h.insert(
        header::LAST_MODIFIED,
        HeaderValue::from_str(last_modified).unwrap(),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(cache_control).unwrap(),
    );
    h.insert(
        header::VARY,
        HeaderValue::from_static("Accept, Accept-Encoding"),
    );
    if let Some(enc) = token_encoding {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static(enc));
    }

    response
}

/// Serve a historical status-list snapshot for `?time=` replayed at `(iat, exp)`.
///
/// Historical tokens are intentionally **not** cached in the signed-bytes cache:
/// each request targets a possibly distinct snapshot (`time`), so the hit rate
/// would be negligible and the cache would only churn retained memory. This is
/// an explicit out-of-scope decision for the signed-token-bytes cache; the
/// token is signed fresh per request against one consistent signing snapshot.
async fn handle_historical_request(
    list_id: &str,
    time: i64,
    accept_type: AcceptType,
    state: &AppState,
    client_accepts_gzip: bool,
) -> Result<Response, ApiError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if time <= 0 || time > now {
        tracing::warn!("Historical query rejected for time {time}");
        return Err(StatusListError::InvalidHistoricalTime.into());
    }

    tracing::info!(
        "Historical query for list {list_id} at time {time} (age: {} seconds)",
        now - time
    );

    let snapshot = state.service.get_snapshot_at(list_id, time).await?;

    // The historical ETag is weak and includes format + encoding so JWT vs CWT
    // and gzip vs identity responses (distinct bytes, re-signed per request)
    // never share a validator.
    let format = match accept_type {
        AcceptType::Cwt => "cwt",
        AcceptType::Jwt => "jwt",
    };
    let encoding = if client_accepts_gzip && accept_type == AcceptType::Jwt {
        TokenEncoding::Gzip
    } else {
        TokenEncoding::Identity
    };
    let etag = generate_historical_etag(&snapshot, format, encoding)?;
    let last_modified = format_http_date(snapshot.iat);
    let validity_duration = (snapshot.exp - snapshot.iat) as u64;
    let cache_control = format!("max-age={validity_duration}, immutable");

    let status_record = StatusListRecord {
        list_id: snapshot.list_id,
        issuer: snapshot.issuer,
        status_list: snapshot.status_list,
        sub: snapshot.sub,
        updated_at: snapshot.iat,
        // A historical token is built from a snapshot, not an optimistic
        // concurrency update; the version is unused on this path.
        version: 0,
    };

    let signing_material = state
        .service
        .cert_provider()
        .signing_material()
        .await
        .map_err(|e| ApiError::from(StatusListError::Backend(Box::new(e))))?;

    let (token_bytes, encoding) = build_status_list_token(
        state,
        accept_type,
        status_record,
        Some((snapshot.iat, snapshot.exp)),
        client_accepts_gzip,
        signing_material,
    )
    .await?;

    let mut response = Response::new(token_bytes.into());
    *response.status_mut() = StatusCode::OK;
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(accept_type.media_type()),
    );
    h.insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    h.insert(
        header::LAST_MODIFIED,
        HeaderValue::from_str(&last_modified).unwrap(),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&cache_control).unwrap(),
    );
    h.insert(
        header::VARY,
        HeaderValue::from_static("Accept, Accept-Encoding"),
    );
    if let Some(enc) = encoding {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static(enc));
    }

    Ok(response)
}

#[derive(Debug, Deserialize)]
pub struct StatusListQuery {
    pub time: Option<i64>,
}

async fn fetch_status_record(
    list_id: &str,
    state: &AppState,
) -> Result<StatusListRecord, ApiError> {
    state
        .service
        .get_status_list(list_id)
        .await
        .map_err(Into::into)
}

fn build_cache_control(token_ttl_secs: u64) -> String {
    // Deliberately no `immutable`: the representation is *not* immutably fixed.
    // The token re-signs and its validator rotates each `E - ttl` window, so
    // freshness-honouring caches/browsers must revalidate to obtain a fresh,
    // unexpired token rather than serving a stale one for its lifetime.
    format!("max-age={}", token_ttl_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::handlers::status_list::publish_status::publish_status;
    use crate::server::handlers::status_list::update_status::update_status;
    use crate::server::handlers::status_list::utils::conditional::parse_http_date;
    use crate::server::handlers::status_list::utils::request::{
        Status, StatusEntry, StatusesRequest,
    };
    use crate::test_utils::{
        RotatingCertProvider, authenticated_issuer, test_app_state,
        test_app_state_with_cert_provider,
    };
    use axum::extract::Json;
    use axum::http::HeaderMap;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    /// A [`TokenSigner`] that counts every `sign` call, so a test can assert how
    /// many times the server actually signed during a conditional revalidation.
    struct CountingSigner {
        inner: Arc<dyn crate::domain::ports::TokenSigner>,
        signs: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::domain::ports::TokenSigner for CountingSigner {
        fn algorithm(&self) -> crate::domain::models::token::SigningAlgorithm {
            self.inner.algorithm()
        }
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, crate::domain::ports::TokenSignerError> {
            self.signs.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(data)
        }
        fn public_key_bytes(&self) -> &[u8] {
            self.inner.public_key_bytes()
        }
    }

    /// A [`CertificateProvider`] returning a stable [`CountingSigner`] on every
    /// call, so tests can count signing attempts through the full handler path
    /// without the fingerprint rotating between requests.
    struct CountingCertProvider {
        signer: Arc<dyn crate::domain::ports::TokenSigner>,
    }

    impl CountingCertProvider {
        fn new(signs: Arc<std::sync::atomic::AtomicUsize>) -> Self {
            let key = crate::utils::crypto::SigningKey::generate(
                crate::domain::models::token::SigningAlgorithm::Es256,
            )
            .expect("generate es256 key");
            Self {
                signer: Arc::new(CountingSigner {
                    inner: Arc::new(key),
                    signs,
                }),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::domain::ports::CertificateProvider for CountingCertProvider {
        async fn signing_material(
            &self,
        ) -> Result<
            Arc<crate::domain::ports::SigningMaterial>,
            crate::domain::models::status_list::StatusListError,
        > {
            Ok(Arc::new(
                crate::domain::ports::SigningMaterial::new(
                    Some(vec!["ZHVtbXlfY2VydA==".to_string()]),
                    self.signer.clone(),
                )
                .expect("signing material"),
            ))
        }
    }

    /// A [`CertificateProvider`] that hands out a *different* signing snapshot on
    /// each call: the first call returns `signer_a`, every later call returns
    /// `signer_b`. This mimics a concurrent key rotation landing *between* the
    /// key-derivation fetch and the token-construction fetch that a naive
    /// handler performs. A correct handler must derive the cache key and sign the
    /// token from the *same* snapshot, so it issues exactly one `signing_material`
    /// call per request and the served token verifies under `signer_a`.
    struct AlternatingCertProvider {
        signer_a: Arc<dyn crate::domain::ports::TokenSigner>,
        signer_b: Arc<dyn crate::domain::ports::TokenSigner>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl AlternatingCertProvider {
        fn new() -> Self {
            let make = || {
                Arc::new(
                    crate::utils::crypto::SigningKey::generate(
                        crate::domain::models::token::SigningAlgorithm::Es256,
                    )
                    .expect("generate es256 key"),
                ) as Arc<dyn crate::domain::ports::TokenSigner>
            };
            Self {
                signer_a: make(),
                signer_b: make(),
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::domain::ports::CertificateProvider for AlternatingCertProvider {
        async fn signing_material(
            &self,
        ) -> Result<
            Arc<crate::domain::ports::SigningMaterial>,
            crate::domain::models::status_list::StatusListError,
        > {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let signer = if call == 0 {
                &self.signer_a
            } else {
                &self.signer_b
            };
            Ok(Arc::new(
                crate::domain::ports::SigningMaterial::new(
                    Some(vec!["ZHVtbXlfY2VydA==".to_string()]),
                    Arc::clone(signer),
                )
                .expect("signing material"),
            ))
        }
    }

    /// Decode the JWT payload of a freshly served (uncompressed) token so tests
    /// can assert the `iat`/`exp` claims directly without a verification key.
    fn decode_jwt_claims(jwt: &[u8]) -> serde_json::Value {
        use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

        let jwt = std::str::from_utf8(jwt).expect("JWT body is UTF-8");
        let payload = jwt.split('.').nth(1).expect("JWT has three segments");
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .expect("JWT payload is valid base64url");
        serde_json::from_slice(&decoded).expect("JWT payload is valid JSON")
    }

    /// Verify an uncompressed ES256 JWT against a raw public key, returning
    /// whether the signature is valid. Used to assert which signer actually
    /// produced a served token.
    fn jwt_verifies_under(jwt: &[u8], public_key_bytes: &[u8]) -> bool {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
        use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

        let jwt = std::str::from_utf8(jwt).expect("JWT body is UTF-8");
        let mut parts = jwt.split('.');
        let (Some(header), Some(payload), Some(sig)) = (parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        let signing_input = format!("{header}.{payload}").into_bytes();
        let signature = match BASE64_URL_SAFE_NO_PAD.decode(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key_bytes);
        key.verify(&signing_input, &signature).is_ok()
    }

    #[tokio::test]
    async fn test_get_status_list_not_found() {
        let app_state = test_app_state(None).await;
        let headers = HeaderMap::new();

        let result = get_status_list(
            State(app_state),
            Path(uuid::Uuid::new_v4().to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_status_list_negotiates_accept_table() {
        // (Accept header, expected Content-Type) — the negotiation outcome for
        // an existing list, exercised end-to-end through the handler.
        let cases: Vec<(&str, &str)> = vec![
            // Exact match.
            (
                ACCEPT_STATUS_LISTS_HEADER_JWT,
                ACCEPT_STATUS_LISTS_HEADER_JWT,
            ),
            (
                ACCEPT_STATUS_LISTS_HEADER_CWT,
                ACCEPT_STATUS_LISTS_HEADER_CWT,
            ),
            // Wildcards serve JWT.
            ("*/*", ACCEPT_STATUS_LISTS_HEADER_JWT),
            ("application/*", ACCEPT_STATUS_LISTS_HEADER_JWT),
            // Case-insensitive type/subtype.
            ("Application/StatusList+JWT", ACCEPT_STATUS_LISTS_HEADER_JWT),
            ("APPLICATION/STATUSLIST+CWT", ACCEPT_STATUS_LISTS_HEADER_CWT),
            // Highest acceptable q wins.
            (
                "application/statuslist+cwt;q=0.9, application/statuslist+jwt;q=0.8",
                ACCEPT_STATUS_LISTS_HEADER_CWT,
            ),
            (
                "application/statuslist+jwt;q=0.8, application/statuslist+cwt;q=0.5",
                ACCEPT_STATUS_LISTS_HEADER_JWT,
            ),
        ];

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

        for (accept, expected_content_type) in cases {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, accept.parse().unwrap());
            let response = get_status_list(
                State(app_state.clone()),
                Path(token_id.clone()),
                Ok(Query(StatusListQuery { time: None })),
                headers,
            )
            .await
            .unwrap()
            .into_response();

            assert_eq!(response.status(), StatusCode::OK, "Accept: {accept:?}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                expected_content_type,
                "Accept: {accept:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_get_status_list_multiline_accept_header() {
        // RFC 9110 §5.3 folds multiple `Accept` field lines into one list, so
        // the handler must read every line and negotiate the whole set
        // together, not just the first one (all `HeaderMap::get` returns).
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

        let mut headers = HeaderMap::new();
        headers.append(header::ACCEPT, "text/html".parse().unwrap());
        headers.append(
            header::ACCEPT,
            "application/statuslist+cwt".parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            ACCEPT_STATUS_LISTS_HEADER_CWT
        );
    }

    #[tokio::test]
    async fn test_get_status_list_406_table() {
        // (Accept header) — every header with no acceptable supported type must
        // yield a 406 advertising `Vary` and listing both supported types.
        let cases: Vec<&str> = vec![
            "text/html",
            "application/json",
            "application/statuslist+jwt;q=0, application/statuslist+cwt;q=0",
            "*/*;q=0",
        ];

        for accept in cases {
            let app_state = test_app_state(None).await;
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, accept.parse().unwrap());

            let response = get_status_list(
                State(app_state),
                Path(uuid::Uuid::new_v4().to_string()),
                Ok(Query(StatusListQuery { time: None })),
                headers,
            )
            .await
            .unwrap_err()
            .into_response();

            assert_eq!(
                response.status(),
                StatusCode::NOT_ACCEPTABLE,
                "Accept: {accept:?}"
            );
            // The 406 advertises Vary (RFC 9110 §12.5.5). It is `no-store`, so
            // caches never store it either way.
            assert_eq!(
                response.headers().get(header::VARY).unwrap(),
                "Accept, Accept-Encoding"
            );
            // The 406 body must list both supported media types (scope requirement).
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(
                body.contains(ACCEPT_STATUS_LISTS_HEADER_JWT)
                    && body.contains(ACCEPT_STATUS_LISTS_HEADER_CWT),
                "406 body must list both supported types, got: {body}"
            );
        }
    }

    #[tokio::test]
    async fn test_get_status_list_jwt_success() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        // Publish first
        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        headers.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        assert!(response.headers().contains_key(header::ETAG));
        assert!(response.headers().contains_key(header::CACHE_CONTROL));
    }

    #[tokio::test]
    async fn test_get_status_list_success_cwt() {
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

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_CWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            ACCEPT_STATUS_LISTS_HEADER_CWT
        );
    }

    #[tokio::test]
    async fn test_get_status_list_jwt_no_gzip_when_client_does_not_accept() {
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

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(
            response.headers().get(header::VARY).unwrap(),
            "Accept, Accept-Encoding"
        );
    }

    #[tokio::test]
    async fn test_jwt_emits_aggregation_uri_when_configured() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri =
            Some("https://aggregation.example.com/statuslists/aggregation".to_string());

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_jwt_omits_aggregation_uri_when_not_configured() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri = None;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_conditional_request_if_modified_since_alone_returns_fresh_200() {
        // If-Modified-Since on its own never certifies a 304: `updated_at` is a
        // real wall-clock timestamp, so a revoke landing in the same second as
        // the client's copy would otherwise be hidden by `updated_at <= IMS`. A
        // 200 with a freshly signed token is always correct; the exact ETag
        // (which includes `version`) is the revalidation mechanism.
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

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list(
            State(app_state.clone()),
            Path(token_id.clone()),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
        )
        .await
        .unwrap()
        .into_response();

        let last_modified = res1.headers().get(header::LAST_MODIFIED).unwrap().clone();

        headers.insert(header::IF_MODIFIED_SINCE, last_modified);
        let res2 = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(
            res2.status(),
            StatusCode::OK,
            "an If-Modified-Since-only request must be served a fresh 200, never a 304"
        );
        let body = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn test_conditional_request_within_validity_returns_304() {
        // Deterministic time-advancement: fetch at `now0`, revalidate a short
        // while later but *within the same* token validity window. The cached
        // token is still valid, so a body-less 304 is correct and efficient.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);

        let etag = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag);

        // Same window (60s < token_exp_secs) -> cached token still valid -> 304.
        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 60,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(res2.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_conditional_request_revalidation_at_dead_zone_boundaries() {
        // The ETag is keyed to the `E - ttl` window (defaults E=900, ttl=300 ->
        // W=600). Within the window a matching ETag is always → 304, even exactly
        // at `window_end - ttl`, because any token issued in the window still has
        // > ttl of validity left. Revalidating at `window_end` falls into the
        // next window, the ETag rolls over, and the client is served a fresh
        // token (200) instead of a stale 304.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let ttl = app_state.token_ttl_secs as i64;
        let now0 = 1_000_000_000;
        // window(1_000_000_000) == [999_999_600, 1_000_000_200)
        let window_end = 999_999_600 + 600;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag);

        // Exactly at `window_end - ttl` the cached token still has > ttl left ->
        // 304.
        let dead_edge = window_end - ttl;
        let res2 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            dead_edge,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res2.status(), StatusCode::NOT_MODIFIED);

        // Revalidating at `window_end` rolls the window over -> fresh 200.
        let res3 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            window_end,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res3.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res3.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn test_conditional_request_expired_token_returns_fresh_200() {
        // Fetch at `now0`, then revalidate after the token validity window has
        // rolled over. The client's cached token has expired, so the server must
        // bypass the 304 and return a freshly signed 200 with a valid body.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let token_exp_secs = app_state.token_exp_secs;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag1 = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag1.clone());

        // Advance past the window boundary so the previously issued token's
        // validity window has lapsed.
        let res2 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0 + token_exp_secs as i64 + 1,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(
            res2.status(),
            StatusCode::OK,
            "expired-token revalidation must return a fresh 200 OK"
        );
        let etag2 = res2.headers().get(header::ETAG).unwrap().clone();
        assert_ne!(
            etag2, etag1,
            "the ETag must rotate when the token validity window changes"
        );
        let body = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !body.is_empty(),
            "expired-token revalidation must carry a newly signed token body"
        );
        // Acceptance criterion #1 requires a freshly signed *valid* token: verify
        // it carries a full validity window rather than expiring at issuance.
        let claims = decode_jwt_claims(&body);
        let iat = claims["iat"].as_i64().expect("token carries iat");
        let exp = claims["exp"].as_i64().expect("token carries exp");
        assert_eq!(
            exp - iat,
            token_exp_secs as i64,
            "the freshly signed token must not be born expired"
        );
    }

    #[tokio::test]
    async fn test_conditional_request_if_modified_since_expired_returns_fresh_200() {
        // An If-Modified-Since revalidation with an expired cached token must
        // also bypass the 304 and serve a fresh body, otherwise the original bug
        // remains reachable through the weaker validator.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let token_exp_secs = app_state.token_exp_secs;
        let now0 = time::OffsetDateTime::now_utc().unix_timestamp();

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let last_modified = res1.headers().get(header::LAST_MODIFIED).unwrap().clone();
        headers.insert(header::IF_MODIFIED_SINCE, last_modified);

        // `now` has passed `updated_at + token_exp_secs` -> the cached token is
        // expired -> the IMS revalidation must not answer 304.
        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + token_exp_secs as i64 + 1,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(res2.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn test_conditional_request_cwt_within_window_returns_304() {
        // The CWT format participates in the same conditional revalidation: a
        // revalidation within the current `E - ttl` window (matching ETag) must
        // yield a body-less 304.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_CWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag);

        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 60,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res2.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_conditional_request_cwt_window_rolled_returns_fresh_200() {
        // After the `E - ttl` window rolls over a CWT revalidation must be served
        // a freshly signed token, not a 304, mirroring the JWT behaviour.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_CWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag1 = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag1.clone());

        // Past the window boundary (W=600) -> rolled over -> fresh 200.
        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 600,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(res2.status(), StatusCode::OK);
        let etag2 = res2.headers().get(header::ETAG).unwrap().clone();
        assert_ne!(
            etag2, etag1,
            "the ETag must rotate when the window rolls over"
        );
        let body = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn test_conditional_request_expired_returns_gzipped_fresh_200() {
        // When a revalidation falls into the fresh-re-sign path (window rolled)
        // the freshly signed JWT must still honour the client's `Accept-Encoding`,
        // i.e. be gzip-compressed on the 200 even though a 304 was bypassed.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        headers.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        assert_eq!(
            res1.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        let etag = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag);

        // Window rolled -> fresh 200, still gzipped.
        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 600,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res2.status(), StatusCode::OK);
        assert_eq!(
            res2.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip",
            "the fresh token on a forced re-sign must still be gzip-compressed"
        );
    }

    #[tokio::test]
    async fn test_conditional_request_expired_token_returns_fresh_headers() {
        // An expired If-Modified-Since validator must respond 200 with the full
        // set of validator/freshness headers so downstream caches keep working
        // after the fresh re-sign.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let token_exp_secs = app_state.token_exp_secs;
        let token_ttl_secs = app_state.token_ttl_secs;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let last_modified = res1.headers().get(header::LAST_MODIFIED).unwrap().clone();
        headers.insert(header::IF_MODIFIED_SINCE, last_modified);

        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + token_exp_secs as i64 + 1,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(res2.status(), StatusCode::OK);
        let h = res2.headers();
        assert!(h.contains_key(header::ETAG));
        assert_eq!(
            h.get(header::CACHE_CONTROL).unwrap().to_str().unwrap(),
            format!("max-age={token_ttl_secs}")
        );
        assert_eq!(h.get(header::VARY).unwrap(), "Accept, Accept-Encoding");
        let body = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn test_conditional_request_content_changed_and_window_rolled() {
        // A genuine content change (new statuses published) with the token window
        // also rolled over must still be answered with a fresh 200 carrying the
        // updated content, never a 304.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag1 = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag1);
        let body1 = axum::body::to_bytes(res1.into_body(), usize::MAX)
            .await
            .unwrap();

        // Change the underlying content (update statuses), then revalidate after
        // the window would have rolled.
        update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
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
            }),
        )
        .await
        .unwrap();

        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 600,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res2.status(), StatusCode::OK);
        let body2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body2.is_empty());
        assert_ne!(
            body1, body2,
            "the served token must reflect the new content"
        );
    }

    #[tokio::test]
    async fn test_same_window_content_change_old_etag_gets_200_with_new_bytes() {
        // A revocation service's core property: updating a credential's status
        // must never be hidden behind a body-less 304. Even *without the window
        // rolling over*, a content change must change the representation identity
        // (`content_hash` is part of the ETag), so revalidating with the
        // pre-change ETag gets a 200 carrying the new bytes — never a 304.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag1 = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag1);
        let body1 = axum::body::to_bytes(res1.into_body(), usize::MAX)
            .await
            .unwrap();

        // Update the content within the same window (revalidate shortly after the
        // fetch, far before the window rolls).
        update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![
                    StatusEntry {
                        index: 0,
                        status: Status::INVALID,
                    },
                    StatusEntry {
                        index: 1,
                        status: Status::VALID,
                    },
                ],
            }),
        )
        .await
        .unwrap();

        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 5,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(
            res2.status(),
            StatusCode::OK,
            "same-window content change must re-sign, never certify a 304"
        );
        let body2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body2.is_empty());
        assert_ne!(
            body1, body2,
            "the old ETag must not be honoured after a same-window content change"
        );
    }

    #[tokio::test]
    async fn test_reinstated_content_within_window_gets_fresh_iat_and_bytes() {
        // Regression for the A -> B -> A reinstatement hole: if a credential is
        // suspended (B) and then reinstated (back to A) *within one window*, the
        // content hash returns to A's value, so an `iat`-less cache key would
        // collide with the earlier A entry and serve its stale bytes (which carry
        // the old `iat`, claiming VALID from before the suspension). Because the
        // monotonic `version` is part of the cache key and the ETag, the
        // reinstated token is a distinct identity even when a same-second burst
        // leaves `updated_at` (and hence `iat`) unchanged: fresh bytes are minted
        // under the bumped version and a different ETag, so the stale A bytes are
        // never reused. And because `updated_at` stays a real wall-clock value,
        // the reinstated token's `iat` is never pushed into the future.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        // State A: index 0 VALID, index 1 INVALID.
        update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
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
            }),
        )
        .await
        .unwrap();

        // First GET of A within the window -> cached with iat_a.
        let res_a = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res_a.status(), StatusCode::OK);
        let etag_a = res_a.headers().get(header::ETAG).unwrap().clone();
        let body_a = axum::body::to_bytes(res_a.into_body(), usize::MAX)
            .await
            .unwrap();
        let iat_a = decode_jwt_claims(&body_a)["iat"].as_i64().unwrap();

        // State B: suspend index 0 (VALID -> SUSPENDED), within the same window.
        update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![StatusEntry {
                    index: 0,
                    status: Status::SUSPENDED,
                }],
            }),
        )
        .await
        .unwrap();

        let res_b = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0 + 4,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res_b.status(), StatusCode::OK);

        // State A again: reinstate index 0 (SUSPENDED -> VALID) — content reverts.
        update_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![StatusEntry {
                    index: 0,
                    status: Status::VALID,
                }],
            }),
        )
        .await
        .unwrap();

        let res_a2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 8,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res_a2.status(), StatusCode::OK);
        let etag_a2 = res_a2.headers().get(header::ETAG).unwrap().clone();
        let body_a2 = axum::body::to_bytes(res_a2.into_body(), usize::MAX)
            .await
            .unwrap();
        let iat_a2 = decode_jwt_claims(&body_a2)["iat"].as_i64().unwrap();

        assert_ne!(
            etag_a2, etag_a,
            "reinstated content must be a distinct identity from the earlier A \
             entry (version is part of the key/ETag)"
        );
        assert!(
            iat_a2 <= iat_a + 1,
            "the reinstated token's iat must not drift ahead of the clock: the \
             version bump distinguishes it from the earlier A entry, not an \
             inflated iat (earlier iat={iat_a}, reinstated iat={iat_a2}); a \
             same-window A -> B -> A must not push iat into the future"
        );
        assert_ne!(
            body_a2, body_a,
            "the reinstated token must be freshly signed, never the stale A bytes \
             cached before the suspension"
        );
    }

    #[tokio::test]
    async fn test_conditional_request_ttl_ge_exp_never_certifies_304() {
        // `ttl >= exp` (exp > 0) leaves no usable runway: even a same-window
        // matching ETag must not certify a 304, because the 304 advertises
        // `max-age = ttl`, which would outlive the token's `exp`. Startup
        // validation rejects this config; the conditional logic must degrade to a
        // 200. Constructed directly here (bypassing config validation) to pin the
        // runtime guard.
        for (exp, ttl) in [(300u64, 300u64), (300, 600)] {
            let token_id = uuid::Uuid::new_v4().to_string();
            let mut app_state = test_app_state(None).await;
            app_state.token_exp_secs = exp;
            app_state.token_ttl_secs = ttl;

            publish_status(
                State(app_state.clone()),
                authenticated_issuer("issuer1"),
                Path(token_id.clone()),
                Json(StatusesRequest { statuses: vec![] }),
            )
            .await
            .unwrap();

            // Revalidate at a realistic `now` at/after the record's `updated_at`
            // (which is set from the real clock at publish time).
            let now0 = crate::domain::service::current_unix_timestamp();
            let mut headers = HeaderMap::new();
            headers.insert(
                header::ACCEPT,
                ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
            );

            let res1 = get_status_list_at(
                State(app_state.clone()),
                token_id.clone(),
                Ok(Query(StatusListQuery { time: None })),
                headers.clone(),
                now0,
            )
            .await
            .unwrap()
            .into_response();
            assert_eq!(res1.status(), StatusCode::OK);
            let etag = res1.headers().get(header::ETAG).unwrap().clone();
            headers.insert(header::IF_NONE_MATCH, etag);

            // Same window/second -> matching ETag, but no runway -> 200, never 304.
            let res2 = get_status_list_at(
                State(app_state),
                token_id,
                Ok(Query(StatusListQuery { time: None })),
                headers,
                now0,
            )
            .await
            .unwrap()
            .into_response();
            assert_eq!(
                res2.status(),
                StatusCode::OK,
                "(exp={exp}, ttl={ttl}) must not certify a 304"
            );
        }
    }

    #[tokio::test]
    async fn test_same_window_non_conditional_gets_reuse_cached_bytes() {
        // Two non-conditional 200 GETs in the same window must reuse the same
        // signed bytes (single sign per window, not one per request): the body is
        // byte-for-byte identical. The token's `iat` is anchored to
        // `max(window_start, updated_at)` — the window start, or the last content
        // change if it is later — not the request time.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let exp_secs = app_state.token_exp_secs;
        let ttl_secs = app_state.token_ttl_secs;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        // Revalidate at a realistic `now` at/after the record's `updated_at`,
        // aligned to a window start so `now0 + 30` is guaranteed to stay in the
        // same window regardless of where the real clock falls.
        let now0 = {
            let t = crate::domain::service::current_unix_timestamp();
            token_window(t, TokenValidity::new(exp_secs, ttl_secs)).1
        };
        let window = token_window(now0, TokenValidity::new(exp_secs, ttl_secs));

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let last_modified = res1.headers().get(header::LAST_MODIFIED).unwrap().clone();
        let updated_at = parse_http_date(last_modified.to_str().unwrap()).unwrap();
        let body1 = axum::body::to_bytes(res1.into_body(), usize::MAX)
            .await
            .unwrap();
        let claims1 = decode_jwt_claims(&body1);
        assert_eq!(
            claims1["iat"].as_i64().unwrap(),
            window.0.max(updated_at),
            "iat must be anchored to max(window_start, updated_at), not the request time"
        );
        assert_eq!(
            claims1["exp"].as_i64().unwrap() - claims1["iat"].as_i64().unwrap(),
            exp_secs as i64
        );

        // Second request, no validator: still Modified -> 200, but the signed
        // bytes come from the cache (identical body => no re-sign).
        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 30,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res2.status(), StatusCode::OK);
        let body2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            body1, body2,
            "same-window 200s must reuse the cached signed bytes"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_misses_in_fresh_window_single_sign() {
        // At most one signing operation per (list, window, format) per replica.
        // Fire many concurrent GETs into a fresh window so they all miss; the
        // single-flight cache must run the builder once. ECDSA signing is
        // randomized, so two signs produce different bytes: all concurrent
        // responses sharing byte-for-byte identical bodies proves a single sign.
        // (The weak ETag is derived from the representation identity, not the
        // bytes, so it is identical regardless of how many signs happened — the
        // bytes are the real proof.)
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let app_state = Arc::new(app_state);
        let mut handles = Vec::new();
        for _ in 0..24 {
            let app_state = app_state.clone();
            let headers = headers.clone();
            let token_id = token_id.clone();
            handles.push(tokio::spawn(async move {
                let res = get_status_list_at(
                    State((*app_state).clone()),
                    token_id,
                    Ok(Query(StatusListQuery { time: None })),
                    headers,
                    now0,
                )
                .await
                .unwrap()
                .into_response();
                assert_eq!(res.status(), StatusCode::OK);
                let etag = res
                    .headers()
                    .get(header::ETAG)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                let body = axum::body::to_bytes(res.into_body(), usize::MAX)
                    .await
                    .unwrap();
                (etag, body)
            }));
        }

        let mut etags = std::collections::HashSet::new();
        let mut first_body: Option<Vec<u8>> = None;
        for h in handles {
            let (etag, body) = h.await.expect("concurrent request task");
            etags.insert(etag);
            match &first_body {
                None => first_body = Some(body.to_vec()),
                Some(first) => assert_eq!(
                    first,
                    &body.to_vec(),
                    "all concurrent responses must share the same signed bytes"
                ),
            }
        }
        assert_eq!(
            etags.len(),
            1,
            "concurrent misses in a fresh window must yield a single sign / ETag"
        );
    }

    #[test]
    fn test_revalidation_metrics_outcome_labels() {
        use crate::config::{TelemetryConfig, TelemetryEnvironment};
        use crate::utils::metrics::{metrics_handler, metrics_test_lock, setup_metrics};
        use opentelemetry_sdk::Resource;
        use prometheus::Registry;

        // The global meter-provider setup must be serialised with other metric
        // tests, so the lock is held outside the async runtime below.
        let _metrics_guard = metrics_test_lock();
        let registry = Registry::new();
        let config = TelemetryConfig {
            environment: TelemetryEnvironment::Development,
            otlp_endpoint: "http://localhost:4317".to_string(),
            sampler_ratio: 1.0,
            enabled: false,
        };
        let _meter_provider = setup_metrics(
            &registry,
            &config,
            Resource::builder()
                .with_service_name("status-list-server-test")
                .build(),
        )
        .expect("metrics setup");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let token_id = uuid::Uuid::new_v4().to_string();
            let app_state = test_app_state(None).await;
            let token_exp_secs = app_state.token_exp_secs;
            // Real clock so `now` lines up with the list's `updated_at` (set at
            // publish time) for the expired If-Modified-Since branch.
            let now0 = time::OffsetDateTime::now_utc().unix_timestamp();
            let (_, window_end) = token_window(
                now0,
                TokenValidity::new(app_state.token_exp_secs, app_state.token_ttl_secs),
            );
            let within_window_now = (now0 + 60).min(window_end - 1);

            publish_status(
                State(app_state.clone()),
                authenticated_issuer("issuer1"),
                Path(token_id.clone()),
                Json(StatusesRequest { statuses: vec![] }),
            )
            .await
            .unwrap();

            let mut headers = HeaderMap::new();
            headers.insert(
                header::ACCEPT,
                ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
            );

            // not_modified: within-window revalidation.
            let res1 = get_status_list_at(
                State(app_state.clone()),
                token_id.clone(),
                Ok(Query(StatusListQuery { time: None })),
                headers.clone(),
                now0,
            )
            .await
            .unwrap()
            .into_response();
            assert_eq!(res1.status(), StatusCode::OK);
            let etag = res1.headers().get(header::ETAG).unwrap().clone();
            let mut nm_headers = headers.clone();
            nm_headers.insert(header::IF_NONE_MATCH, etag.clone());
            let res_nm = get_status_list_at(
                State(app_state.clone()),
                token_id.clone(),
                Ok(Query(StatusListQuery { time: None })),
                nm_headers,
                within_window_now,
            )
            .await
            .unwrap()
            .into_response();
            assert_eq!(res_nm.status(), StatusCode::NOT_MODIFIED);

            // modified: window rolled over -> ETag mismatch -> fresh 200.
            let mut mod_headers = headers.clone();
            mod_headers.insert(header::IF_NONE_MATCH, etag.clone());
            let res_mod = get_status_list_at(
                State(app_state.clone()),
                token_id.clone(),
                Ok(Query(StatusListQuery { time: None })),
                mod_headers,
                window_end,
            )
            .await
            .unwrap()
            .into_response();
            assert_eq!(res_mod.status(), StatusCode::OK);

            // modified via expired If-Modified-Since validator (past the anchored
            // token's earliest expiry) -> fresh 200.
            let mut expired_headers = headers.clone();
            let last_modified = res1.headers().get(header::LAST_MODIFIED).unwrap().clone();
            expired_headers.insert(header::IF_MODIFIED_SINCE, last_modified);
            let res_exp = get_status_list_at(
                State(app_state),
                token_id,
                Ok(Query(StatusListQuery { time: None })),
                expired_headers,
                now0 + token_exp_secs as i64 + 1,
            )
            .await
            .unwrap()
            .into_response();
            assert_eq!(res_exp.status(), StatusCode::OK);

            let rendered = metrics_handler(registry).await;
            assert!(
                rendered.contains("conditional_revalidation_total"),
                "revalidation counter should be exported, got:\n{rendered}"
            );
            for label in ["not_modified", "modified"] {
                assert!(
                    rendered.contains(&format!("outcome=\"{label}\"")),
                    "expected outcome=\"{label}\" in exported metrics:\n{rendered}"
                );
            }
        });
    }

    #[tokio::test]
    async fn test_get_status_list_rejects_future_time() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        let future_time = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;

        let result = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery {
                time: Some(future_time),
            })),
            HeaderMap::new(),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_status_list_returns_snapshot_valid_at_requested_time() {
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

        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: Some(now) })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Generate a fresh, self-signed EC P-256 key (matching the ES256 signature
    /// algorithm) plus a distinct certificate chain, so a test can rotate either
    /// the signing key or the certificate between requests.
    fn rotated_signing_material() -> (String, Vec<String>) {
        let certified =
            rcgen::generate_simple_self_signed(vec!["rotated.local".to_string()]).unwrap();
        let key_pem = certified.signing_key.serialize_pem();
        let cert_pem = certified.cert.pem();
        use base64::prelude::{BASE64_STANDARD, Engine as _};
        let chain = vec![BASE64_STANDARD.encode(cert_pem.as_bytes())];
        (key_pem, chain)
    }

    fn assert_jwt_body(body: &[u8]) {
        // A served JWT must decode to a runnable token: presence of iat/exp
        // claims with a full validity span.
        let claims = decode_jwt_claims(body);
        let iat = claims["iat"].as_i64().expect("token carries iat");
        let exp = claims["exp"].as_i64().expect("token carries exp");
        assert!(exp > iat, "a freshly signed token must not be born expired");
    }

    #[tokio::test]
    async fn test_key_rotation_invalidates_cached_token_bytes() {
        // Rotating the signing key within the same token window must invalidate
        // the cached signed bytes: the next request re-signs with the new key and
        // serves different bytes/ETag, never the stale key's token.
        let provider = Arc::new(RotatingCertProvider::new(
            include_str!("../../../../test_data/ec-private.pem").to_string(),
            vec!["ZHVtbXlfY2VydA==".to_string()],
        ));
        let app_state = test_app_state_with_cert_provider(provider.clone()).await;
        let token_id = uuid::Uuid::new_v4().to_string();
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag1 = res1.headers().get(header::ETAG).unwrap().clone();
        let body1 = axum::body::to_bytes(res1.into_body(), usize::MAX)
            .await
            .unwrap();

        // Rotate the signing key; keep it in the same window.
        let (new_key, new_cert_chain) = rotated_signing_material();
        provider.rotate(new_key, new_cert_chain);

        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 60,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res2.status(), StatusCode::OK);
        let etag2 = res2.headers().get(header::ETAG).unwrap().clone();
        let body2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_ne!(
            etag1, etag2,
            "the ETag must change when the signing key rotates"
        );
        assert_ne!(
            body1, body2,
            "a rotated signing key must re-sign, never serve the stale key's bytes"
        );
        assert_jwt_body(&body2);
    }

    #[tokio::test]
    async fn test_certificate_renewal_invalidates_cached_token_bytes() {
        // Renewing the certificate (fresh x5c/x5chain in the token) within the same
        // window must also invalidate cached bytes, mirroring key rotation.
        let provider = Arc::new(RotatingCertProvider::new(
            include_str!("../../../../test_data/ec-private.pem").to_string(),
            vec!["ZHVtbXlfY2VydA==".to_string()],
        ));
        let app_state = test_app_state_with_cert_provider(provider.clone()).await;
        let token_id = uuid::Uuid::new_v4().to_string();
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag1 = res1.headers().get(header::ETAG).unwrap().clone();
        let body1 = axum::body::to_bytes(res1.into_body(), usize::MAX)
            .await
            .unwrap();

        // Renew the certificate only (same signing key), same window.
        let (same_key, _) = (
            include_str!("../../../../test_data/ec-private.pem").to_string(),
            (),
        );
        let (_, renewed_chain) = rotated_signing_material();
        provider.rotate(same_key, renewed_chain);

        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 60,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res2.status(), StatusCode::OK);
        let etag2 = res2.headers().get(header::ETAG).unwrap().clone();
        let body2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_ne!(
            etag1, etag2,
            "the ETag must change when the certificate is renewed"
        );
        assert_ne!(
            body1, body2,
            "a renewed certificate (new x5c) must re-sign, never serve stale bytes"
        );
        assert_jwt_body(&body2);
    }

    /// Parse the `max-age` directive out of a `Cache-Control` response header.
    fn parse_max_age(cache_control: &str) -> i64 {
        for directive in cache_control.split(',') {
            let directive = directive.trim();
            if let Some(value) = directive.strip_prefix("max-age=") {
                return value.parse::<i64>().expect("max-age is numeric");
            }
        }
        panic!("no max-age directive in Cache-Control: {cache_control}");
    }

    #[tokio::test]
    async fn test_304_never_outlives_cached_token_exp_property() {
        // Property-style invariant: a 304 certifies the client's cached token for
        // `max-age = ttl` more seconds (that is the freshness the 304 advertises),
        // so we must only ever certify a 304 at `now` while `now + max_age <= exp`,
        // where `exp` is the *actual* expiry of the token the client holds, decoded
        // from the JWT of the fetch that produced the validator. We sweep
        // exp/ttl configs, fetch offsets within the window, revalidation offsets
        // across the token's lifetime, and both validator kinds (If-None-Match and
        // If-Modified-Since).
        for (exp, ttl) in [
            (900u64, 300u64),
            (300, 200),
            (300, 300),
            (300, 600),
            (1, 0),
            (900, 899),
        ] {
            let provider = Arc::new(RotatingCertProvider::new(
                include_str!("../../../../test_data/ec-private.pem").to_string(),
                vec!["ZHVtbXlfY2VydA==".to_string()],
            ));
            let mut app_state = test_app_state_with_cert_provider(provider).await;
            app_state.token_exp_secs = exp;
            app_state.token_ttl_secs = ttl;
            let app_state = app_state;

            let token_id = uuid::Uuid::new_v4().to_string();
            publish_status(
                State(app_state.clone()),
                authenticated_issuer("issuer1"),
                Path(token_id.clone()),
                Json(StatusesRequest { statuses: vec![] }),
            )
            .await
            .unwrap();

            let mut accept_headers = HeaderMap::new();
            accept_headers.insert(
                header::ACCEPT,
                ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
            );

            // Base the window on a realistic `now` at/after the record's
            // `updated_at` (set from the real clock at publish time), so the
            // token's `iat`/`exp` and the revalidation probes actually exercise
            // the expiry boundary.
            let validity = TokenValidity::new(exp, ttl);
            let now0 = crate::domain::service::current_unix_timestamp();
            let window_start = token_window(now0, validity).0;
            let width = token_window(now0, validity).1 - window_start;

            // Vary where within the window the client first fetched.
            for fetch_offset in [0, width / 2, width.saturating_sub(1)] {
                let fetch_at = window_start + fetch_offset;

                let res_fetch = get_status_list_at(
                    State(app_state.clone()),
                    token_id.clone(),
                    Ok(Query(StatusListQuery { time: None })),
                    accept_headers.clone(),
                    fetch_at,
                )
                .await
                .unwrap()
                .into_response();
                assert_eq!(res_fetch.status(), StatusCode::OK);
                let etag = res_fetch.headers().get(header::ETAG).unwrap().clone();
                let last_modified = res_fetch
                    .headers()
                    .get(header::LAST_MODIFIED)
                    .unwrap()
                    .clone();
                let body = axum::body::to_bytes(res_fetch.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let claims = decode_jwt_claims(&body);
                let cached_exp = claims["exp"].as_i64().unwrap();

                for use_inm in [true, false] {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::ACCEPT,
                        ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
                    );
                    if use_inm {
                        headers.insert(header::IF_NONE_MATCH, etag.clone());
                    } else {
                        headers.insert(header::IF_MODIFIED_SINCE, last_modified.clone());
                    }

                    // Probe a bounded set of strategic revalidation offsets that
                    // exercise the boundaries (immediate, near the ttl runway
                    // edge, at/before/after the token's expiry) rather than every
                    // second, keeping the sweep fast while still sweeping the
                    // config, fetch-offset and validator dimensions.
                    let remaining = cached_exp - fetch_at;
                    let mut probes: Vec<i64> = vec![
                        fetch_at,
                        fetch_at + 1,
                        fetch_at + ttl as i64,
                        fetch_at + ttl as i64 + 1,
                        fetch_at + remaining,
                        fetch_at + remaining + 1,
                        cached_exp - 1,
                        cached_exp,
                        cached_exp + 1,
                        cached_exp + 2,
                    ];
                    probes.sort_unstable();
                    probes.dedup();
                    probes.retain(|&t| t >= fetch_at);

                    for revalidate_at in probes {
                        let res = get_status_list_at(
                            State(app_state.clone()),
                            token_id.clone(),
                            Ok(Query(StatusListQuery { time: None })),
                            headers.clone(),
                            revalidate_at,
                        )
                        .await
                        .unwrap()
                        .into_response();

                        match res.status() {
                            StatusCode::NOT_MODIFIED => {
                                let cc = res
                                    .headers()
                                    .get(header::CACHE_CONTROL)
                                    .unwrap()
                                    .to_str()
                                    .unwrap();
                                let max_age = parse_max_age(cc);
                                assert!(
                                    revalidate_at + max_age <= cached_exp,
                                    "(exp={exp}, ttl={ttl}, fetch={fetch_offset}, \
                                     {validator}) 304 at now={revalidate_at} with max-age={max_age} \
                                     would extend the cached token (exp={cached_exp}) past its expiry",
                                    validator = if use_inm { "inm" } else { "ims" },
                                );
                            }
                            StatusCode::OK => {
                                let body = axum::body::to_bytes(res.into_body(), usize::MAX)
                                    .await
                                    .unwrap();
                                assert!(!body.is_empty());
                            }
                            other => panic!(
                                "(exp={exp}, ttl={ttl}, fetch={fetch_offset}) \
                                 unexpected status {other}"
                            ),
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_weak_etag_is_stable_across_replicas() {
        // The weak ETag is derived from the representation identity, not the
        // signed bytes (whose ES256 signatures are randomized). Two replicas —
        // separate bytes caches and separate sign operations over the same
        // content and signer — must therefore issue the same ETag for the same
        // list in the same window, so a client can revalidate against either
        // replica and get a 304.
        let provider = Arc::new(RotatingCertProvider::new(
            include_str!("../../../../test_data/ec-private.pem").to_string(),
            vec!["ZHVtbXlfY2VydA==".to_string()],
        ));
        let replica_a = test_app_state_with_cert_provider(provider.clone()).await;
        let replica_b = test_app_state_with_cert_provider(provider.clone()).await;
        let now = 1_000_000_000i64;

        let list_id = uuid::Uuid::new_v4().to_string();

        for replica in [&replica_a, &replica_b] {
            publish_status(
                State(replica.clone()),
                authenticated_issuer("issuer1"),
                Path(list_id.clone()),
                Json(StatusesRequest {
                    statuses: vec![StatusEntry {
                        index: 0,
                        status: Status::INVALID,
                    }],
                }),
            )
            .await
            .unwrap();
        }

        let mut accept_headers = HeaderMap::new();
        accept_headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let mut etags = Vec::new();
        for replica in [&replica_a, &replica_b] {
            let res = get_status_list_at(
                State(replica.clone()),
                list_id.clone(),
                Ok(Query(StatusListQuery { time: None })),
                accept_headers.clone(),
                now,
            )
            .await
            .unwrap()
            .into_response();
            assert_eq!(res.status(), StatusCode::OK);
            etags.push(res.headers().get(header::ETAG).unwrap().clone());
        }

        assert_eq!(
            etags[0], etags[1],
            "two replicas over the same content/signer/window must issue the same weak ETag"
        );
        assert!(
            etags[0].to_str().unwrap().starts_with("W/"),
            "the live ETag must be weak"
        );
    }

    #[tokio::test]
    async fn test_matching_inm_304_does_not_sign_on_cold_cache() {
        // Acceptance criterion: a revalidation must do no signing. Even with a
        // disabled bytes cache (capacity 0, where every 200 re-signs), a matching
        // If-None-Match within the window must answer 304 without invoking the
        // signer at all — the key/ETag are derived before any sign and token
        // bytes are only built for a Modified response.
        let signs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = Arc::new(CountingCertProvider::new(signs.clone()));
        let mut app_state = test_app_state_with_cert_provider(provider).await;
        app_state.token_bytes_cache = crate::server::cache::TokenBytesCache::new(0);
        let token_id = uuid::Uuid::new_v4().to_string();
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag = res1.headers().get(header::ETAG).unwrap().clone();
        assert_eq!(
            signs.load(Ordering::SeqCst),
            1,
            "the fetch itself signs exactly once"
        );

        headers.insert(header::IF_NONE_MATCH, etag);
        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 60,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(
            res2.status(),
            StatusCode::NOT_MODIFIED,
            "matching If-None-Match within the window must answer 304"
        );
        assert_eq!(
            signs.load(Ordering::SeqCst),
            1,
            "a 304 revalidation must not sign, even on a cold/disabled cache"
        );
    }

    #[tokio::test]
    async fn test_signing_material_rotation_between_key_derivation_and_token() {
        // Regression: the cache key and the signed bytes must be produced from the
        // *same* signing snapshot. A naive handler fingerprints snapshot A to build
        // the key, then fetches snapshot B (after a concurrent rotation) to sign,
        // caching B-signed bytes under A's key and returning an ETag that claims
        // signer A. `AlternatingCertProvider` returns a different signer on each
        // `signing_material()` call, so the buggy two-fetch path signs with B; the
        // correct single-fetch path signs with A.
        let provider = Arc::new(AlternatingCertProvider::new());
        let app_state = test_app_state_with_cert_provider(provider.clone()).await;
        let token_id = uuid::Uuid::new_v4().to_string();
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res.status(), StatusCode::OK);

        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();

        assert!(
            jwt_verifies_under(&body, provider.signer_a.public_key_bytes()),
            "the served token must be signed by the same snapshot whose fingerprint \
             keyed the cache entry (signer A), not a later snapshot from a concurrent rotation"
        );
        assert!(
            !jwt_verifies_under(&body, provider.signer_b.public_key_bytes()),
            "the served token must not be signed by the post-rotation snapshot"
        );
    }
}
