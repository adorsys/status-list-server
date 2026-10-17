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
    etag::{content_hash, generate_historical_etag},
    negotiation::{AcceptType, client_accepts_gzip, negotiate_accept},
    token::{build_status_list_token, issuer_aggregation_uri},
    token_cache::signer_fingerprint,
};
use crate::server::cache::{CachedToken, TokenCacheKey, TokenEncoding};

/// Built lazily: a meter taken before `setup_metrics` runs is a silent no-op.
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

/// Takes `now` as a parameter so tests can control the clock.
async fn get_status_list_at(
    State(state): State<AppState>,
    list_id: String,
    query_result: Result<Query<StatusListQuery>, QueryRejection>,
    headers: HeaderMap,
    now: i64,
) -> Result<impl IntoResponse + Debug + use<>, ApiError> {
    // Legacy lists have non-UUID IDs, so only reject NUL, which Postgres can't store.
    if list_id.contains('\0') {
        return Err(ApiError::bad_request(
            "invalid_list_id",
            "list_id must not contain NUL",
        ));
    }

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

    // Multiple Accept headers form one list (RFC 9110 §5.3).
    let accept_fields: Vec<&str> = headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let accept_type = match negotiate_accept(accept_fields) {
        Some(ty) => ty,
        None => {
            // Vary is only an RFC SHOULD here; the 406 is no-store anyway.
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

    let status_record = fetch_status_record(&list_id, &state).await?;
    let aggregation_uri = issuer_aggregation_uri(&state, &status_record.issuer).await;

    // Pin `iat` to the window start so the bytes, and the ETag, stay stable for the whole window.
    let validity = TokenValidity::new(state.token_exp_secs, state.token_ttl_secs);
    let window_start = token_window(now, validity).0;
    let iat = window_start;
    let exp = crate::domain::service::token_expiry(iat, state.token_exp_secs)?;
    let validity_window = (iat, exp);

    // Sign with the key's own snapshot, or a rotation could cache bytes under the wrong signer.
    let (key, signing_material) = build_token_cache_key(
        &state,
        accept_type,
        &status_record,
        &list_id,
        window_start,
        aggregation_uri.clone(),
    )
    .await?;

    // A 304 needs the cached bytes, since the strong ETag is a digest of them.
    let cached = get_or_build_live_token(
        &state,
        accept_type,
        &status_record,
        &key,
        &signing_material,
        &validity_window,
        now,
    )
    .await?;
    state
        .token_bytes_cache
        .invalidate_superseded(&list_id, key.version, now)
        .await;

    let (served_bytes, served_encoding, current_etag) =
        if client_accepts_gzip && accept_type == AcceptType::Jwt {
            let gzip_bytes = cached
                .gzip_bytes
                .as_ref()
                .expect("gzip bytes must be present for JWT")
                .clone();
            let gzip_etag = cached
                .gzip_etag
                .as_ref()
                .expect("gzip ETag must be present for JWT")
                .clone();
            (
                gzip_bytes,
                Some(crate::server::handlers::status_list::utils::constants::GZIP_HEADER),
                gzip_etag,
            )
        } else {
            (cached.bytes.clone(), None, cached.identity_etag.clone())
        };

    // Never certify a 304 for a token that has already expired.
    let now_after = now;
    let exp_after = if now_after >= exp {
        let window_start_after = token_window(now_after, validity).0;
        let iat_after = window_start_after;
        crate::domain::service::token_expiry(iat_after, state.token_exp_secs)?
    } else {
        exp
    };

    let last_modified_ts = status_record.updated_at;
    let last_modified = format_http_date(last_modified_ts);
    let cache_control = build_cache_control(state.token_ttl_secs, exp_after, now_after);

    let (final_etag, final_bytes, final_encoding, _final_exp) = if now_after >= exp {
        let validity = TokenValidity::new(state.token_exp_secs, state.token_ttl_secs);
        let window_start = token_window(now_after, validity).0;
        let iat = window_start;
        let new_exp = crate::domain::service::token_expiry(iat, state.token_exp_secs)?;
        let validity_window = (iat, new_exp);

        let (key, signing_material) = build_token_cache_key(
            &state,
            accept_type,
            &status_record,
            &list_id,
            window_start,
            aggregation_uri,
        )
        .await?;
        let cached = get_or_build_live_token(
            &state,
            accept_type,
            &status_record,
            &key,
            &signing_material,
            &validity_window,
            now_after,
        )
        .await?;
        state
            .token_bytes_cache
            .invalidate_superseded(&list_id, key.version, now_after)
            .await;

        let (served_bytes, served_encoding, current_etag) =
            if client_accepts_gzip && accept_type == AcceptType::Jwt {
                let gzip_bytes = cached
                    .gzip_bytes
                    .as_ref()
                    .expect("gzip bytes must be present for JWT")
                    .clone();
                let gzip_etag = cached
                    .gzip_etag
                    .as_ref()
                    .expect("gzip ETag must be present for JWT")
                    .clone();
                (
                    gzip_bytes,
                    Some(crate::server::handlers::status_list::utils::constants::GZIP_HEADER),
                    gzip_etag,
                )
            } else {
                (cached.bytes.clone(), None, cached.identity_etag.clone())
            };
        (current_etag, served_bytes, served_encoding, new_exp)
    } else {
        (current_etag, served_bytes, served_encoding, exp)
    };

    match evaluate_conditional_request(if_none_match, &final_etag) {
        ConditionalResponse::NotModified => {
            revalidation_metrics()
                .total
                .add(1, &[KeyValue::new("outcome", "not_modified")]);
            Ok((
                StatusCode::NOT_MODIFIED,
                [
                    (header::ETAG, final_etag.as_str()),
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
            Ok(build_ok_response(
                final_bytes,
                final_encoding,
                accept_type,
                &final_etag,
                &last_modified,
                &cache_control,
            ))
        }
    }
}

/// Returns the signing snapshot too; sign with that one so the bytes match the key's signer.
async fn build_token_cache_key(
    state: &AppState,
    accept_type: AcceptType,
    status_record: &StatusListRecord,
    list_id: &str,
    window_start: i64,
    aggregation_uri: Option<String>,
) -> Result<(TokenCacheKey, Arc<SigningMaterial>), ApiError> {
    let format = match accept_type {
        AcceptType::Cwt => "cwt",
        AcceptType::Jwt => "jwt",
    };
    let hash = content_hash(status_record);
    let signing_material = state
        .service
        .cert_provider()
        .signing_material()
        .await
        .map_err(|e| ApiError::from(StatusListError::Backend(Box::new(e))))?;
    let signer = signer_fingerprint(&signing_material);
    let key = TokenCacheKey {
        list_id: list_id.to_string(),
        content_hash: hash,
        signer_fingerprint: signer,
        window_start,
        version: status_record.version,
        format: format.to_string(),
        aggregation_uri,
        token_exp_secs: state.token_exp_secs,
    };
    Ok((key, signing_material))
}

async fn get_or_build_live_token(
    state: &AppState,
    accept_type: AcceptType,
    status_record: &StatusListRecord,
    key: &TokenCacheKey,
    signing_material: &Arc<SigningMaterial>,
    validity_window: &(i64, i64),
    now: i64,
) -> Result<CachedToken, ApiError> {
    state
        .token_bytes_cache
        .get_or_build(
            key,
            || {
                let signing_material = signing_material.clone();
                let status_record = status_record.clone();
                async move {
                    let (bytes, _enc) = build_status_list_token(
                        state,
                        accept_type,
                        status_record,
                        key.aggregation_uri.clone(),
                        Some(*validity_window),
                        false,
                        signing_material,
                    )
                    .await?;
                    let format = match accept_type {
                        AcceptType::Cwt => "cwt",
                        AcceptType::Jwt => "jwt",
                    };
                    Ok::<CachedToken, ApiError>(CachedToken::new(Bytes::from(bytes), format, now))
                }
            },
            now,
        )
        .await
}

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

/// Not cached: each `?time=` hits a different snapshot, so the hit rate would be near zero.
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

    // Format and encoding go into the ETag so JWT/CWT and gzip/identity never share one.
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
        // Unused for historical tokens.
        version: 0,
    };

    let signing_material = state
        .service
        .cert_provider()
        .signing_material()
        .await
        .map_err(|e| ApiError::from(StatusListError::Backend(Box::new(e))))?;

    let aggregation_uri = issuer_aggregation_uri(state, &status_record.issuer).await;
    let (token_bytes, encoding) = build_status_list_token(
        state,
        accept_type,
        status_record,
        aggregation_uri,
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

fn build_cache_control(token_ttl_secs: u64, exp: i64, now: i64) -> String {
    // No `immutable`: the token re-signs every window.
    // Cap max-age at the remaining lifetime so a 304 never outlives `exp`.
    let remaining = exp.saturating_sub(now).max(0) as u64;
    let max_age = token_ttl_secs.min(remaining);
    format!("max-age={max_age}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::{AggregationId, Credential, CredentialError, Issuer};
    use crate::domain::ports::CredentialRepo;
    use crate::server::handlers::status_list::publish_status::publish_status;
    use crate::server::handlers::status_list::update_status::update_status;
    use crate::server::handlers::status_list::utils::request::{
        Status, StatusEntry, StatusesRequest,
    };
    use crate::test_utils::{
        RotatingCertProvider, authenticated_issuer, metrics_after, publish_list, register_issuer,
        test_app_state, test_app_state_with_cert_provider,
    };
    use axum::extract::Json;
    use axum::http::HeaderMap;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

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

    fn decode_jwt_claims(jwt: &[u8]) -> serde_json::Value {
        use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

        let jwt = std::str::from_utf8(jwt).expect("JWT body is UTF-8");
        let payload = jwt.split('.').nth(1).expect("JWT has three segments");
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .expect("JWT payload is valid base64url");
        serde_json::from_slice(&decoded).expect("JWT payload is valid JSON")
    }

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
    async fn test_get_status_list_rejects_nul_in_list_id() {
        let app_state = test_app_state(None).await;
        let past = time::OffsetDateTime::now_utc().unix_timestamp() - 60;

        for time in [None, Some(past)] {
            let err = get_status_list(
                State(app_state.clone()),
                Path("477121aa-b598\0-419e-916f-1e74654ff38b".to_string()),
                Ok(Query(StatusListQuery { time })),
                HeaderMap::new(),
            )
            .await
            .unwrap_err();

            assert_eq!(err.status, StatusCode::BAD_REQUEST, "time={time:?}");
            assert_eq!(err.error, "invalid_list_id", "time={time:?}");
        }
    }

    #[tokio::test]
    async fn test_get_status_list_resolves_legacy_non_uuid_list_id() {
        let app_state = test_app_state(None).await;
        publish_list(&app_state.service, "issuer1", "legacy-list").await;

        let response = get_status_list(
            State(app_state),
            Path("legacy-list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            HeaderMap::new(),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_status_list_negotiates_accept_table() {
        let cases: Vec<(&str, &str)> = vec![
            (
                ACCEPT_STATUS_LISTS_HEADER_JWT,
                ACCEPT_STATUS_LISTS_HEADER_JWT,
            ),
            (
                ACCEPT_STATUS_LISTS_HEADER_CWT,
                ACCEPT_STATUS_LISTS_HEADER_CWT,
            ),
            ("*/*", ACCEPT_STATUS_LISTS_HEADER_JWT),
            ("application/*", ACCEPT_STATUS_LISTS_HEADER_JWT),
            ("Application/StatusList+JWT", ACCEPT_STATUS_LISTS_HEADER_JWT),
            ("APPLICATION/STATUSLIST+CWT", ACCEPT_STATUS_LISTS_HEADER_CWT),
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
            assert_eq!(
                response.headers().get(header::VARY).unwrap(),
                "Accept, Accept-Encoding"
            );
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

    const AGGREGATION_BASE: &str = "https://statuslist.example.com/api/v1/aggregation";

    async fn served_aggregation_uri(app_state: AppState, accept: &str) -> Option<String> {
        let token_id = uuid::Uuid::new_v4().to_string();
        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, accept.parse().unwrap());
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        if accept == ACCEPT_STATUS_LISTS_HEADER_CWT {
            cwt_aggregation_uri(&body)
        } else {
            decode_jwt_claims(&body)["status_list"]["aggregation_uri"]
                .as_str()
                .map(str::to_string)
        }
    }

    fn cwt_aggregation_uri(cwt: &[u8]) -> Option<String> {
        use crate::server::handlers::status_list::utils::constants::STATUS_LIST;
        use coset::{TaggedCborSerializable as _, cbor::Value};

        let payload = coset::CoseSign1::from_tagged_slice(cwt)
            .unwrap()
            .payload
            .unwrap();
        let claims: Value = coset::cbor::de::from_reader(payload.as_slice()).unwrap();
        let status_list = claims
            .as_map()
            .unwrap()
            .iter()
            .find(|(key, _)| *key == Value::Integer(STATUS_LIST.into()))
            .map(|(_, value)| value)
            .unwrap();
        status_list
            .as_map()
            .unwrap()
            .iter()
            .find(|(key, _)| key.as_text() == Some("aggregation_uri"))
            .and_then(|(_, value)| value.as_text())
            .map(str::to_string)
    }

    #[tokio::test]
    async fn test_token_carries_issuer_scoped_aggregation_uri() {
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri = Some(AGGREGATION_BASE.parse().unwrap());
        let aggregation_id = register_issuer(&app_state.service, "issuer1").await;
        let expected = format!("{AGGREGATION_BASE}/{aggregation_id}");

        for accept in [
            ACCEPT_STATUS_LISTS_HEADER_JWT,
            ACCEPT_STATUS_LISTS_HEADER_CWT,
        ] {
            assert_eq!(
                served_aggregation_uri(app_state.clone(), accept).await,
                Some(expected.clone()),
                "{accept}"
            );
        }
    }

    #[tokio::test]
    async fn test_token_omits_aggregation_uri_when_not_configured() {
        let app_state = test_app_state(None).await;
        register_issuer(&app_state.service, "issuer1").await;

        assert_eq!(
            served_aggregation_uri(app_state, ACCEPT_STATUS_LISTS_HEADER_JWT).await,
            None
        );
    }

    #[tokio::test]
    async fn test_revalidation_serves_a_new_token_when_aggregation_uri_changes() {
        let scoped: Option<url::Url> = Some(AGGREGATION_BASE.parse().unwrap());
        for (before, after) in [(None, scoped.clone()), (scoped, None)] {
            for (condition, validator) in [
                (header::IF_NONE_MATCH, header::ETAG),
                (header::IF_MODIFIED_SINCE, header::LAST_MODIFIED),
            ] {
                let mut app_state = test_app_state(None).await;
                app_state.aggregation_uri = before.clone();
                register_issuer(&app_state.service, "issuer1").await;
                let token_id = uuid::Uuid::new_v4().to_string();
                publish_status(
                    State(app_state.clone()),
                    authenticated_issuer("issuer1"),
                    Path(token_id.clone()),
                    Json(StatusesRequest { statuses: vec![] }),
                )
                .await
                .unwrap();
                let now = OffsetDateTime::now_utc().unix_timestamp();
                let fetch = |app_state: AppState, headers: HeaderMap| {
                    get_status_list_at(
                        State(app_state),
                        token_id.clone(),
                        Ok(Query(StatusListQuery { time: None })),
                        headers,
                        now,
                    )
                };

                let first = fetch(app_state.clone(), HeaderMap::new())
                    .await
                    .unwrap()
                    .into_response();
                let mut revalidation = HeaderMap::new();
                revalidation.insert(condition.clone(), first.headers()[&validator].clone());
                app_state.aggregation_uri = after.clone();
                let response = fetch(app_state, revalidation)
                    .await
                    .unwrap()
                    .into_response();

                assert_eq!(response.status(), StatusCode::OK, "{condition}");
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert_eq!(
                    decode_jwt_claims(&body)["status_list"]["aggregation_uri"].is_string(),
                    after.is_some(),
                    "{condition}"
                );
            }
        }
    }

    struct UnavailableCredentials;

    #[async_trait::async_trait]
    impl CredentialRepo for UnavailableCredentials {
        async fn find(&self, _: &str) -> Result<Option<Credential>, CredentialError> {
            Err(CredentialError::Backend(
                "credential store unavailable".into(),
            ))
        }

        async fn find_by_kid(&self, _: &str) -> Result<Option<Credential>, CredentialError> {
            Err(CredentialError::Backend(
                "credential store unavailable".into(),
            ))
        }

        async fn insert(&self, _: Credential, _: AggregationId) -> Result<(), CredentialError> {
            Err(CredentialError::Backend(
                "credential store unavailable".into(),
            ))
        }

        async fn find_aggregation_id(
            &self,
            _: &str,
        ) -> Result<Option<AggregationId>, CredentialError> {
            Err(CredentialError::Backend(
                "credential store unavailable".into(),
            ))
        }

        async fn find_issuer_by_aggregation_id(
            &self,
            _: AggregationId,
        ) -> Result<Option<Issuer>, CredentialError> {
            Err(CredentialError::Backend(
                "credential store unavailable".into(),
            ))
        }
    }

    #[test]
    fn test_token_omits_aggregation_uri_when_lookup_fails() {
        let metrics = metrics_after(async {
            let mut app_state = test_app_state(None).await;
            app_state.aggregation_uri = Some(AGGREGATION_BASE.parse().unwrap());
            let service = &app_state.service;
            app_state.service = std::sync::Arc::new(crate::domain::service::Service::from_arcs(
                service.status_list_repo.clone(),
                std::sync::Arc::new(UnavailableCredentials),
                service.status_list_cache.clone(),
                service.snapshot_repo.clone(),
                service.cert_provider.clone(),
            ));

            assert_eq!(
                served_aggregation_uri(app_state, ACCEPT_STATUS_LISTS_HEADER_JWT).await,
                None
            );
        });
        let omitted = metrics
            .lines()
            .find(|line| line.starts_with("aggregation_uri_omitted_total"))
            .unwrap_or_else(|| panic!("aggregation_uri_omitted not exported:\n{metrics}"));
        assert!(omitted.ends_with(" 1"), "{omitted}");
    }

    #[test]
    fn test_token_skips_the_aggregation_id_lookup_for_a_withheld_issuer() {
        let metrics = metrics_after(async {
            let mut app_state = test_app_state(None).await;
            app_state.aggregation_uri = Some(AGGREGATION_BASE.parse().unwrap());
            app_state.aggregation_withheld_from =
                Arc::new(HashSet::from([Issuer::from("issuer1")]));
            let service = &app_state.service;
            app_state.service = Arc::new(crate::domain::service::Service::from_arcs(
                service.status_list_repo.clone(),
                Arc::new(UnavailableCredentials),
                service.status_list_cache.clone(),
                service.snapshot_repo.clone(),
                service.cert_provider.clone(),
            ));

            assert_eq!(
                served_aggregation_uri(app_state, ACCEPT_STATUS_LISTS_HEADER_JWT).await,
                None
            );
        });
        let omitted = metrics
            .lines()
            .find(|line| line.starts_with("aggregation_uri_omitted_total"));
        assert!(omitted.is_none_or(|line| line.ends_with(" 0")), "{metrics}");
    }

    #[tokio::test]
    async fn test_conditional_request_if_modified_since_alone_returns_fresh_200() {
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
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let ttl = app_state.token_ttl_secs as i64;
        let now0 = 1_000_000_000;
        let window_end = 999_999_900 + 900;

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

        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 900,
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

        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 900,
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
            now0 + 900,
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
    async fn test_conditional_request_matching_etag_within_window_certifies_304_even_when_ttl_ge_exp()
     {
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
                StatusCode::NOT_MODIFIED,
                "(exp={exp}, ttl={ttl}) a same-window matching ETag must certify a 304"
            );
        }
    }

    #[tokio::test]
    async fn test_same_window_non_conditional_gets_reuse_cached_bytes() {
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
        let body1 = axum::body::to_bytes(res1.into_body(), usize::MAX)
            .await
            .unwrap();
        let claims1 = decode_jwt_claims(&body1);
        assert_eq!(
            claims1["iat"].as_i64().unwrap(),
            window.0,
            "iat must be anchored to the window start (ticket 564), not the request time"
        );
        assert_eq!(
            claims1["exp"].as_i64().unwrap() - claims1["iat"].as_i64().unwrap(),
            exp_secs as i64
        );

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
        let claims = decode_jwt_claims(body);
        let iat = claims["iat"].as_i64().expect("token carries iat");
        let exp = claims["exp"].as_i64().expect("token carries exp");
        assert!(exp > iat, "a freshly signed token must not be born expired");
    }

    #[tokio::test]
    async fn test_key_rotation_invalidates_cached_token_bytes() {
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

            let validity = TokenValidity::new(exp, ttl);
            let now0 = crate::domain::service::current_unix_timestamp();
            let window_start = token_window(now0, validity).0;
            let width = token_window(now0, validity).1 - window_start;

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
    async fn test_strong_etag_differs_across_replicas() {
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

        assert_ne!(
            etags[0], etags[1],
            "two replicas over the same content/signer/window must issue byte-different \
             strong ETags (randomized ES256 signatures); this cross-replica deviation is \
             documented in the ticket"
        );
        assert!(
            etags[0].to_str().unwrap().starts_with('"')
                && !etags[0].to_str().unwrap().starts_with("W/"),
            "the live ETag must be strong"
        );
    }

    #[tokio::test]
    async fn test_matching_inm_304_does_not_sign_with_warm_cache() {
        let signs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = Arc::new(CountingCertProvider::new(signs.clone()));
        let app_state = test_app_state_with_cert_provider(provider).await;
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
            "a 304 revalidation must not sign when the representation is resident"
        );
    }

    #[tokio::test]
    async fn test_signing_material_rotation_between_key_derivation_and_token() {
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

    #[tokio::test]
    async fn test_cached_live_token_rejects_u64_max_token_exp_secs() {
        let mut app_state = test_app_state(None).await;

        let token_id = uuid::Uuid::new_v4().to_string();
        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        app_state.token_exp_secs = u64::MAX;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let err = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            1_000_000_000,
        )
        .await
        .expect_err("u64::MAX token_exp_secs must fail closed on the cached path");

        assert_eq!(
            err.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a directly constructed AppState with u64::MAX token_exp_secs must error, \
             not mint an already-expired token"
        );
    }
}
