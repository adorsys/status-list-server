use std::{fmt::Debug, io::Write as _, sync::Arc};

use axum::{
    extract::rejection::QueryRejection,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use coset::{
    self, CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable,
    cbor::Value as CborValue,
    iana::{Algorithm, EnumI64, HeaderParameter},
};
use flate2::{Compression, write::GzEncoder};
use jsonwebtoken::{EncodingKey, Header};
use p256::ecdsa::{Signature, signature::Signer};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    application::UseCaseError,
    models::{StatusListClaims, StatusListRecord},
    utils::{keygen::Keypair, state::AppState},
    web::errors::ApiError,
};

use super::{
    conditional::{ConditionalResponse, evaluate_conditional_request, format_http_date},
    constants::{
        ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT, CWT_TYPE, EXP, GZIP_HEADER,
        ISSUED_AT, STATUS_LIST, STATUS_LISTS_CWT_TYPE_VALUE, STATUS_LISTS_HEADER_JWT, SUBJECT, TTL,
    },
    error::StatusListError,
    etag::{generate_etag, generate_historical_etag},
};

pub async fn get_status_list(
    State(state): State<AppState>,
    Path(list_id): Path<String>,
    query_result: Result<Query<StatusListQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<impl IntoResponse + Debug + use<>, ApiError> {
    let query = match query_result {
        Ok(Query(q)) => q,
        Err(e) => {
            tracing::warn!("Failed to parse query parameters: {e}");
            return Err(StatusListError::InvalidHistoricalTime.into());
        }
    };
    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());
    let client_accepts_gzip = client_accepts_gzip(&headers);

    // Validate accept header
    let accept_type = match accept {
        None => ACCEPT_STATUS_LISTS_HEADER_JWT.to_string(), // Default to JWT
        Some(accept)
            if accept == ACCEPT_STATUS_LISTS_HEADER_JWT
                || accept == ACCEPT_STATUS_LISTS_HEADER_CWT =>
        {
            accept.to_string()
        }
        Some(_) => return Err(StatusListError::InvalidAcceptHeader.into()),
    };

    // Handle historical query (draft-21 §8.4) separately from conditional requests
    if let Some(time) = query.time {
        return handle_historical_request(
            &list_id,
            time,
            &accept_type,
            &state,
            client_accepts_gzip,
        )
        .await;
    }

    // Extract conditional request headers
    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok());
    let if_modified_since = headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|h| h.to_str().ok());

    // Fetch status list record (from cache or database via application service)
    let status_record = fetch_status_record(&list_id, &state).await?;

    let current_etag = generate_etag(&status_record);

    // Last-Modified reflects the persisted content's last modification time.
    // The served token is re-signed every validity bucket, but ETag is
    // content-based and `max-age` (= token_ttl_secs < token_exp_secs) bounds
    // staleness so clients/CDNs cannot replay an expired token indefinitely.
    let last_modified_ts = status_record.updated_at;
    let last_modified = format_http_date(last_modified_ts);

    let cache_control = build_cache_control(state.token_ttl_secs);

    // Evaluate conditional request
    match evaluate_conditional_request(
        if_none_match,
        if_modified_since,
        &current_etag,
        last_modified_ts,
    ) {
        ConditionalResponse::NotModified => {
            // Return 304 with caching headers but no body
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
            // Build full token response
            let (token_bytes, encoding) = build_token(
                &accept_type,
                &status_record,
                None, // Use default validity window (now + token_exp_secs)
                &state,
                client_accepts_gzip,
            )
            .await?;

            let mut response = Response::new(token_bytes.into());
            *response.status_mut() = StatusCode::OK;
            let h = response.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&accept_type).unwrap(),
            );
            h.insert(header::ETAG, HeaderValue::from_str(&current_etag).unwrap());
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
    }
}

/// Handles historical resolution requests (draft-21 §8.4).
///
/// Historical queries are deliberately never served from the current
/// list cache: that cache contains mutable, present-day state.
/// They also don't participate in conditional request handling since
/// we're fetching a specific snapshot in time.
async fn handle_historical_request(
    list_id: &str,
    time: i64,
    accept_type: &str,
    state: &AppState,
    client_accepts_gzip: bool,
) -> Result<Response, ApiError> {
    // Validate time parameter: must be positive and not in the future
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if time <= 0 {
        tracing::warn!("Historical query rejected: time must be positive, got {time}");
        return Err(StatusListError::InvalidHistoricalTime.into());
    }
    if time > now {
        tracing::warn!("Historical query rejected: time is in the future ({time} > {now})");
        return Err(StatusListError::InvalidHistoricalTime.into());
    }

    // §12.7 privacy warning: historical queries leak timing information
    tracing::info!(
        "Historical query for list {list_id} at time {time} (age: {} seconds)",
        now - time
    );

    // Fetch the snapshot via application service
    let snapshot = state
        .status_lists
        .get_historical_status_list(list_id, time)
        .await
        .map_err(|err| {
            tracing::error!("Failed to resolve historical status list {list_id}: {err:?}");
            match err {
                crate::application::UseCaseError::NotFound => {
                    StatusListError::HistoricalStatusListNotFound
                }
                _ => StatusListError::InternalServerError,
            }
        })?;

    // Generate ETag and extract values before consuming snapshot
    let etag = generate_historical_etag(&snapshot);
    let last_modified = format_http_date(snapshot.iat);
    let validity_duration = (snapshot.exp - snapshot.iat) as u64;
    // A historical snapshot is immutable, but its cache lifetime must not
    // outlive the token's own validity window: an 86400 floor would let a
    // client cache a sub-day token past its `exp`, so max-age tracks the
    // window exactly.
    let cache_control = format!("max-age={validity_duration}, immutable");

    // Build the status record from the snapshot
    let status_record = StatusListRecord {
        list_id: snapshot.list_id,
        issuer: snapshot.issuer.0,
        status_list: crate::models::StatusList {
            bits: snapshot.status_list.bits,
            lst: snapshot.status_list.lst,
        },
        sub: snapshot.sub,
        updated_at: snapshot.iat, // Use snapshot iat as the modification time
    };

    // Build token with the snapshot's validity window
    let (token_bytes, encoding) = build_token(
        accept_type,
        &status_record,
        Some((snapshot.iat, snapshot.exp)),
        state,
        client_accepts_gzip,
    )
    .await?;

    let mut response = Response::new(token_bytes.into());
    *response.status_mut() = StatusCode::OK;
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(accept_type).unwrap(),
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
    /// draft-21 §8.4 Unix timestamp for a historical Status List Token.
    pub time: Option<i64>,
}

/// Fetches status record from application service (which handles caching internally)
async fn fetch_status_record(
    list_id: &str,
    state: &AppState,
) -> Result<Arc<StatusListRecord>, ApiError> {
    match state.status_lists.get_status_list(list_id).await {
        Ok(record) => {
            let status_record = StatusListRecord {
                list_id: record.list_id,
                issuer: record.issuer.0,
                status_list: crate::models::StatusList {
                    bits: record.status_list.bits,
                    lst: record.status_list.lst,
                },
                sub: record.sub,
                updated_at: record.updated_at,
            };
            Ok(Arc::new(status_record))
        }
        Err(UseCaseError::NotFound) => Err(StatusListError::StatusListNotFound.into()),
        Err(error) => {
            tracing::error!(?error, list_id, "Failed to retrieve status list");
            Err(StatusListError::InternalServerError.into())
        }
    }
}

/// Parses the request's `Accept-Encoding` header(s) (RFC 9110 content
/// negotiation) and reports whether the client has advertised support for
/// gzip.
///
/// Returns `false` when the header is absent, so responses are only compressed
/// when the client has explicitly opted in (see draft-21 §8.2).
///
/// Per RFC 9110 §12.5.3, an explicitly-named coding takes precedence over the
/// `*` wildcard. This means `gzip;q=0, *` is treated as "anything but gzip"
/// — the explicit `q=0` disables gzip even though the wildcard alone would
/// accept it.
///
/// Multiple `Accept-Encoding` field lines are combined as if comma-separated
/// (RFC 9110 §5.3), so all header lines are inspected via `get_all`.
fn client_accepts_gzip(headers: &HeaderMap) -> bool {
    let mut entries: Vec<(&str, Option<f32>)> = Vec::new();
    for val in headers.get_all(header::ACCEPT_ENCODING) {
        let Ok(val) = val.to_str() else { continue };
        for s in val.split(',') {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            let (coding, params) = s
                .split_once(';')
                .map(|(c, p)| (c.trim(), p.trim()))
                .unwrap_or((s, ""));
            let q = params
                .split(';')
                .find_map(|p| p.trim().strip_prefix("q=").map(|q| q.trim()))
                .and_then(|q| q.parse::<f32>().ok());
            entries.push((coding, q));
        }
    }

    match entries
        .iter()
        .find(|(c, _)| c.eq_ignore_ascii_case("gzip"))
        .map(|(_, q)| *q)
    {
        // gzip explicitly named with no q -> default weight 1.0 -> accept
        Some(None) => true,
        // gzip;q=v -> accept only if v > 0
        Some(Some(q)) => q > 0.0,
        // gzip not named: consult the * wildcard only
        None => entries.iter().any(|(c, q)| {
            c.eq_ignore_ascii_case("*") && (q.is_none() || q.map(|v| v > 0.0).unwrap_or(false))
        }),
    }
}

/// Builds and conditionally compresses the token (JWT or CWT).
///
/// Gzip compression is only applied when the client signals support via the
/// `Accept-Encoding` header, per HTTP semantics (RFC 9110 §8.4), and only
/// for JWT-format tokens (draft-21 §8.2 recommends Content-Encoding only for
/// JWT-format tokens; CWT responses are never compressed). When gzip is
/// negotiated the returned encoding hint is `Some("gzip")`; otherwise the raw
/// token bytes are returned with `None`.
async fn build_token(
    accept: &str,
    status_record: &StatusListRecord,
    validity_window: Option<(i64, i64)>,
    state: &AppState,
    client_accepts_gzip: bool,
) -> Result<(Vec<u8>, Option<&'static str>), StatusListError> {
    // Get the certificate chain
    let certs_parts = state
        .certificate_provider
        .certificate_chain()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get certificate chain: {e:?}");
            StatusListError::InternalServerError
        })?
        .ok_or_else(|| {
            tracing::warn!("The server certificate is not yet provisioned.");
            StatusListError::ServiceUnavailable
        })?;

    // Load the signing key
    let signing_key_pem = state
        .certificate_provider
        .signing_key_pem()
        .await
        .map_err(|e| {
            tracing::error!("Failed to load signing key: {e:?}");
            StatusListError::InternalServerError
        })?;

    let accept_header = accept.to_string();
    let status_record = status_record.clone();
    let aggregation_uri = state.aggregation_uri.clone();
    let validity_window = validity_window.unwrap_or_else(|| {
        let iat = OffsetDateTime::now_utc().unix_timestamp();
        (iat, iat + state.token_exp_secs as i64)
    });
    let token_ttl_secs = state.token_ttl_secs;

    // CWT responses must never be gzipped (draft-21 §8.2 recommends
    // Content-Encoding only for JWT-format tokens).
    let should_gzip = client_accepts_gzip && accept_header == ACCEPT_STATUS_LISTS_HEADER_JWT;

    tokio::task::spawn_blocking(move || {
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).map_err(|e| {
            tracing::error!("Failed to parse server key: {e:?}");
            StatusListError::InternalServerError
        })?;

        let token_bytes = match accept_header.as_str() {
            ACCEPT_STATUS_LISTS_HEADER_CWT => issue_cwt(
                &status_record,
                &keypair,
                &certs_parts,
                &aggregation_uri,
                validity_window.0,
                validity_window.1,
                token_ttl_secs,
            )?,
            _ => issue_jwt(
                &status_record,
                &keypair,
                &certs_parts,
                &aggregation_uri,
                validity_window.0,
                validity_window.1,
                token_ttl_secs,
            )?
            .into_bytes(),
        };

        if should_gzip {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&token_bytes).map_err(|err| {
                tracing::error!("Failed to compress payload: {err:?}");
                StatusListError::InternalServerError
            })?;
            let compressed = encoder.finish().map_err(|err| {
                tracing::error!("Failed to finish compression: {err:?}");
                StatusListError::InternalServerError
            })?;
            Ok((compressed, Some(GZIP_HEADER)))
        } else {
            Ok((token_bytes, None))
        }
    })
    .await
    .map_err(|err| {
        tracing::error!("Panicked while building token: {err:?}");
        StatusListError::InternalServerError
    })?
}

// Function to create a CWT per the specification
fn issue_cwt(
    status_record: &StatusListRecord,
    keypair: &Keypair,
    cert_chain: &[String],
    aggregation_uri: &Option<String>,
    iat: i64,
    exp: i64,
    token_ttl_secs: u64,
) -> Result<Vec<u8>, StatusListError> {
    // According to the spec, the lifetime of the token depends on the lifetime of the referenced token
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-13.7
    let mut claims = vec![
        (
            CborValue::Integer(SUBJECT.into()),
            CborValue::Text(status_record.sub.clone()),
        ),
        (
            CborValue::Integer(ISSUED_AT.into()),
            CborValue::Integer(iat.into()),
        ),
        (
            CborValue::Integer(EXP.into()),
            CborValue::Integer(exp.into()),
        ),
        (
            CborValue::Integer(TTL.into()),
            CborValue::Integer(token_ttl_secs.into()),
        ),
    ];
    // §4.3 requires lst as a CBOR byte string, not the base64url text used for JSON (§4.2).
    let lst_bytes = base64url::decode(&status_record.status_list.lst).map_err(|err| {
        tracing::error!("Failed to decode lst for CWT status_list claim: {err:?}");
        StatusListError::InternalServerError
    })?;

    // Adding the status list map to the claims
    let mut status_list = vec![
        (
            CborValue::Text("bits".into()),
            CborValue::Integer(status_record.status_list.bits.into()),
        ),
        (CborValue::Text("lst".into()), CborValue::Bytes(lst_bytes)),
    ];
    if let Some(uri) = aggregation_uri {
        status_list.push((
            CborValue::Text("aggregation_uri".into()),
            CborValue::Text(uri.clone()),
        ));
    }
    claims.push((
        CborValue::Integer(STATUS_LIST.into()),
        CborValue::Map(status_list),
    ));

    let payload = CborValue::Map(claims).to_vec().map_err(|err| {
        tracing::error!("Failed to serialize claims: {err:?}");
        StatusListError::InternalServerError
    })?;

    let x5chain_value = build_x5chain(cert_chain)?;
    // Building the protected header
    let protected = HeaderBuilder::new()
        .algorithm(Algorithm::ES256)
        .value(HeaderParameter::X5Chain.to_i64(), x5chain_value)
        .value(
            CWT_TYPE,
            CborValue::Text(STATUS_LISTS_CWT_TYPE_VALUE.into()),
        )
        .build();

    let signing_key = keypair.signing_key();

    // Building the CWT
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(&[], |payload| {
            let signature: Signature = signing_key.sign(payload);
            signature.to_vec()
        })
        .build();

    // Tagged as COSE_Sign1_Tagged (CBOR tag 18), per draft-ietf-oauth-status-list-21 §5.2.
    let cwt_bytes = sign1.to_tagged_vec().map_err(|err| {
        tracing::error!("Failed to serialize CWT: {err:?}");
        StatusListError::InternalServerError
    })?;

    Ok(cwt_bytes)
}

fn build_x5chain(cert_chain: &[String]) -> Result<CborValue, StatusListError> {
    use base64::prelude::{BASE64_STANDARD, Engine as _};

    let result: Result<Vec<Vec<u8>>, _> = cert_chain
        .iter()
        .map(|b64| BASE64_STANDARD.decode(b64))
        .collect();
    let certs_der = result.map_err(|err| {
        tracing::error!("Failed to decode certificate chain to DER: {err:?}");
        StatusListError::InternalServerError
    })?;

    let x5chain_value = if certs_der.len() == 1 {
        CborValue::Bytes(certs_der.into_iter().next().unwrap())
    } else {
        let cert_array: Vec<CborValue> = certs_der.into_iter().map(CborValue::Bytes).collect();
        CborValue::Array(cert_array)
    };

    Ok(x5chain_value)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StatusListToken {
    pub exp: Option<i64>,
    pub iat: i64,
    pub status_list: StatusListClaims,
    pub sub: String,
    pub ttl: Option<i64>,
}

fn issue_jwt(
    status_record: &StatusListRecord,
    keypair: &Keypair,
    cert_chain: &[String],
    aggregation_uri: &Option<String>,
    iat: i64,
    exp: i64,
    token_ttl_secs: u64,
) -> Result<String, StatusListError> {
    let ttl = token_ttl_secs as i64;
    let status_list = StatusListClaims {
        bits: status_record.status_list.bits,
        lst: status_record.status_list.lst.clone(),
        aggregation_uri: aggregation_uri.clone(),
    };
    // Building the claims
    let claims = StatusListToken {
        exp: Some(exp),
        iat,
        status_list,
        sub: status_record.sub.to_owned(),
        ttl: Some(ttl),
    };
    // Building the header
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some(STATUS_LISTS_HEADER_JWT.into());
    header.x5c = Some(cert_chain.to_vec());

    let pem_bytes = keypair.to_pkcs8_pem_bytes().map_err(|err| {
        tracing::error!("Failed to convert signing key to PEM: {err:?}");
        StatusListError::InternalServerError
    })?;
    let signer = EncodingKey::from_ec_pem(&pem_bytes).map_err(|err| {
        tracing::error!("Failed to create encoding key: {err:?}");
        StatusListError::InternalServerError
    })?;
    let token = jsonwebtoken::encode(&header, &claims, &signer).map_err(|err| {
        tracing::error!("Failed to encode JWT: {err:?}");
        StatusListError::InternalServerError
    })?;
    Ok(token)
}

/// Builds Cache-Control header value for successful responses
///
/// Returns a Cache-Control directive with max-age set to the token TTL and the
/// immutable flag, indicating content won't change during cache lifetime.
///
/// # Arguments
/// * `token_ttl_secs` - The token time-to-live in seconds
///
/// # Returns
/// A string formatted as "max-age={token_ttl_secs}, immutable"
fn build_cache_control(token_ttl_secs: u64) -> String {
    format!("max-age={}, immutable", token_ttl_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{
            StatusList, StatusListHistoryRecord, StatusListRecord, status_list_history,
            status_lists,
        },
        test_utils::{test_app_state, test_app_state_with},
        web::handlers::status_list::test_support::encode_compressed,
    };
    use axum::{
        body::to_bytes,
        extract::{Path, State},
        http::{self, HeaderMap, StatusCode},
    };
    use coset::{CoseSign1, Label, TaggedCborSerializable};
    use jsonwebtoken::{DecodingKey, Validation};
    use p256::ecdsa::{VerifyingKey, signature::Verifier};
    use p256::pkcs8::{EncodePublicKey, LineEnding};
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::{io::Read, sync::Arc};

    #[tokio::test]
    async fn test_get_status_list_jwt_success() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = StatusListRecord {
            list_id: "test_list".to_string(),
            issuer: "issuer1".to_string(),
            status_list,
            sub: "test_subject".to_string(),
            updated_at: 0,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        headers.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers.get(http::header::CONTENT_ENCODING).unwrap(), "gzip");
        assert_eq!(
            headers.get(http::header::VARY).unwrap(),
            "Accept, Accept-Encoding"
        );

        let compressed_body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&compressed_body_bytes[..]);
        let mut body_bytes = Vec::new();
        decoder.read_to_end(&mut body_bytes).unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();

        // Load the decoding key
        let signing_key_pem = app_state
            .certificate_provider
            .signing_key_pem()
            .await
            .unwrap();
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).unwrap();
        let decoding_key_pem = keypair
            .verifying_key()
            .to_public_key_pem(LineEnding::default())
            .unwrap()
            .into_bytes();
        let decoding_key = DecodingKey::from_ec_pem(&decoding_key_pem).unwrap();
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        // Disable exp validation since the token is expired in the test
        // we just want to verify the claims
        validation.validate_exp = false;
        let token_data =
            jsonwebtoken::decode::<StatusListToken>(body_str, &decoding_key, &validation).unwrap();

        // Verify the claims
        assert_eq!(token_data.claims.sub, "test_subject");
        assert_eq!(token_data.claims.status_list.bits, 8);
        assert_eq!(
            token_data.claims.status_list.lst,
            encode_compressed(&[0, 0, 0])
        );
    }

    #[tokio::test]
    async fn test_get_status_list_jwt_no_gzip_when_client_does_not_accept() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = StatusListRecord {
            list_id: "test_list".to_string(),
            issuer: "issuer1".to_string(),
            status_list,
            sub: "test_subject".to_string(),
            updated_at: 0,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        // No Accept-Encoding header: the client did not advertise gzip support.

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert!(
            headers.get(http::header::CONTENT_ENCODING).is_none(),
            "Content-Encoding must not be present when gzip was not applied"
        );
        // Vary must be present even without gzip so caches key on Accept-Encoding.
        assert_eq!(
            headers.get(http::header::VARY).unwrap(),
            "Accept, Accept-Encoding"
        );

        let body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();

        let signing_key_pem = app_state
            .certificate_provider
            .signing_key_pem()
            .await
            .unwrap();
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).unwrap();
        let decoding_key_pem = keypair
            .verifying_key()
            .to_public_key_pem(LineEnding::default())
            .unwrap()
            .into_bytes();
        let decoding_key = DecodingKey::from_ec_pem(&decoding_key_pem).unwrap();
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.validate_exp = false;
        let token_data =
            jsonwebtoken::decode::<StatusListToken>(body_str, &decoding_key, &validation).unwrap();

        assert_eq!(token_data.claims.sub, "test_subject");
        assert_eq!(token_data.claims.status_list.bits, 8);
        assert_eq!(
            token_data.claims.status_list.lst,
            encode_compressed(&[0, 0, 0])
        );
    }

    #[tokio::test]
    async fn test_get_status_list_success_cwt() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = StatusListRecord {
            list_id: "test_list".to_string(),
            issuer: "issuer1".to_string(),
            status_list: status_list.clone(),
            sub: "test_subject".to_string(),
            updated_at: 0,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_CWT.parse().unwrap(),
        );
        // Even though the client advertises gzip support, CWT responses must
        // never be gzipped (draft-21 §8.2 recommends Content-Encoding only for
        // JWT-format tokens).
        headers.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert!(
            headers.get(http::header::CONTENT_ENCODING).is_none(),
            "CWT responses must never be gzipped"
        );
        assert_eq!(
            headers.get(http::header::VARY).unwrap(),
            "Accept, Accept-Encoding"
        );

        let body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();

        // Tagged decode: the CWT MUST be COSE_Sign1_Tagged (CBOR tag 18) per §5.2.
        let cwt = CoseSign1::from_tagged_slice(&body_bytes).unwrap();

        // Load the key from the cache
        let signing_key_pem = app_state
            .certificate_provider
            .signing_key_pem()
            .await
            .unwrap();
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).unwrap();
        let signing_key = keypair.signing_key();
        let verifying_key = VerifyingKey::from(signing_key);

        // Verify signature
        let result = cwt.verify_signature(&[], |sig, data| {
            let signature = Signature::from_slice(sig).unwrap();
            verifying_key.verify(data, &signature)
        });
        assert!(result.is_ok());

        let payload_bytes = cwt.payload.unwrap();
        let payload = CborValue::from_slice(&payload_bytes).unwrap();
        let claims = match payload {
            CborValue::Map(claims) => claims,
            _ => panic!("Invalid CWT payload"),
        };

        // Literal spec integers (§5.2), not the production constants — catches constants.rs regressions.
        let sub = claims
            .iter()
            .find(|(k, _)| k == &CborValue::Integer(2i32.into()))
            .unwrap()
            .1
            .clone();
        assert_eq!(sub, CborValue::Text("test_subject".to_string()));

        let status_list_map = claims
            .iter()
            .find(|(k, _)| k == &CborValue::Integer(65533i32.into()))
            .unwrap()
            .1
            .clone();
        let status_list = match status_list_map {
            CborValue::Map(map) => map,
            _ => panic!("Invalid status list"),
        };

        let bits = status_list
            .iter()
            .find(|(k, _)| k == &CborValue::Text("bits".to_string()))
            .unwrap()
            .1
            .clone();
        assert_eq!(bits, CborValue::Integer(8.into()));

        // §4.3: lst MUST be a CBOR byte string, not the base64url text used for JSON (§4.2).
        let lst = status_list
            .iter()
            .find(|(k, _)| k == &CborValue::Text("lst".to_string()))
            .unwrap()
            .1
            .clone();
        let expected_lst_bytes = base64url::decode(&encode_compressed(&[0, 0, 0])).unwrap();
        assert_eq!(lst, CborValue::Bytes(expected_lst_bytes));

        let ttl = claims
            .iter()
            .find(|(k, _)| k == &CborValue::Integer(65534i32.into()))
            .unwrap()
            .1
            .clone();
        assert_eq!(ttl, CborValue::Integer(300.into()));

        // Label 16 (type) MUST be the full media type per §5.2, unlike JWT's abbreviated typ.
        let type_header = cwt
            .protected
            .header
            .rest
            .iter()
            .find(|(label, _)| *label == Label::Int(CWT_TYPE))
            .map(|(_, value)| value.clone())
            .expect("label 16 (type) missing from CWT protected header");
        assert_eq!(
            type_header,
            CborValue::Text(STATUS_LISTS_CWT_TYPE_VALUE.to_string())
        );
    }

    fn record_with_bits_8(list_id: &str, status_list: StatusList) -> StatusListRecord {
        StatusListRecord {
            list_id: list_id.to_string(),
            issuer: "issuer1".to_string(),
            status_list,
            sub: "test_subject".to_string(),
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn test_jwt_emits_aggregation_uri_when_configured() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = record_with_bits_8("test_list", status_list);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state_with(
            Some(db_conn.clone()),
            Some("https://aggregation.example.com/statuslists/aggregation".to_string()),
        )
        .await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        headers.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers.get(http::header::CONTENT_ENCODING).unwrap(), "gzip");
        assert_eq!(
            headers.get(http::header::VARY).unwrap(),
            "Accept, Accept-Encoding"
        );
        let compressed = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut body = Vec::new();
        decoder.read_to_end(&mut body).unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();

        let signing_key_pem = app_state
            .certificate_provider
            .signing_key_pem()
            .await
            .unwrap();
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).unwrap();
        let decoding_key_pem = keypair
            .verifying_key()
            .to_public_key_pem(LineEnding::default())
            .unwrap()
            .into_bytes();
        let decoding_key = DecodingKey::from_ec_pem(&decoding_key_pem).unwrap();
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.validate_exp = false;
        let token_data =
            jsonwebtoken::decode::<StatusListToken>(body_str, &decoding_key, &validation).unwrap();

        assert_eq!(
            token_data.claims.status_list.aggregation_uri.as_deref(),
            Some("https://aggregation.example.com/statuslists/aggregation")
        );
    }

    #[tokio::test]
    async fn test_jwt_omits_aggregation_uri_when_not_configured() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = record_with_bits_8("test_list", status_list);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        headers.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers.get(http::header::CONTENT_ENCODING).unwrap(), "gzip");
        assert_eq!(
            headers.get(http::header::VARY).unwrap(),
            "Accept, Accept-Encoding"
        );
        let compressed = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut body = Vec::new();
        decoder.read_to_end(&mut body).unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();

        let signing_key_pem = app_state
            .certificate_provider
            .signing_key_pem()
            .await
            .unwrap();
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).unwrap();
        let decoding_key_pem = keypair
            .verifying_key()
            .to_public_key_pem(LineEnding::default())
            .unwrap()
            .into_bytes();
        let decoding_key = DecodingKey::from_ec_pem(&decoding_key_pem).unwrap();
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.validate_exp = false;
        let token_data =
            jsonwebtoken::decode::<StatusListToken>(body_str, &decoding_key, &validation).unwrap();
        assert_eq!(token_data.claims.status_list.aggregation_uri, None);
    }

    #[tokio::test]
    async fn test_cwt_emits_aggregation_uri_when_configured() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = record_with_bits_8("test_list", status_list);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state_with(
            Some(db_conn.clone()),
            Some("https://aggregation.example.com/statuslists/aggregation".to_string()),
        )
        .await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_CWT.parse().unwrap(),
        );
        headers.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert!(
            headers.get(http::header::CONTENT_ENCODING).is_none(),
            "CWT responses must never be gzipped"
        );
        assert_eq!(
            headers.get(http::header::VARY).unwrap(),
            "Accept, Accept-Encoding"
        );
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();

        let cwt = CoseSign1::from_tagged_slice(&body).unwrap();

        let signing_key_pem = app_state
            .certificate_provider
            .signing_key_pem()
            .await
            .unwrap();
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).unwrap();
        let signing_key = keypair.signing_key();
        let verifying_key = VerifyingKey::from(signing_key);

        let verify_result = cwt.verify_signature(&[], |sig, data| {
            let signature = Signature::from_slice(sig).unwrap();
            verifying_key.verify(data, &signature)
        });
        assert!(verify_result.is_ok());

        let claims = match CborValue::from_slice(&cwt.payload.unwrap()).unwrap() {
            CborValue::Map(m) => m,
            _ => panic!("Invalid CWT payload"),
        };
        let status_list_map = claims
            .iter()
            .find(|(k, _)| k == &CborValue::Integer(STATUS_LIST.into()))
            .unwrap()
            .1
            .clone();
        let status_list = match status_list_map {
            CborValue::Map(m) => m,
            _ => panic!("Invalid status list"),
        };

        let aggregation_uri = status_list
            .iter()
            .find(|(k, _)| k == &CborValue::Text("aggregation_uri".to_string()))
            .map(|(_, v)| v.clone());
        assert_eq!(
            aggregation_uri,
            Some(CborValue::Text(
                "https://aggregation.example.com/statuslists/aggregation".to_string()
            ))
        );
    }

    #[tokio::test]
    async fn test_cwt_omits_aggregation_uri_when_not_configured() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = record_with_bits_8("test_list", status_list);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_CWT.parse().unwrap(),
        );
        headers.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert!(
            headers.get(http::header::CONTENT_ENCODING).is_none(),
            "CWT responses must never be gzipped"
        );
        assert_eq!(
            headers.get(http::header::VARY).unwrap(),
            "Accept, Accept-Encoding"
        );
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();

        let cwt = CoseSign1::from_tagged_slice(&body).unwrap();

        let signing_key_pem = app_state
            .certificate_provider
            .signing_key_pem()
            .await
            .unwrap();
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).unwrap();
        let signing_key = keypair.signing_key();
        let verifying_key = VerifyingKey::from(signing_key);

        let verify_result = cwt.verify_signature(&[], |sig, data| {
            let signature = Signature::from_slice(sig).unwrap();
            verifying_key.verify(data, &signature)
        });
        assert!(verify_result.is_ok());

        let claims = match CborValue::from_slice(&cwt.payload.unwrap()).unwrap() {
            CborValue::Map(m) => m,
            _ => panic!("Invalid CWT payload"),
        };
        let status_list_map = claims
            .iter()
            .find(|(k, _)| k == &CborValue::Integer(STATUS_LIST.into()))
            .unwrap()
            .1
            .clone();
        let status_list = match status_list_map {
            CborValue::Map(m) => m,
            _ => panic!("Invalid status list"),
        };

        let aggregation_uri = status_list
            .iter()
            .find(|(k, _)| k == &CborValue::Text("aggregation_uri".to_string()))
            .map(|(_, v)| v.clone());
        assert!(
            aggregation_uri.is_none(),
            "aggregation_uri should be absent when not configured"
        );
    }

    #[tokio::test]
    async fn test_get_status_list_not_found() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let result = get_status_list(
            State(app_state),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error.as_ref(), "status_list_not_found");
        assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_status_list_unsupported_accept_header() {
        let app_state = test_app_state(None).await;

        let mut headers = HeaderMap::new();
        headers.insert(http::header::ACCEPT, "application/xml".parse().unwrap()); // unsupported

        let result = get_status_list(
            State(app_state),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await;

        assert!(result.is_err());
        let _err = result.unwrap_err();
    }

    #[tokio::test]
    async fn test_error_responses_omit_etag_and_last_modified() {
        // Test 404 Not Found error
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let result = get_status_list(
            State(app_state),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await;

        assert!(result.is_err());
        let response = result.unwrap_err().into_response();
        let response_headers = response.headers();

        // Verify error responses do NOT include ETag or Last-Modified headers
        assert!(
            response_headers.get(http::header::ETAG).is_none(),
            "Error response should not include ETag header"
        );
        assert!(
            response_headers.get(http::header::LAST_MODIFIED).is_none(),
            "Error response should not include Last-Modified header"
        );

        // But should include Cache-Control
        assert!(
            response_headers.get(http::header::CACHE_CONTROL).is_some(),
            "Error response should include Cache-Control header"
        );
    }

    #[test]
    fn test_build_cache_control() {
        // Test with specific TTL value
        let cache_control = build_cache_control(300);
        assert_eq!(cache_control, "max-age=300, immutable");

        // Test with zero TTL
        let cache_control_zero = build_cache_control(0);
        assert_eq!(cache_control_zero, "max-age=0, immutable");

        // Test with large TTL value
        let cache_control_large = build_cache_control(86400);
        assert_eq!(cache_control_large, "max-age=86400, immutable");
    }

    #[tokio::test]
    async fn test_get_status_list_includes_caching_headers() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = StatusListRecord {
            list_id: "test_list".to_string(),
            issuer: "issuer1".to_string(),
            status_list,
            sub: "test_subject".to_string(),
            updated_at: 1234567890,
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let response_headers = response.headers();

        // Verify ETag header is present and has correct format
        let etag = response_headers
            .get(http::header::ETAG)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(etag.starts_with("W/\""), "ETag should be a weak validator");
        assert!(etag.ends_with('"'), "ETag should be quoted");

        // Verify Last-Modified header is present
        let last_modified = response_headers
            .get(http::header::LAST_MODIFIED)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(!last_modified.is_empty(), "Last-Modified should be present");

        // Verify Cache-Control header is present and correct
        let cache_control = response_headers
            .get(http::header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "max-age=300, immutable");

        let vary = response_headers
            .get(http::header::VARY)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(vary, "Accept, Accept-Encoding");
    }

    #[tokio::test]
    async fn test_conditional_request_with_matching_etag() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = StatusListRecord {
            list_id: "test_list".to_string(),
            issuer: "issuer1".to_string(),
            status_list,
            sub: "test_subject".to_string(),
            updated_at: 1234567890,
        };

        // Single query result - will be cached after first request
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        // First request - get the ETag
        let first_response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
        )
        .await
        .unwrap()
        .into_response();

        let etag = first_response
            .headers()
            .get(http::header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Second request - conditional request with the ETag (will use cache)
        let mut conditional_headers = HeaderMap::new();
        conditional_headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        conditional_headers.insert(http::header::IF_NONE_MATCH, etag.parse().unwrap());

        let conditional_response = get_status_list(
            State(app_state),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            conditional_headers,
        )
        .await
        .unwrap()
        .into_response();

        // Should return 304 Not Modified
        assert_eq!(conditional_response.status(), StatusCode::NOT_MODIFIED);

        // Should still have caching headers
        let response_headers = conditional_response.headers();
        assert!(response_headers.contains_key(http::header::ETAG));
        assert!(response_headers.contains_key(http::header::LAST_MODIFIED));
        assert!(response_headers.contains_key(http::header::CACHE_CONTROL));
        assert!(
            response_headers.contains_key(http::header::VARY),
            "304 response should include Vary: Accept, Accept-Encoding"
        );
        assert_eq!(
            response_headers
                .get(http::header::VARY)
                .unwrap()
                .to_str()
                .unwrap(),
            "Accept, Accept-Encoding"
        );

        // Body should be empty
        let body_bytes = to_bytes(conditional_response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body_bytes.len(), 0, "304 response should have no body");
    }

    #[tokio::test]
    async fn test_conditional_request_if_modified_since_returns_304() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = StatusListRecord {
            list_id: "test_list".to_string(),
            issuer: "issuer1".to_string(),
            status_list,
            sub: "test_subject".to_string(),
            updated_at: 1672531200, // 2023-01-01 00:00:00 UTC
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        // First request: capture Last-Modified.
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        let first_response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(first_response.status(), StatusCode::OK);
        let last_modified = first_response
            .headers()
            .get(http::header::LAST_MODIFIED)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Second request with If-Modified-Since: Last-Modified (updated_at) is
        // <= the captured timestamp, so the handler must return 304 — no ETag sent.
        let mut conditional_headers = HeaderMap::new();
        conditional_headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        conditional_headers.insert(
            http::header::IF_MODIFIED_SINCE,
            last_modified.parse().unwrap(),
        );
        let conditional_response = get_status_list(
            State(app_state),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            conditional_headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(conditional_response.status(), StatusCode::NOT_MODIFIED);
        assert!(
            conditional_response
                .headers()
                .contains_key(http::header::LAST_MODIFIED),
            "304 response should include Last-Modified"
        );
        assert!(
            conditional_response
                .headers()
                .contains_key(http::header::CACHE_CONTROL),
            "304 response should include Cache-Control"
        );
        let body_bytes = to_bytes(conditional_response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body_bytes.len(), 0, "304 response should have no body");
    }

    #[tokio::test]
    async fn test_conditional_request_if_modified_since_returns_200() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]),
        };
        let status_list_token = StatusListRecord {
            list_id: "test_list".to_string(),
            issuer: "issuer1".to_string(),
            status_list,
            sub: "test_subject".to_string(),
            updated_at: 1672531200, // 2023-01-01 00:00:00 UTC
        };
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_lists::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        // An If-Modified-Since older than updated_at means the served
        // representation is newer than the client's cached value, so the
        // handler must return 200 with a fresh body.
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        headers.insert(
            http::header::IF_MODIFIED_SINCE,
            "Thu, 01 Jan 1970 00:00:00 GMT".parse().unwrap(),
        );
        let response = get_status_list(
            State(app_state),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().contains_key(http::header::ETAG),
            "200 response should include ETag"
        );
    }

    #[tokio::test]
    async fn test_get_status_list_returns_snapshot_valid_at_requested_time() {
        let snapshot = StatusListHistoryRecord {
            snapshot_id: "snapshot-1".to_string(),
            list_id: "test_list".to_string(),
            issuer: "test_issuer".to_string(),
            status_list: StatusList {
                bits: 8,
                lst: encode_compressed(&[42]),
            },
            sub: "test_subject".to_string(),
            iat: 1_700_000_000,
            exp: 1_700_000_900,
        };
        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<status_list_history::Model, Vec<_>, _>(vec![vec![
                    snapshot.clone(),
                ]])
                .into_connection(),
        );
        let app_state = test_app_state(Some(db_conn)).await;

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery {
                time: Some(1_700_000_450),
            })),
            HeaderMap::new(),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Historical queries don't use gzip (no Accept-Encoding header provided)
        let body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();

        let signing_key_pem = app_state
            .certificate_provider
            .signing_key_pem()
            .await
            .unwrap();
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).unwrap();
        let decoding_key_pem = keypair
            .verifying_key()
            .to_public_key_pem(LineEnding::default())
            .unwrap()
            .into_bytes();
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.validate_exp = false;
        let token = jsonwebtoken::decode::<StatusListToken>(
            &body_str,
            &DecodingKey::from_ec_pem(&decoding_key_pem).unwrap(),
            &validation,
        )
        .unwrap()
        .claims;

        assert_eq!(token.iat, snapshot.iat);
        assert_eq!(token.exp, Some(snapshot.exp));
        assert!(token.iat <= 1_700_000_450);
        assert!(token.exp.unwrap() > 1_700_000_450);
        assert_eq!(token.status_list.lst, snapshot.status_list.lst);
    }

    #[tokio::test]
    async fn test_get_status_list_returns_not_found_when_time_is_unavailable() {
        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results::<status_list_history::Model, Vec<_>, _>(vec![vec![]])
                .into_connection(),
        );
        let result = get_status_list(
            State(test_app_state(Some(db_conn)).await),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: Some(1) })),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(
            result.unwrap_err().into_response().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn test_get_status_list_rejects_negative_time() {
        let app_state = test_app_state(None).await;
        let result = get_status_list(
            State(app_state),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: Some(-1) })),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(
            result.unwrap_err().into_response().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn test_get_status_list_rejects_zero_time() {
        let app_state = test_app_state(None).await;
        let result = get_status_list(
            State(app_state),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery { time: Some(0) })),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(
            result.unwrap_err().into_response().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn test_get_status_list_rejects_future_time() {
        let app_state = test_app_state(None).await;
        // Use a time far in the future
        let result = get_status_list(
            State(app_state),
            Path("test_list".to_string()),
            Ok(Query(StatusListQuery {
                time: Some(i64::MAX),
            })),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(
            result.unwrap_err().into_response().status(),
            StatusCode::BAD_REQUEST
        );
    }

    // --- client_accepts_gzip: RFC 9110 §12.5.3 wildcard precedence ---

    #[test]
    fn test_accepts_gzip_simple() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_accepts_gzip_with_qvalue() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=0.5".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_gzip_q0() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=0".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_gzip_q0_with_wildcard_accept() {
        // "gzip;q=0, *" means "anything except gzip" → must NOT gzip.
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=0, *".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_accepts_via_wildcard_only() {
        // gzip not named, only * → wildcard accepts gzip.
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "*".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_accepts_via_wildcard_q1() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "*;q=1".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_wildcard_q0() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "*;q=0".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_identity_q0_gzip_q0() {
        // identity;q=0, gzip;q=0 → gzip explicitly disabled.
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT_ENCODING,
            "identity;q=0, gzip;q=0".parse().unwrap(),
        );
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_when_header_absent() {
        let h = HeaderMap::new();
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_multiple_accept_encoding_lines() {
        // RFC 9110 §5.3: multiple field lines are combined as comma-separated.
        let mut h = HeaderMap::new();
        h.append(header::ACCEPT_ENCODING, "deflate".parse().unwrap());
        h.append(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_multiple_lines_explicit_gzip_q0_blocks_wildcard() {
        let mut h = HeaderMap::new();
        h.append(header::ACCEPT_ENCODING, "gzip;q=0".parse().unwrap());
        h.append(header::ACCEPT_ENCODING, "*".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_case_insensitive_gzip() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "GZIP".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }
}
