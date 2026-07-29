use std::{fmt::Debug, io::Write as _};

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
    domain::models::status_list::{StatusListError, StatusListRecord},
    server::{AppState, error::ApiError},
    utils::keygen::Keypair,
};

use super::{
    conditional::{ConditionalResponse, evaluate_conditional_request, format_http_date},
    constants::{
        ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT, CWT_TYPE, EXP, GZIP_HEADER,
        ISSUED_AT, STATUS_LIST, STATUS_LISTS_CWT_TYPE_VALUE, STATUS_LISTS_HEADER_JWT, SUBJECT, TTL,
    },
    etag::{generate_etag, generate_historical_etag},
};

/// Handle GET /status-lists/{list_id} request.
///
/// This function handles the following cases:
///
/// - Retrieve a status list identified by its list id.
/// - Retrieve a historical status list identified by its list id and time.
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

    let accept_type = match accept {
        None => ACCEPT_STATUS_LISTS_HEADER_JWT.to_string(),
        Some(accept)
            if accept == ACCEPT_STATUS_LISTS_HEADER_JWT
                || accept == ACCEPT_STATUS_LISTS_HEADER_CWT =>
        {
            accept.to_string()
        }
        Some(_) => {
            return Err(ApiError::bad_request(
                "invalid_accept_header",
                "Unsupported Accept header",
            ));
        }
    };

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

    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok());
    let if_modified_since = headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|h| h.to_str().ok());

    let status_record = fetch_status_record(&list_id, &state).await?;
    let current_etag = generate_etag(&status_record);
    let last_modified_ts = status_record.updated_at;
    let last_modified = format_http_date(last_modified_ts);
    let cache_control = build_cache_control(state.token_ttl_secs);

    match evaluate_conditional_request(
        if_none_match,
        if_modified_since,
        &current_etag,
        last_modified_ts,
    ) {
        ConditionalResponse::NotModified => Ok((
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, current_etag.as_str()),
                (header::LAST_MODIFIED, last_modified.as_str()),
                (header::CACHE_CONTROL, cache_control.as_str()),
                (header::VARY, "Accept, Accept-Encoding"),
            ],
        )
            .into_response()),
        ConditionalResponse::Modified => {
            let (token_bytes, encoding) = build_token(
                &accept_type,
                &status_record,
                None,
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

async fn handle_historical_request(
    list_id: &str,
    time: i64,
    accept_type: &str,
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

    let snapshot = state.service.get_historical_snapshot(list_id, time).await?;

    let etag = generate_historical_etag(&snapshot);
    let last_modified = format_http_date(snapshot.iat);
    let validity_duration = (snapshot.exp - snapshot.iat) as u64;
    let cache_control = format!("max-age={validity_duration}, immutable");

    let status_record = StatusListRecord {
        list_id: snapshot.list_id,
        issuer: snapshot.issuer,
        status_list: snapshot.status_list,
        sub: snapshot.sub,
        updated_at: snapshot.iat,
    };

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
        Some(None) => true,
        Some(Some(q)) => q > 0.0,
        None => entries.iter().any(|(c, q)| {
            c.eq_ignore_ascii_case("*") && (q.is_none() || q.map(|v| v > 0.0).unwrap_or(false))
        }),
    }
}

async fn build_token(
    accept: &str,
    status_record: &StatusListRecord,
    validity_window: Option<(i64, i64)>,
    state: &AppState,
    client_accepts_gzip: bool,
) -> Result<(Vec<u8>, Option<&'static str>), StatusListError> {
    let certs_parts = state
        .service
        .cert_provider
        .certificate_chain()
        .await
        .map_err(|e| StatusListError::Backend(Box::new(e)))?
        .ok_or_else(|| {
            StatusListError::Backend(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Certificate not provisioned",
            )))
        })?;

    let signing_key_pem = state
        .service
        .cert_provider
        .signing_key_pem()
        .await
        .map_err(|e| StatusListError::Backend(Box::new(e)))?;

    let accept_header = accept.to_string();
    let status_record = status_record.clone();
    let aggregation_uri = state.aggregation_uri.clone();
    let validity_window = validity_window.unwrap_or_else(|| {
        let iat = OffsetDateTime::now_utc().unix_timestamp();
        (iat, iat + state.token_exp_secs as i64)
    });
    let token_ttl_secs = state.token_ttl_secs;

    let should_gzip = client_accepts_gzip && accept_header == ACCEPT_STATUS_LISTS_HEADER_JWT;

    tokio::task::spawn_blocking(move || {
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem)
            .map_err(|e| StatusListError::Backend(Box::new(e)))?;

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
            encoder
                .write_all(&token_bytes)
                .map_err(|err| StatusListError::Backend(Box::new(err)))?;
            let compressed = encoder
                .finish()
                .map_err(|err| StatusListError::Backend(Box::new(err)))?;
            Ok((compressed, Some(GZIP_HEADER)))
        } else {
            Ok((token_bytes, None))
        }
    })
    .await
    .map_err(|err| StatusListError::Backend(Box::new(err)))?
}

fn issue_cwt(
    status_record: &StatusListRecord,
    keypair: &Keypair,
    cert_chain: &[String],
    aggregation_uri: &Option<String>,
    iat: i64,
    exp: i64,
    token_ttl_secs: u64,
) -> Result<Vec<u8>, StatusListError> {
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

    let lst_bytes = base64url::decode(&status_record.status_list.lst)
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;

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

    let payload = CborValue::Map(claims)
        .to_vec()
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;

    let x5chain_value = build_x5chain(cert_chain)?;
    let protected = HeaderBuilder::new()
        .algorithm(Algorithm::ES256)
        .value(HeaderParameter::X5Chain.to_i64(), x5chain_value)
        .value(
            CWT_TYPE,
            CborValue::Text(STATUS_LISTS_CWT_TYPE_VALUE.into()),
        )
        .build();

    let signing_key = keypair.signing_key();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(&[], |payload| {
            let signature: Signature = signing_key.sign(payload);
            signature.to_vec()
        })
        .build();

    let cwt_bytes = sign1
        .to_tagged_vec()
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;

    Ok(cwt_bytes)
}

fn build_x5chain(cert_chain: &[String]) -> Result<CborValue, StatusListError> {
    use base64::prelude::{BASE64_STANDARD, Engine as _};

    let result: Result<Vec<Vec<u8>>, _> = cert_chain
        .iter()
        .map(|b64| BASE64_STANDARD.decode(b64))
        .collect();
    let certs_der = result.map_err(|err| StatusListError::Backend(Box::new(err)))?;

    let x5chain_value = if certs_der.len() == 1 {
        CborValue::Bytes(certs_der.into_iter().next().unwrap())
    } else {
        let cert_array: Vec<CborValue> = certs_der.into_iter().map(CborValue::Bytes).collect();
        CborValue::Array(cert_array)
    };

    Ok(x5chain_value)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct StatusListClaims {
    pub bits: u8,
    pub lst: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aggregation_uri: Option<String>,
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
    let claims = StatusListToken {
        exp: Some(exp),
        iat,
        status_list,
        sub: status_record.sub.to_owned(),
        ttl: Some(ttl),
    };
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some(STATUS_LISTS_HEADER_JWT.into());
    header.x5c = Some(cert_chain.to_vec());

    let pem_bytes = keypair
        .to_pkcs8_pem_bytes()
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;
    let signer = EncodingKey::from_ec_pem(&pem_bytes)
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;
    let token = jsonwebtoken::encode(&header, &claims, &signer)
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;
    Ok(token)
}

fn build_cache_control(token_ttl_secs: u64) -> String {
    format!("max-age={}, immutable", token_ttl_secs)
}
