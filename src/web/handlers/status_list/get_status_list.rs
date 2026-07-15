use std::{fmt::Debug, io::Write as _};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
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
    models::{StatusListClaims, StatusListRecord},
    utils::{keygen::Keypair, state::AppState},
};

use super::{
    conditional::{ConditionalResponse, evaluate_conditional_request, format_http_date},
    constants::{
        ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT, CWT_TYPE, EXP, GZIP_HEADER,
        ISSUED_AT, STATUS_LIST, STATUS_LISTS_CWT_TYPE_VALUE, STATUS_LISTS_HEADER_JWT, SUBJECT, TTL,
    },
    error::StatusListError,
    etag::generate_etag,
};

pub async fn get_status_list(
    State(state): State<AppState>,
    Path(list_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse + Debug + use<>, StatusListError> {
    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());

    // Validate accept header
    let accept_type = match accept {
        None => ACCEPT_STATUS_LISTS_HEADER_JWT, // Default to JWT
        Some(accept)
            if accept == ACCEPT_STATUS_LISTS_HEADER_JWT
                || accept == ACCEPT_STATUS_LISTS_HEADER_CWT =>
        {
            accept
        }
        Some(_) => return Err(StatusListError::InvalidAcceptHeader),
    };

    // Extract conditional request headers
    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok());
    let if_modified_since = headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|h| h.to_str().ok());

    // Fetch status list record (from cache or database)
    let status_record = fetch_status_record(&list_id, &state).await?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let validity_bucket = now / state.token_exp_secs.max(1) as i64;

    let current_etag = generate_etag(&status_record, validity_bucket);

    let last_modified = format_http_date(status_record.updated_at);

    let cache_control = build_cache_control(state.token_ttl_secs);

    // Evaluate conditional request
    match evaluate_conditional_request(
        if_none_match,
        if_modified_since,
        &current_etag,
        status_record.updated_at,
    ) {
        ConditionalResponse::NotModified => {
            // Return 304 with caching headers but no body
            Ok((
                StatusCode::NOT_MODIFIED,
                [
                    (header::ETAG, current_etag.as_str()),
                    (header::LAST_MODIFIED, last_modified.as_str()),
                    (header::CACHE_CONTROL, cache_control.as_str()),
                    (header::VARY, "Accept"),
                ],
            )
                .into_response())
        }
        ConditionalResponse::Modified => {
            // Build full token response
            let compressed_token = build_token(accept_type, &status_record, &state).await?;

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, accept_type),
                    (header::CONTENT_ENCODING, GZIP_HEADER),
                    (header::ETAG, current_etag.as_str()),
                    (header::LAST_MODIFIED, last_modified.as_str()),
                    (header::CACHE_CONTROL, cache_control.as_str()),
                    (header::VARY, "Accept"),
                ],
                compressed_token,
            )
                .into_response())
        }
    }
}

/// Fetches status record from cache or database
async fn fetch_status_record(
    list_id: &str,
    state: &AppState,
) -> Result<StatusListRecord, StatusListError> {
    // Check cache for status list record
    if let Some(cached_record) = state.cache.get(list_id).await {
        tracing::info!("Cache hit for status list record: {list_id}");
        return Ok(cached_record);
    }

    tracing::info!("Cache miss for status list token: {list_id}");
    // Get status list claims from database
    let status_record = state
        .status_list_repo
        .find_one_by(list_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to get status list {list_id} from database: {err:?}");
            StatusListError::InternalServerError
        })?
        .ok_or(StatusListError::StatusListNotFound)?;

    // Store the token in the cache for future requests
    state
        .cache
        .insert(list_id.to_string(), status_record.clone())
        .await;

    Ok(status_record)
}

/// Builds and compresses the token (JWT or CWT)
async fn build_token(
    accept: &str,
    status_record: &StatusListRecord,
    state: &AppState,
) -> Result<Vec<u8>, StatusListError> {
    // Get the certificate chain
    let certs_parts = state
        .cert_manager
        .cert_chain_parts()
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
    let signing_key_pem = state.cert_manager.signing_key_pem().await.map_err(|e| {
        tracing::error!("Failed to load signing key: {e:?}");
        StatusListError::InternalServerError
    })?;

    let accept_header = accept.to_string();
    let status_record = status_record.clone();
    let aggregation_uri = state.aggregation_uri.clone();
    let token_exp_secs = state.token_exp_secs;
    let token_ttl_secs = state.token_ttl_secs;

    tokio::task::spawn_blocking(move || {
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).map_err(|e| {
            tracing::error!("Failed to parse server key: {e:?}");
            StatusListError::InternalServerError
        })?;

        let token_bytes = match accept_header.as_str() {
            ACCEPT_STATUS_LISTS_HEADER_CWT => issue_cwt(
                &status_record,
                &keypair,
                certs_parts,
                &aggregation_uri,
                token_exp_secs,
                token_ttl_secs,
            )?,
            _ => issue_jwt(
                &status_record,
                &keypair,
                certs_parts,
                &aggregation_uri,
                token_exp_secs,
                token_ttl_secs,
            )?
            .into_bytes(),
        };

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&token_bytes).map_err(|err| {
            tracing::error!("Failed to compress payload: {err:?}");
            StatusListError::InternalServerError
        })?;

        encoder.finish().map_err(|err| {
            tracing::error!("Failed to finish compression: {err:?}");
            StatusListError::InternalServerError
        })
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
    cert_chain: Vec<String>,
    aggregation_uri: &Option<String>,
    token_exp_secs: u64,
    token_ttl_secs: u64,
) -> Result<Vec<u8>, StatusListError> {
    let mut claims = vec![];

    // Building the claims
    claims.push((
        CborValue::Integer(SUBJECT.into()),
        CborValue::Text(status_record.sub.clone()),
    ));
    let iat = OffsetDateTime::now_utc().unix_timestamp();
    claims.push((
        CborValue::Integer(ISSUED_AT.into()),
        CborValue::Integer(iat.into()),
    ));
    // According to the spec, the lifetime of the token depends on the lifetime of the referenced token
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-13.7
    let exp = iat + token_exp_secs as i64;
    claims.push((
        CborValue::Integer(EXP.into()),
        CborValue::Integer(exp.into()),
    ));
    claims.push((
        CborValue::Integer(TTL.into()),
        CborValue::Integer(token_ttl_secs.into()),
    ));
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

    let x5chain_value = build_x5chain(&cert_chain)?;
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
    cert_chain: Vec<String>,
    aggregation_uri: &Option<String>,
    token_exp_secs: u64,
    token_ttl_secs: u64,
) -> Result<String, StatusListError> {
    let iat = OffsetDateTime::now_utc().unix_timestamp();
    let ttl = token_ttl_secs as i64;
    let exp = iat + token_exp_secs as i64;
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
    header.x5c = Some(cert_chain);

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
/// Returns a Cache-Control directive with public caching, max-age set to the token TTL,
/// and immutable flag to indicate content won't change during cache lifetime.
///
/// # Arguments
/// * `token_ttl_secs` - The token time-to-live in seconds
///
/// # Returns
/// A string formatted as "public, max-age={token_ttl_secs}, immutable"
fn build_cache_control(token_ttl_secs: u64) -> String {
    format!("public, max-age={}, immutable", token_ttl_secs)
}

/// Builds Cache-Control header value for error responses
///
/// Returns a Cache-Control directive that prevents caching of error states.
///
/// # Returns
/// A static string "no-store, max-age=0"
pub(crate) fn build_error_cache_control() -> &'static str {
    "no-store, max-age=0"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{StatusList, StatusListRecord, status_lists},
        test_utils::{test_app_state, test_app_state_with},
        utils::lst_gen::encode_compressed,
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
            lst: encode_compressed(&[0, 0, 0]).unwrap(),
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

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers.get(http::header::CONTENT_ENCODING).unwrap(), "gzip");

        let compressed_body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&compressed_body_bytes[..]);
        let mut body_bytes = Vec::new();
        decoder.read_to_end(&mut body_bytes).unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();

        // Load the decoding key
        let signing_key_pem = app_state.cert_manager.signing_key_pem().await.unwrap();
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
            encode_compressed(&[0, 0, 0]).unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_status_list_success_cwt() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]).unwrap(),
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

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers.get(http::header::CONTENT_ENCODING).unwrap(), "gzip");

        let compressed_body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&compressed_body_bytes[..]);
        let mut body_bytes = Vec::new();
        decoder.read_to_end(&mut body_bytes).unwrap();

        // Tagged decode: the CWT MUST be COSE_Sign1_Tagged (CBOR tag 18) per §5.2.
        let cwt = CoseSign1::from_tagged_slice(&body_bytes).unwrap();

        // Load the key from the cache
        let signing_key_pem = app_state.cert_manager.signing_key_pem().await.unwrap();
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
        let expected_lst_bytes =
            base64url::decode(&encode_compressed(&[0, 0, 0]).unwrap()).unwrap();
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
            lst: encode_compressed(&[0, 0, 0]).unwrap(),
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

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let compressed = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut body = Vec::new();
        decoder.read_to_end(&mut body).unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();

        let signing_key_pem = app_state.cert_manager.signing_key_pem().await.unwrap();
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
            lst: encode_compressed(&[0, 0, 0]).unwrap(),
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

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let compressed = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut body = Vec::new();
        decoder.read_to_end(&mut body).unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();

        let signing_key_pem = app_state.cert_manager.signing_key_pem().await.unwrap();
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
            lst: encode_compressed(&[0, 0, 0]).unwrap(),
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

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let compressed = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut body = Vec::new();
        decoder.read_to_end(&mut body).unwrap();

        let cwt = CoseSign1::from_tagged_slice(&body).unwrap();

        let signing_key_pem = app_state.cert_manager.signing_key_pem().await.unwrap();
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
            lst: encode_compressed(&[0, 0, 0]).unwrap(),
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

        let response = get_status_list(
            State(app_state.clone()),
            Path("test_list".to_string()),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let compressed = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut body = Vec::new();
        decoder.read_to_end(&mut body).unwrap();

        let cwt = CoseSign1::from_tagged_slice(&body).unwrap();

        let signing_key_pem = app_state.cert_manager.signing_key_pem().await.unwrap();
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

        let result =
            get_status_list(State(app_state), Path("test_list".to_string()), headers).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        let response = err.clone().into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(err, StatusListError::StatusListNotFound);

        // Verify error response includes no-store Cache-Control header
        let cache_control = response.headers().get(http::header::CACHE_CONTROL);
        assert!(
            cache_control.is_some(),
            "Error response should include Cache-Control header"
        );
        assert_eq!(
            cache_control.unwrap().to_str().unwrap(),
            "no-store, max-age=0",
            "Error response should have no-store Cache-Control directive"
        );
    }

    #[tokio::test]
    async fn test_get_status_list_unsupported_accept_header() {
        let app_state = test_app_state(None).await;

        let mut headers = HeaderMap::new();
        headers.insert(http::header::ACCEPT, "application/xml".parse().unwrap()); // unsupported

        let result =
            get_status_list(State(app_state), Path("test_list".to_string()), headers).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        let response = err.clone().into_response();
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(err, StatusListError::InvalidAcceptHeader);

        // Verify error response includes no-store Cache-Control header
        let cache_control = response.headers().get(http::header::CACHE_CONTROL);
        assert!(
            cache_control.is_some(),
            "Error response should include Cache-Control header"
        );
        assert_eq!(
            cache_control.unwrap().to_str().unwrap(),
            "no-store, max-age=0",
            "Error response should have no-store Cache-Control directive"
        );
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

        let result =
            get_status_list(State(app_state), Path("test_list".to_string()), headers).await;

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
        assert_eq!(cache_control, "public, max-age=300, immutable");

        // Test with zero TTL
        let cache_control_zero = build_cache_control(0);
        assert_eq!(cache_control_zero, "public, max-age=0, immutable");

        // Test with large TTL value
        let cache_control_large = build_cache_control(86400);
        assert_eq!(cache_control_large, "public, max-age=86400, immutable");
    }

    #[test]
    fn test_build_error_cache_control() {
        // Test error cache control header
        let error_cache_control = build_error_cache_control();
        assert_eq!(error_cache_control, "no-store, max-age=0");
    }

    #[tokio::test]
    async fn test_get_status_list_includes_caching_headers() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]).unwrap(),
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
        assert_eq!(cache_control, "public, max-age=300, immutable");

        let vary = response_headers
            .get(http::header::VARY)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(vary, "Accept");
    }

    #[tokio::test]
    async fn test_conditional_request_with_matching_etag() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_compressed(&[0, 0, 0]).unwrap(),
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
            "304 response should include Vary: Accept"
        );
        assert_eq!(
            response_headers
                .get(http::header::VARY)
                .unwrap()
                .to_str()
                .unwrap(),
            "Accept"
        );

        // Body should be empty
        let body_bytes = to_bytes(conditional_response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body_bytes.len(), 0, "304 response should have no body");
    }
}
