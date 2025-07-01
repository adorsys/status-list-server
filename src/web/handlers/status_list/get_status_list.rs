use std::{fmt::Debug, io::Write as _};

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use coset::{
    self,
    cbor::Value as CborValue,
    iana::{Algorithm, EnumI64, HeaderParameter},
    CborSerializable, CoseSign1Builder, HeaderBuilder,
};
use flate2::{write::GzEncoder, Compression};
use jsonwebtoken::{EncodingKey, Header};
use p256::ecdsa::{signature::Signer, Signature};
use serde::{Deserialize, Serialize};

use crate::{
    models::{StatusList, StatusListRecord},
    utils::{keygen::Keypair, state::AppState},
    web::handlers::status_list::constants::{TOKEN_EXP, TOKEN_TTL},
};

use super::{
    constants::{
        ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT, CWT_TYPE, EXP, GZIP_HEADER,
        ISSUED_AT, STATUS_LIST, STATUS_LISTS_HEADER_CWT, STATUS_LISTS_HEADER_JWT, SUBJECT, TTL,
    },
    error::StatusListError,
};

pub async fn get_status_list(
    State(state): State<AppState>,
    Path(list_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse + Debug, StatusListError> {
    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());

    // build the token depending on the accept header
    match accept {
        None =>
        // assume jwt by default if no accept header is provided
        {
            build_status_list_token(ACCEPT_STATUS_LISTS_HEADER_JWT, &list_id, &state).await
        }
        Some(accept)
            if accept == ACCEPT_STATUS_LISTS_HEADER_JWT
                || accept == ACCEPT_STATUS_LISTS_HEADER_CWT =>
        {
            build_status_list_token(accept, &list_id, &state).await
        }
        Some(_) => Err(StatusListError::InvalidAcceptHeader),
    }
}

async fn build_status_list_token(
    accept: &str,
    list_id: &str,
    state: &AppState,
) -> Result<impl IntoResponse + Debug, StatusListError> {
    // Check cache for status list record
    if let Some(cached_record) = state.cache.status_list_record_cache.get(list_id).await {
        tracing::info!("Cache hit for status list record: {list_id}");
        // Record is in cache, proceed with building the response
        return build_response_from_record(accept, &cached_record, state).await;
    }

    tracing::info!("Cache miss for status list token: {list_id}");
    // Get status list claims from database
    let status_record = state
        .status_list_repo
        .find_one_by(list_id.to_string())
        .await
        .map_err(|err| {
            tracing::error!("Failed to get status list {list_id} from database: {err:?}");
            StatusListError::InternalServerError
        })?
        .ok_or(StatusListError::StatusListNotFound)?;

    // Store the token in the cache for future requests
    state
        .cache
        .status_list_record_cache
        .insert(list_id.to_string(), status_record.clone())
        .await;

    build_response_from_record(accept, &status_record, state).await
}

async fn build_response_from_record(
    accept: &str,
    status_record: &StatusListRecord,
    state: &AppState,
) -> Result<impl IntoResponse + Debug, StatusListError> {
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
    let keypair = Keypair::from_pkcs8_pem(&signing_key_pem).map_err(|e| {
        tracing::error!("Failed to parse server key: {e:?}");
        StatusListError::InternalServerError
    })?;

    let apply_gzip = |data: &[u8]| -> Result<Vec<u8>, StatusListError> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).map_err(|err| {
            tracing::error!("Failed to compress payload: {err:?}");
            StatusListError::InternalServerError
        })?;
        encoder.finish().map_err(|err| {
            tracing::error!("Failed to finish compression: {err:?}");
            StatusListError::InternalServerError
        })
    };

    let token_bytes = match accept {
        ACCEPT_STATUS_LISTS_HEADER_CWT => issue_cwt(status_record, &keypair, certs_parts)?,
        _ => issue_jwt(status_record, &keypair, certs_parts)?.into_bytes(),
    };

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, accept),
            (header::CONTENT_ENCODING, GZIP_HEADER),
        ],
        apply_gzip(&token_bytes)?,
    )
        .into_response())
}

// Function to create a CWT per the specification
fn issue_cwt(
    status_record: &StatusListRecord,
    keypair: &Keypair,
    cert_chain: Vec<String>,
) -> Result<Vec<u8>, StatusListError> {
    let mut claims = vec![];

    // Building the claims
    claims.push((
        CborValue::Integer(SUBJECT.into()),
        CborValue::Text(status_record.sub.clone()),
    ));
    let iat = Utc::now().timestamp();
    claims.push((
        CborValue::Integer(ISSUED_AT.into()),
        CborValue::Integer(iat.into()),
    ));
    // According to the spec, the lifetime of the token depends on the lifetime of the referenced token
    // https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html#section-13.1
    let exp = iat + TOKEN_EXP;
    claims.push((
        CborValue::Integer(EXP.into()),
        CborValue::Integer(exp.into()),
    ));
    claims.push((
        CborValue::Integer(TTL.into()),
        CborValue::Integer(TOKEN_TTL.into()),
    ));
    // Adding the status list map to the claims
    let status_list = vec![
        (
            CborValue::Text("bits".into()),
            CborValue::Integer(status_record.status_list.bits.into()),
        ),
        (
            CborValue::Text("lst".into()),
            CborValue::Text(status_record.status_list.lst.clone()),
        ),
    ];
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
        .value(CWT_TYPE, CborValue::Text(STATUS_LISTS_HEADER_CWT.into()))
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

    let cwt_bytes = sign1.to_vec().map_err(|err| {
        tracing::error!("Failed to serialize CWT: {err:?}");
        StatusListError::InternalServerError
    })?;

    Ok(cwt_bytes)
}

fn build_x5chain(cert_chain: &[String]) -> Result<CborValue, StatusListError> {
    use base64::prelude::{Engine as _, BASE64_STANDARD};

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
pub struct StatusListToken {
    pub exp: Option<i64>,
    pub iat: i64,
    pub status_list: StatusList,
    pub sub: String,
    pub ttl: Option<i64>,
}

fn issue_jwt(
    status_record: &StatusListRecord,
    keypair: &Keypair,
    cert_chain: Vec<String>,
) -> Result<String, StatusListError> {
    let iat = Utc::now().timestamp();
    let ttl = TOKEN_TTL;
    let exp = iat + TOKEN_EXP;
    // Building the claims
    let claims = StatusListToken {
        exp: Some(exp),
        iat,
        status_list: status_record.status_list.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{status_lists, StatusList, StatusListRecord},
        test_utils::test_app_state,
        utils::lst_gen::encode_compressed,
    };
    use axum::{
        body::to_bytes,
        extract::{Path, State},
        http::{self, HeaderMap, StatusCode},
    };
    use coset::CoseSign1;
    use jsonwebtoken::{DecodingKey, Validation};
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
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

        let cwt = CoseSign1::from_slice(&body_bytes).unwrap();

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

        // Verify claims
        let sub = claims
            .iter()
            .find(|(k, _)| k == &CborValue::Integer(SUBJECT.into()))
            .unwrap()
            .1
            .clone();
        assert_eq!(sub, CborValue::Text("test_subject".to_string()));

        let status_list_map = claims
            .iter()
            .find(|(k, _)| k == &CborValue::Integer(STATUS_LIST.into()))
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

        let lst = status_list
            .iter()
            .find(|(k, _)| k == &CborValue::Text("lst".to_string()))
            .unwrap()
            .1
            .clone();
        assert_eq!(lst, CborValue::Text(encode_compressed(&[0, 0, 0]).unwrap()));

        let ttl = claims
            .iter()
            .find(|(k, _)| k == &CborValue::Integer(TTL.into()))
            .unwrap()
            .1
            .clone();
        assert_eq!(ttl, CborValue::Integer(300.into()));
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
        assert_eq!(err.clone().into_response().status(), StatusCode::NOT_FOUND);
        assert_eq!(err, StatusListError::StatusListNotFound);
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
        assert_eq!(
            err.clone().into_response().status(),
            StatusCode::NOT_ACCEPTABLE
        );
        assert_eq!(err, StatusListError::InvalidAcceptHeader);
    }
}
