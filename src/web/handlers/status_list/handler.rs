use std::{fmt::Debug, io::Write as _, sync::Arc};

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use blake3;
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
use serde_json::{json, Value};

use crate::{
    models::{Status, StatusEntry, StatusList, StatusListToken},
    utils::{keygen::Keypair, state::AppState},
};

use super::{
    constants::{
        ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT, CWT_TYPE, EXP, GZIP_HEADER,
        ISSUED_AT, STATUS_LIST, STATUS_LISTS_HEADER_CWT, STATUS_LISTS_HEADER_JWT, SUBJECT, TTL,
    },
    error::StatusListError,
};

pub trait StatusListTokenExt {
    fn new(
        list_id: String,
        issuer: String,
        exp: Option<i64>,
        iat: i64,
        status_list: StatusList,
        sub: String,
        ttl: Option<i64>,
    ) -> Self;
}

impl StatusListTokenExt for StatusListToken {
    fn new(
        list_id: String,
        issuer: String,
        exp: Option<i64>,
        iat: i64,
        status_list: StatusList,
        sub: String,
        ttl: Option<i64>,
    ) -> Self {
        Self {
            list_id,
            issuer,
            exp,
            iat,
            status_list,
            sub,
            ttl,
        }
    }
}

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
    // Get status list claims from database
    let status_claims = state
        .status_list_token_repo
        .find_one_by(list_id.to_string())
        .await
        .map_err(|err| {
            tracing::error!("Failed to get status list {list_id} from database: {err:?}");
            StatusListError::InternalServerError
        })?;

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

    let status_claims = match status_claims {
        Some(status_claims) => status_claims,
        None => {
            return Err(StatusListError::StatusListNotFound);
        }
    };

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
        ACCEPT_STATUS_LISTS_HEADER_CWT => issue_cwt(&status_claims, &keypair, certs_parts)?,
        _ => issue_jwt(&status_claims, &keypair, certs_parts)?.into_bytes(),
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
    token: &StatusListToken,
    keypair: &Keypair,
    cert_chain: Vec<String>,
) -> Result<Vec<u8>, StatusListError> {
    let mut claims = vec![];

    // Building the claims
    claims.push((
        CborValue::Integer(SUBJECT.into()),
        CborValue::Text(token.sub.clone()),
    ));
    let iat = Utc::now().timestamp();
    claims.push((
        CborValue::Integer(ISSUED_AT.into()),
        CborValue::Integer(iat.into()),
    ));
    // According to the spec, the lifetime of the token depends on the lifetime of the referenced token
    // https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html#section-13.1
    if let Some(exp) = token.exp {
        claims.push((
            CborValue::Integer(EXP.into()),
            CborValue::Integer(exp.into()),
        ));
    }
    claims.push((
        CborValue::Integer(TTL.into()),
        if let Some(ttl) = token.ttl {
            CborValue::Integer(ttl.into())
        } else {
            // Default to 12 hours
            CborValue::Integer(43200.into())
        },
    ));
    // Adding the status list map to the claims
    let status_list = vec![
        (
            CborValue::Text("bits".into()),
            CborValue::Integer(token.status_list.bits.into()),
        ),
        (
            CborValue::Text("lst".into()),
            CborValue::Text(token.status_list.lst.clone()),
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
pub struct StatusListClaims {
    pub exp: Option<i64>,
    pub iat: i64,
    pub status_list: StatusList,
    pub sub: String,
    pub ttl: Option<i64>,
}

fn issue_jwt(
    token: &StatusListToken,
    keypair: &Keypair,
    cert_chain: Vec<String>,
) -> Result<String, StatusListError> {
    let iat = Utc::now().timestamp();
    let ttl = token.ttl.unwrap_or(43200);
    // Building the claims
    let claims = StatusListClaims {
        exp: token.exp,
        iat,
        status_list: token.status_list.clone(),
        sub: token.sub.to_owned(),
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

pub async fn update_statuslist(
    State(appstate): State<Arc<AppState>>,
    Path(list_id): Path<String>,
    Extension(issuer): Extension<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let updates = match body
        .as_object()
        .and_then(|body| body.get("updates"))
        .and_then(|statuslist| statuslist.as_array())
    {
        Some(updates) => updates,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                StatusListError::MalformedBody(
                    "Request body must contain a valid 'updates' array".to_string(),
                ),
            )
                .into_response();
        }
    };

    if updates.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            StatusListError::Generic("No status updates provided".to_string()),
        )
            .into_response();
    }

    let updates_json = match serde_json::to_vec(updates) {
        Ok(json) => json,
        Err(e) => {
            tracing::error!("Failed to serialize updates: {e}");
            return (StatusCode::BAD_REQUEST, "Failed to serialize request body").into_response();
        }
    };

    let updates: Vec<StatusEntry> = match serde_json::from_slice(&updates_json) {
        Ok(updates) => updates,
        Err(e) => {
            tracing::error!("Malformed request body: {e}");
            return (
                StatusCode::BAD_REQUEST,
                StatusListError::MalformedBody(
                    "Request body must contain a valid 'updates' array".to_string(),
                ),
            )
                .into_response();
        }
    };

    let store = &appstate.status_list_token_repo;

    let status_list_token = match store.find_one_by(list_id.clone()).await {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Find error: {:?}", e);
            return (
                StatusCode::NOT_FOUND,
                StatusListError::StatusListNotFound.to_string(),
            )
                .into_response();
        }
    };

    if let Some(status_list_token) = status_list_token {
        // Ownership check: only the owner (token.sub) can update
        if status_list_token.issuer != issuer {
            return (
                StatusCode::FORBIDDEN,
                StatusListError::Forbidden("Issuer does not own this list".to_string()),
            )
                .into_response();
        }
        let lst = status_list_token.status_list;
        let updated_lst = match update_status(&lst.lst, updates) {
            Ok(updated_lst) => updated_lst,
            Err(e) => {
                tracing::error!("Status update failed: {:?}", e);
                return match e {
                    StatusListError::InvalidIndex => {
                        (StatusCode::BAD_REQUEST, "Invalid index").into_response()
                    }
                    _ => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        StatusListError::UpdateFailed.to_string(),
                    )
                        .into_response(),
                };
            }
        };

        let status_list = StatusList {
            bits: lst.bits,
            lst: updated_lst,
        };

        let statuslisttoken = StatusListToken::new(
            list_id.clone(),
            status_list_token.issuer,
            status_list_token.exp,
            status_list_token.iat,
            status_list,
            status_list_token.sub.clone(),
            status_list_token.ttl,
        );

        match store.update_one(list_id.clone(), statuslisttoken).await {
            Ok(true) => StatusCode::ACCEPTED.into_response(),
            Ok(false) => {
                tracing::error!("Failed to update status list");
                (
                    StatusCode::BAD_REQUEST,
                    StatusListError::UpdateFailed.to_string(),
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!("Update error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database update failed").into_response()
            }
        }
    } else {
        (StatusCode::NOT_FOUND, "Status list not found").into_response()
    }
}

fn encode_lst(bits: Vec<u8>) -> String {
    base64url::encode(
        bits.iter()
            .flat_map(|&n| n.to_be_bytes())
            .collect::<Vec<u8>>(),
    )
}

fn update_status(lst: &str, updates: Vec<StatusEntry>) -> Result<String, StatusListError> {
    let mut decoded_lst =
        base64url::decode(lst).map_err(|e| StatusListError::Generic(e.to_string()))?;

    for update in updates {
        let index = update.index as usize;
        if index >= decoded_lst.len() {
            return Err(StatusListError::InvalidIndex);
        }

        decoded_lst[index] = match update.status {
            Status::VALID => 0,
            Status::INVALID => 1,
            Status::SUSPENDED => 2,
            Status::APPLICATIONSPECIFIC => 3,
        };
    }

    Ok(encode_lst(decoded_lst))
}

/// Status List Aggregation endpoint handler
pub async fn status_list_aggregation(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    // Fetch all status list tokens from the repository
    let tokens_result = state.status_list_token_repo.find_all().await;

    let tokens = match tokens_result {
        Ok(tokens) => tokens,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                json!({"error": "Failed to fetch status lists"}).to_string(),
            )
                .into_response();
        }
    };

    // Build the list of URIs
    let status_lists: Vec<String> = tokens
        .iter()
        .map(|token| {
            format!(
                "https://{}/statuslists/{}",
                state.server_domain, token.list_id
            )
        })
        .collect();

    // ETag support (simple hash of the list)
    let etag = format!("\"{}\"", blake3::hash(status_lists.join(",").as_bytes()));
    if let Some(if_none_match) = headers.get(header::IF_NONE_MATCH) {
        if if_none_match.to_str().ok() == Some(&etag) {
            return (
                StatusCode::NOT_MODIFIED,
                [(header::ETAG, etag.as_str())],
                "", // No body for 304
            )
                .into_response();
        }
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::ETAG, etag.as_str()),
        ],
        json!({ "status_lists": status_lists }).to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{status_list_tokens, StatusList, StatusListToken},
        test_utils::test_app_state,
    };
    use axum::{
        body::to_bytes,
        extract::{Path, State},
        http::{self, HeaderMap, StatusCode},
        Json,
    };
    use coset::CoseSign1;
    use jsonwebtoken::{DecodingKey, Validation};
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    use p256::pkcs8::{EncodePublicKey, LineEnding};
    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::json;
    use std::{io::Read, sync::Arc};

    #[tokio::test]
    async fn test_get_status_list_jwt_success() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 0, 0]),
        };
        let status_list_token = StatusListToken::new(
            "test_list".to_string(),
            "issuer1".to_string(),
            Some(1234767890),
            1234567890,
            status_list.clone(),
            "test_subject".to_string(),
            None,
        );
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![
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
            jsonwebtoken::decode::<StatusListClaims>(body_str, &decoding_key, &validation).unwrap();

        // Verify the claims
        assert_eq!(token_data.claims.sub, "test_subject");
        assert_eq!(token_data.claims.status_list.bits, 8);
        assert_eq!(token_data.claims.status_list.lst, encode_lst(vec![0, 0, 0]));
        assert_eq!(token_data.claims.exp, Some(1234767890));
        assert_eq!(token_data.claims.ttl, Some(43200));
    }

    #[tokio::test]
    async fn test_get_status_list_success_cwt() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 0, 0]),
        };
        let status_list_token = StatusListToken::new(
            "test_list".to_string(),
            "issuer1".to_string(),
            None,
            1234567890,
            status_list.clone(),
            "test_subject".to_string(),
            Some(43200),
        );
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![
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
        assert_eq!(lst, CborValue::Text(encode_lst(vec![0, 0, 0])));

        let ttl = claims
            .iter()
            .find(|(k, _)| k == &CborValue::Integer(TTL.into()))
            .unwrap()
            .1
            .clone();
        assert_eq!(ttl, CborValue::Integer(43200.into()));
    }

    #[tokio::test]
    async fn test_get_status_list_not_found() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![]])
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

    #[tokio::test]
    async fn test_update_statuslist_success() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let initial_status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 0, 0]),
        };
        let owner = "issuer1";
        let existing_token = StatusListToken::new(
            "test_list".to_string(),
            "issuer1".to_string(),
            None,
            1234567890,
            initial_status_list.clone(),
            owner.to_string(), // sub matches issuer
            None,
        );
        let updated_status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 1, 0]), // After update: index 1 set to INVALID
        };
        let updated_token = StatusListToken::new(
            "test_list".to_string(),
            "issuer1".to_string(),
            None,
            1234567890,
            updated_status_list,
            owner.to_string(), // sub matches issuer
            None,
        );
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![existing_token.clone()],
                    vec![existing_token],
                    vec![updated_token],
                ])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let update_body = json!({
            "updates": [
                {"index": 1, "status": "INVALID"}
            ]
        });

        let response = update_statuslist(
            State(app_state.into()),
            Path(owner.to_string()),
            Extension(owner.to_string()),
            Json(update_body),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_update_statuslist_not_found() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![]])
                .into_connection(),
        );

        let app_state = test_app_state(Some(db_conn.clone())).await;

        let update_body = json!({
            "updates": [
                {"index": 1, "status": "INVALID"}
            ]
        });

        let response = update_statuslist(
            State(app_state.into()),
            Path("test_list".to_string()),
            Extension("test_list".to_string()),
            Json(update_body),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_status_list_aggregation_non_empty() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let mock_token = StatusListToken::new(
            "id1".to_string(),
            "issuer1".to_string(),
            None,
            0,
            StatusList {
                bits: 1,
                lst: "foo".to_string(),
            },
            "sub1".to_string(),
            None,
        );
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![
                    mock_token.clone(),
                ]])
                .into_connection(),
        );
        let app_state = test_app_state(Some(db_conn)).await;

        // First request to get ETag
        let initial_response =
            status_list_aggregation(State(app_state.clone()), HeaderMap::new()).await;
        let etag = initial_response
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap();

        // Second request with If-None-Match
        let headers = HeaderMap::from_iter([(header::IF_NONE_MATCH, etag.parse().unwrap())]);
        let response = status_list_aggregation(State(app_state.clone()), headers).await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_status_list_aggregation_empty() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![]])
                .into_connection(),
        );
        let app_state = test_app_state(Some(db_conn)).await;
        let mut headers = HeaderMap::new();
        let response = status_list_aggregation(State(app_state.clone()), headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.get("status_lists").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 0);
    }

    #[tokio::test]
    async fn test_status_list_aggregation_etag_and_if_none_match() {
        // Initialize crypto provider
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let token = StatusListToken::new(
            "id1".to_string(),
            "issuer1".to_string(),
            None,
            0,
            StatusList {
                bits: 1,
                lst: "foo".to_string(),
            },
            "sub1".to_string(),
            None,
        );
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![token.clone()],
                    vec![token.clone()],
                ])
                .into_connection(),
        );
        let app_state = test_app_state(Some(db_conn)).await;

        // First request to get ETag
        let initial_response =
            status_list_aggregation(State(app_state.clone()), HeaderMap::new()).await;
        let etag = initial_response
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap();

        // Second request with If-None-Match
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, etag.parse().unwrap());
        let response = status_list_aggregation(State(app_state.clone()), headers).await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_status_list_aggregation_error() {
        use crate::database::error::RepositoryError;
        use crate::database::queries::Repository;
        use crate::models::StatusListToken;
        use async_trait::async_trait;
        use std::sync::Arc;

        struct FailingStore;
        #[async_trait]
        impl Repository<StatusListToken> for FailingStore {
            async fn find_all(&self) -> Result<Vec<StatusListToken>, RepositoryError> {
                Err(RepositoryError::FindError("fail".to_string()))
            }

            async fn find_one_by(
                &self,
                _id: String,
            ) -> Result<Option<StatusListToken>, RepositoryError> {
                Err(RepositoryError::FindError("fail".to_string()))
            }

            async fn update_one(
                &self,
                _id: String,
                _entity: StatusListToken,
            ) -> Result<bool, RepositoryError> {
                Err(RepositoryError::FindError("fail".to_string()))
            }

            async fn insert_one(&self, _entity: StatusListToken) -> Result<(), RepositoryError> {
                Err(RepositoryError::InsertError("fail".to_string()))
            }
        }

        let app_state = AppState {
            credential_repo: crate::database::queries::SeaOrmStore::new(Arc::new(
                MockDatabase::new(DatabaseBackend::Postgres).into_connection(),
            )),
            status_list_token_repo: Arc::new(FailingStore),
            server_domain: "example.com".to_string(),
            cert_manager: Arc::new(
                crate::cert_manager::CertManager::new(
                    vec!["example.com".to_string()],
                    "admin@example.com",
                    None::<String>,
                    "https://acme-v02.api.letsencrypt.org/directory",
                )
                .unwrap(),
            ),
        };
        let headers = HeaderMap::new();
        let response = status_list_aggregation(State(app_state), headers).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
