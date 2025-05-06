use std::{fmt::Debug, sync::Arc};

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use coset::{
    self, cbor::Value as CborValue, iana::Algorithm, CborSerializable, CoseSign1Builder,
    HeaderBuilder,
};
use jsonwebtoken::{EncodingKey, Header};
use p256::ecdsa::{signature::Signer, Signature};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    model::{Status, StatusEntry, StatusList, StatusListToken},
    utils::{keygen::Keypair, state::AppState},
};

use super::{
    constants::{
        ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT, CWT_TYPE, EXP, ISSUED_AT,
        STATUS_LIST, STATUS_LISTS_HEADER_CWT, STATUS_LISTS_HEADER_JWT, SUBJECT, TTL,
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

    // Validate accept header
    let accept = match accept {
        None => ACCEPT_STATUS_LISTS_HEADER_JWT, // Default to JWT if no accept header
        Some(accept)
            if accept == ACCEPT_STATUS_LISTS_HEADER_JWT
                || accept == ACCEPT_STATUS_LISTS_HEADER_CWT =>
        {
            accept
        }
        Some(_) => return Err(StatusListError::InvalidAcceptHeader),
    };

    // Get status list claims from database
    let list_id_clone = list_id.clone();
    let status_list_token = state
        .status_list_token_repository
        .find_one_by(list_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to get status list {list_id_clone} from database: {err:?}");
            StatusListError::InternalServerError
        })?
        .ok_or(StatusListError::StatusListNotFound)?;

    build_status_list_token(accept, &status_list_token, &state).await
}

pub async fn build_status_list_token(
    accept: &str,
    status_list_token: &StatusListToken,
    repo: &AppState,
) -> Result<impl IntoResponse + Debug, StatusListError> {
    let server_key = repo.server_key.clone();

    if ACCEPT_STATUS_LISTS_HEADER_JWT == accept {
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, accept)],
            issue_jwt(status_list_token, &server_key)?,
        )
            .into_response())
    } else {
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, accept)],
            issue_cwt(status_list_token, &server_key)?,
        )
            .into_response())
    }
}

fn issue_cwt(
    status_list_token: &StatusListToken,
    server_key: &Keypair,
) -> Result<Vec<u8>, StatusListError> {
    let mut claims = vec![];

    claims.push((
        CborValue::Integer(SUBJECT.into()),
        CborValue::Text(status_list_token.sub.clone()),
    ));
    let iat = Utc::now().timestamp();
    claims.push((
        CborValue::Integer(ISSUED_AT.into()),
        CborValue::Integer(iat.into()),
    ));
    // According to the spec, the lifetime of the token depends on the lifetime of the referenced token
    // https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html#section-13.1
    if let Some(exp) = status_list_token.exp {
        claims.push((
            CborValue::Integer(EXP.into()),
            CborValue::Integer(exp.into()),
        ));
    }
    claims.push((
        CborValue::Integer(TTL.into()),
        if let Some(ttl) = status_list_token.ttl {
            CborValue::Integer(ttl.into())
        } else {
            CborValue::Integer(43200.into())
        },
    ));
    let status_list = vec![
        (
            CborValue::Text("bits".into()),
            CborValue::Integer(status_list_token.status_list.bits.into()),
        ),
        (
            CborValue::Text("lst".into()),
            CborValue::Text(status_list_token.status_list.lst.clone()),
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

    // Building the protected header
    let protected = HeaderBuilder::new()
        .algorithm(Algorithm::ES256)
        .value(CWT_TYPE, CborValue::Text(STATUS_LISTS_HEADER_CWT.into()))
        .build();

    let signing_key = server_key.signing_key();

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusListClaims {
    pub exp: Option<i64>,
    pub iat: i64,
    pub status_list: StatusList,
    pub sub: String,
    pub ttl: Option<i64>,
}

fn issue_jwt(
    status_list_token: &StatusListToken,
    server_key: &Keypair,
) -> Result<String, StatusListError> {
    let iat = Utc::now().timestamp();
    let ttl = status_list_token.ttl.unwrap_or(43200);
    let claims = StatusListClaims {
        exp: status_list_token.exp,
        iat,
        status_list: status_list_token.status_list.clone(),
        sub: status_list_token.sub.to_owned(),
        ttl: Some(ttl),
    };
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some(STATUS_LISTS_HEADER_JWT.into());

    let pem_bytes = server_key.to_pkcs8_pem_bytes().map_err(|err| {
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

    let store = &appstate.status_list_token_repository;

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
        // Issuer verification is assumed to be handled via authentication (e.g., JWT)
        // Proceed with the update without explicit issuer check here

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

        let updated_token = StatusListToken::new(
            list_id.clone(),
            status_list_token.issuer.clone(),
            status_list_token.exp,
            status_list_token.iat,
            status_list,
            status_list_token.sub.clone(),
            status_list_token.ttl,
        );

        match store.update_one(updated_token).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::queries::SeaOrmStore,
        model::{status_list_tokens, StatusList, StatusListToken},
        utils::state::AppState,
    };
    use axum::{
        body::to_bytes,
        extract::{Path, State},
        http::{self, HeaderMap, StatusCode},
        Json,
    };
    use coset::CoseSign1;
    use jsonwebtoken::{DecodingKey, Validation};
    use p256::{
        ecdsa::{signature::Verifier, VerifyingKey},
        pkcs8::{EncodePublicKey, LineEnding},
    };
    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::json;
    use std::sync::Arc;

    fn server_key() -> Keypair {
        Keypair::from_pkcs8_pem(include_str!("../../../test_resources/ec-private.pem")).unwrap()
    }

    #[tokio::test]
    async fn test_get_status_list_jwt_success() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 0, 0]),
        };
        let status_list_token = StatusListToken::new(
            "test_list".to_string(),
            "test_issuer".to_string(),
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

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

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
        let body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();

        let decoding_key_pem = app_state
            .server_key
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
            "test_issuer".to_string(),
            None,
            1234567890,
            status_list.clone(),
            "test_subject".to_string(),
            Some(43200),
        );
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![
                    status_list_token.clone(),
                ]])
                .into_connection(),
        );

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

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
        let body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();

        let cwt = CoseSign1::from_slice(&body_bytes).unwrap();

        let binding = app_state.server_key.clone();
        let signing_key = binding.signing_key();
        let verifying_key = VerifyingKey::from(signing_key);
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

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

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
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let db_conn = Arc::new(mock_db.into_connection());

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        };

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
        let existing_token = StatusListToken::new(
            "test_list".to_string(),
            "test_issuer".to_string(),
            None,
            1234567890,
            initial_status_list.clone(),
            "test_subject".to_string(),
            None,
        );
        let updated_status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 1, 0]), // After update: index 1 set to INVALID
        };
        let updated_token = StatusListToken::new(
            "test_list".to_string(),
            "test_issuer".to_string(),
            None,
            1234567890,
            updated_status_list,
            "test_subject".to_string(),
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

        let app_state = Arc::new(AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        });

        let update_body = json!({
            "updates": [
                {"index": 1, "status": "INVALID"}
            ]
        });

        let response = update_statuslist(
            State(app_state),
            Path("test_list".to_string()),
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

        let app_state = Arc::new(AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        });

        let update_body = json!({
            "updates": [
                {"index": 1, "status": "INVALID"}
            ]
        });

        let response = update_statuslist(
            State(app_state),
            Path("test_list".to_string()),
            Json(update_body),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
