use std::io::Write as _;
use std::sync::{Mutex, OnceLock};

use coset::{
    self, CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable,
    cbor::Value as CborValue,
    iana::{Algorithm, EnumI64, HeaderParameter},
};
use flate2::{Compression, write::GzEncoder};
use jsonwebtoken::{EncodingKey, Header};
use opentelemetry::{KeyValue, global, metrics::Counter};
use p256::ecdsa::{Signature, signature::Signer};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::domain::models::status_list::{StatusListError, StatusListRecord};
use crate::utils::keygen::Keypair;

use super::constants::{
    ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT, CWT_TYPE, EXP, GZIP_HEADER,
    ISSUED_AT, STATUS_LIST, STATUS_LISTS_CWT_TYPE_VALUE, STATUS_LISTS_HEADER_JWT, SUBJECT, TTL,
};

const TOKEN_ATTEMPTS_METRIC: &str = "token_generation_attempts";
const TOKEN_FAILURES_METRIC: &str = "token_generation_failures";

/// Token-generation SLI counters. Cached after first use: the first token is
/// only ever generated after `init_telemetry`/`setup_metrics` has installed the
/// global meter provider, so the handles are valid (unlike a handle taken at
/// module init, which would be a permanent no-op).
#[derive(Clone)]
struct TokenMetrics {
    attempts: Counter<u64>,
    failures: Counter<u64>,
}

fn token_metrics() -> TokenMetrics {
    static METRICS: OnceLock<Mutex<Option<(u64, TokenMetrics)>>> = OnceLock::new();
    crate::utils::metrics::cached_instruments(&METRICS, || {
        let meter = global::meter("status-list-server");
        TokenMetrics {
            attempts: meter
                .u64_counter(TOKEN_ATTEMPTS_METRIC)
                .with_description("Total number of status-list token generation attempts")
                .build(),
            failures: meter
                .u64_counter(TOKEN_FAILURES_METRIC)
                .with_description("Total number of failed status-list token generations")
                .build(),
        }
    })
}

/// Classify the client's `Accept` header into the bounded `format` label value.
fn token_format(accept: &str) -> &'static str {
    if accept == ACCEPT_STATUS_LISTS_HEADER_CWT {
        "cwt"
    } else {
        "jwt"
    }
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

/// Build a signed status-list token (JWT or CWT) for the given record.
///
/// # Parameters
/// * `accept` – the `Accept` header value (e.g. `application/statuslist+jwt`)
/// * `status_record` – the status list data to encode
/// * `validity_window` – `(iat, exp)` pair; defaults to `(now, now + token_exp_secs)`
/// * `client_accepts_gzip` – whether to gzip-compress JWT output
pub(crate) async fn build_status_list_token(
    state: &crate::server::AppState,
    accept: &str,
    status_record: &StatusListRecord,
    validity_window: Option<(i64, i64)>,
    client_accepts_gzip: bool,
) -> Result<(Vec<u8>, Option<&'static str>), StatusListError> {
    let format = token_format(accept);
    let attributes = [KeyValue::new("format", format)];
    token_metrics().attempts.add(1, &attributes);
    match build_status_list_token_inner(
        state,
        accept,
        status_record,
        validity_window,
        client_accepts_gzip,
    )
    .await
    {
        Ok(token) => Ok(token),
        Err(err) => {
            token_metrics().failures.add(1, &attributes);
            Err(err)
        }
    }
}

async fn build_status_list_token_inner(
    state: &crate::server::AppState,
    accept: &str,
    status_record: &StatusListRecord,
    validity_window: Option<(i64, i64)>,
    client_accepts_gzip: bool,
) -> Result<(Vec<u8>, Option<&'static str>), StatusListError> {
    let certs_parts = state
        .service
        .cert_provider()
        .certificate_chain()
        .await
        .map_err(|e| StatusListError::Backend(Box::new(e)))?
        .ok_or(StatusListError::Unavailable)?;

    let signing_key_pem = state
        .service
        .cert_provider()
        .signing_key_pem()
        .await
        .map_err(|e| StatusListError::Backend(Box::new(e)))?;

    let accept = accept.to_string();
    let status_record = status_record.clone();
    let aggregation_uri = state.aggregation_uri.clone();
    let validity_window = validity_window.unwrap_or_else(|| {
        let iat = OffsetDateTime::now_utc().unix_timestamp();
        (iat, iat + state.token_exp_secs as i64)
    });
    let token_ttl_secs = state.token_ttl_secs;
    let should_gzip = client_accepts_gzip && accept == ACCEPT_STATUS_LISTS_HEADER_JWT;

    tokio::task::spawn_blocking(move || {
        let keypair = Keypair::from_pkcs8_pem(&signing_key_pem)
            .map_err(|e| StatusListError::Backend(Box::new(e)))?;

        let token_bytes = match accept.as_str() {
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
