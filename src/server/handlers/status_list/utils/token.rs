use std::io::Write as _;
use std::sync::{Arc, Mutex, OnceLock};

use coset::{
    self, CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable,
    cbor::Value as CborValue,
    iana::{Algorithm, EnumI64, HeaderParameter},
};
use flate2::{Compression, write::GzEncoder};
use opentelemetry::{KeyValue, global, metrics::Counter};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::domain::models::status_list::{StatusListError, StatusListRecord};
use crate::domain::models::token::SigningAlgorithm;
use crate::domain::ports::TokenSigner;

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

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'static str,
    typ: &'static str,
    x5c: &'a [String],
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
    let cert_components = state
        .service
        .cert_provider()
        .get_active_certificate()
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
        let token_bytes = match accept.as_str() {
            ACCEPT_STATUS_LISTS_HEADER_CWT => {
                let x5chain = cert_components
                    .x5chain
                    .ok_or(StatusListError::Unavailable)?;
                issue_cwt(
                    &status_record,
                    cert_components.signing_key,
                    x5chain,
                    aggregation_uri,
                    validity_window.0,
                    validity_window.1,
                    token_ttl_secs,
                )?
            }
            _ => {
                let cert_chain = cert_components
                    .certificate_chain
                    .ok_or(StatusListError::Unavailable)?;
                issue_jwt(
                    &status_record,
                    cert_components.signing_key,
                    cert_chain,
                    aggregation_uri,
                    validity_window.0,
                    validity_window.1,
                    token_ttl_secs,
                )?
                .into_bytes()
            }
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
    signer: Arc<dyn TokenSigner>,
    x5chain: CborValue,
    aggregation_uri: Option<String>,
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

    let (bits, lst_bytes) = status_record.status_list.token_lst_bytes()?;

    let mut status_list = vec![
        (
            CborValue::Text("bits".into()),
            CborValue::Integer(bits.into()),
        ),
        (CborValue::Text("lst".into()), CborValue::Bytes(lst_bytes)),
    ];
    if let Some(uri) = aggregation_uri {
        status_list.push((
            CborValue::Text("aggregation_uri".into()),
            CborValue::Text(uri),
        ));
    }
    claims.push((
        CborValue::Integer(STATUS_LIST.into()),
        CborValue::Map(status_list),
    ));

    let payload = CborValue::Map(claims)
        .to_vec()
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;

    let cose_alg = cose_algorithm(signer.algorithm())?;
    let protected = HeaderBuilder::new()
        .algorithm(cose_alg)
        .value(HeaderParameter::X5Chain.to_i64(), x5chain)
        .value(
            CWT_TYPE,
            CborValue::Text(STATUS_LISTS_CWT_TYPE_VALUE.into()),
        )
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .try_create_signature(&[], |tbs| signer.sign(tbs))
        .map_err(|err| StatusListError::Backend(Box::new(err)))?
        .build();

    let cwt_bytes = sign1
        .to_tagged_vec()
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;

    Ok(cwt_bytes)
}

fn issue_jwt(
    status_record: &StatusListRecord,
    signer: Arc<dyn TokenSigner>,
    cert_chain: Vec<String>,
    aggregation_uri: Option<String>,
    iat: i64,
    exp: i64,
    token_ttl_secs: u64,
) -> Result<String, StatusListError> {
    let ttl = token_ttl_secs as i64;
    let (bits, lst) = status_record.status_list.token_lst()?;
    let status_list = StatusListClaims {
        bits,
        lst,
        aggregation_uri,
    };
    let claims = StatusListToken {
        exp: Some(exp),
        iat,
        status_list,
        sub: status_record.sub.to_owned(),
        ttl: Some(ttl),
    };
    let header = JwtHeader {
        alg: signer.algorithm().jose_name(),
        typ: STATUS_LISTS_HEADER_JWT,
        x5c: &cert_chain,
    };
    let header =
        serde_json::to_vec(&header).map_err(|err| StatusListError::Backend(Box::new(err)))?;
    let payload =
        serde_json::to_vec(&claims).map_err(|err| StatusListError::Backend(Box::new(err)))?;

    let mut token = base64url::encode(header);
    token.push('.');
    token.push_str(&base64url::encode(payload));

    let signature = signer
        .sign(token.as_bytes())
        .map_err(|err| StatusListError::Backend(Box::new(err)))?;
    token.push('.');
    token.push_str(&base64url::encode(signature));
    Ok(token)
}

fn cose_algorithm(algorithm: SigningAlgorithm) -> Result<Algorithm, StatusListError> {
    Algorithm::from_i64(algorithm.cose_id()).ok_or_else(|| {
        StatusListError::Backend(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported COSE algorithm id: {}", algorithm.cose_id()),
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::status_list::StatusList;
    use crate::utils::crypto::SigningKey;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA256,
        UnparsedPublicKey,
    };
    use coset::TaggedCborSerializable;
    use jsonwebtoken::{DecodingKey, Validation, decode};

    use base64::prelude::Engine as _;

    fn sample_record() -> StatusListRecord {
        StatusListRecord {
            list_id: "list-1".into(),
            issuer: "test-issuer".into(),
            sub: "https://example.com/status-list/1".into(),
            status_list: StatusList {
                bits: 1,
                lst: base64url::encode(b"\x00\x01\x02\x03"),
            },
            updated_at: 1000,
        }
    }

    fn jwt_algorithm(algorithm: SigningAlgorithm) -> jsonwebtoken::Algorithm {
        match algorithm {
            SigningAlgorithm::Es256 => jsonwebtoken::Algorithm::ES256,
            SigningAlgorithm::Es384 => jsonwebtoken::Algorithm::ES384,
            SigningAlgorithm::EdDsa => jsonwebtoken::Algorithm::EdDSA,
            SigningAlgorithm::Rs256 => jsonwebtoken::Algorithm::RS256,
        }
    }

    fn jwt_decoding_key(key: &SigningKey) -> DecodingKey {
        match key.algorithm() {
            SigningAlgorithm::Es256 | SigningAlgorithm::Es384 => {
                DecodingKey::from_ec_der(key.public_key_bytes())
            }
            SigningAlgorithm::EdDsa => DecodingKey::from_ed_der(key.public_key_bytes()),
            SigningAlgorithm::Rs256 => DecodingKey::from_rsa_der(key.public_key_bytes()),
        }
    }

    fn verify_cwt_signature(
        key: &SigningKey,
        signature: &[u8],
        tbs: &[u8],
    ) -> Result<(), aws_lc_rs::error::Unspecified> {
        match key.algorithm() {
            SigningAlgorithm::Es256 => {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key_bytes())
                    .verify(tbs, signature)
            }
            SigningAlgorithm::Es384 => {
                UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, key.public_key_bytes())
                    .verify(tbs, signature)
            }
            SigningAlgorithm::EdDsa => {
                UnparsedPublicKey::new(&ED25519, key.public_key_bytes()).verify(tbs, signature)
            }
            SigningAlgorithm::Rs256 => {
                UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key_bytes())
                    .verify(tbs, signature)
            }
        }
    }

    #[test]
    fn test_dynamic_jwt_alg_header() {
        let record = sample_record();
        let cert_chain = vec!["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE=".to_string()];

        let rsa_pem = include_str!("../../../../../test_data/gcloud_test_key.dummy.pem");

        let test_keys = [
            SigningKey::generate(SigningAlgorithm::Es256).unwrap(),
            SigningKey::generate(SigningAlgorithm::Es384).unwrap(),
            SigningKey::generate(SigningAlgorithm::EdDsa).unwrap(),
            SigningKey::from_pem(rsa_pem).unwrap(),
        ];

        for key in &test_keys {
            let signer: Arc<dyn TokenSigner> =
                Arc::new(SigningKey::from_pem(&key.to_pkcs8_pem().unwrap()).unwrap());
            let token =
                issue_jwt(&record, signer, cert_chain.clone(), None, 1000, 2000, 300).unwrap();
            let header = jsonwebtoken::decode_header(&token).unwrap();
            assert_eq!(header.alg, jwt_algorithm(key.algorithm()));
            assert_eq!(header.typ.as_deref(), Some(STATUS_LISTS_HEADER_JWT));

            let mut validation = Validation::new(jwt_algorithm(key.algorithm()));
            validation.validate_exp = false;
            let decoded = decode::<StatusListToken>(&token, &jwt_decoding_key(key), &validation)
                .expect("JWT signature verifies with its public key");
            assert_eq!(decoded.claims.sub, record.sub);
        }
    }

    #[test]
    fn test_dynamic_cwt_alg_header() {
        let record = sample_record();
        let cert_chain = vec![base64::prelude::BASE64_STANDARD.encode(b"dummy-cert-der")];

        let rsa_pem = include_str!("../../../../../test_data/gcloud_test_key.dummy.pem");

        let test_keys = [
            SigningKey::generate(SigningAlgorithm::Es256).unwrap(),
            SigningKey::generate(SigningAlgorithm::Es384).unwrap(),
            SigningKey::generate(SigningAlgorithm::EdDsa).unwrap(),
            SigningKey::from_pem(rsa_pem).unwrap(),
        ];

        for key in &test_keys {
            let signer: Arc<dyn TokenSigner> =
                Arc::new(SigningKey::from_pem(&key.to_pkcs8_pem().unwrap()).unwrap());
            let material =
                crate::domain::ports::SigningMaterial::new(Some(cert_chain.clone()), signer);
            let components = material.into_certificate_components();
            let x5chain = components.x5chain.expect("pre-built x5chain");
            let cwt_bytes = issue_cwt(
                &record,
                components.signing_key,
                x5chain,
                None,
                1000,
                2000,
                300,
            )
            .unwrap();
            let sign1 = coset::CoseSign1::from_tagged_slice(&cwt_bytes).unwrap();
            let expected_alg = match key.algorithm() {
                SigningAlgorithm::Es256 => Algorithm::ES256,
                SigningAlgorithm::Es384 => Algorithm::ES384,
                SigningAlgorithm::EdDsa => Algorithm::EdDSA,
                SigningAlgorithm::Rs256 => Algorithm::RS256,
            };
            assert_eq!(
                sign1.protected.header.alg,
                Some(coset::RegisteredLabelWithPrivate::Assigned(expected_alg))
            );
            let x5chain_label = coset::Label::Int(HeaderParameter::X5Chain.to_i64());
            let has_x5chain = sign1
                .protected
                .header
                .rest
                .iter()
                .any(|(label, _)| *label == x5chain_label);
            assert!(
                has_x5chain,
                "CWT must carry a spec-compliant x5chain protected header"
            );
            sign1
                .verify_signature(&[], |signature, tbs| {
                    verify_cwt_signature(key, signature, tbs)
                })
                .expect("CWT signature verifies with its public key");
        }
    }

    /// Hot-path CWT signing throughput benchmark.
    ///
    /// Skipped by default (`cargo test`); run explicitly with
    /// `cargo test --lib -- --ignored server::handlers::status_list::utils::token::tests::benchmark_cwt_throughput`.
    ///
    /// Exercises `issue_cwt` with a pre-parsed x5chain (the zero-decode hot
    /// path) across a fixed number of iterations and reports tokens/second. Run
    /// against an earlier revision to compare before/after throughput.
    #[test]
    #[ignore]
    fn benchmark_cwt_throughput() {
        use std::time::Instant;

        const ITERATIONS: usize = 20_000;

        let record = sample_record();
        let cert_chain = vec![base64::prelude::BASE64_STANDARD.encode(b"dummy-cert-der")];
        let signer: Arc<dyn crate::domain::ports::TokenSigner> =
            Arc::new(SigningKey::generate(SigningAlgorithm::Es256).unwrap());
        let material = crate::domain::ports::SigningMaterial::new(Some(cert_chain), signer);
        let components = material.into_certificate_components();
        let x5chain = components.x5chain.expect("pre-built x5chain");

        let start = Instant::now();
        let mut checksum = 0usize;
        for _ in 0..ITERATIONS {
            let bytes = issue_cwt(
                &record,
                components.signing_key.clone(),
                x5chain.clone(),
                None,
                1000,
                2000,
                300,
            )
            .expect("issue_cwt succeeds");
            checksum = checksum.wrapping_add(bytes.len());
        }
        let elapsed = start.elapsed();
        let per_sec = ITERATIONS as f64 / elapsed.as_secs_f64();

        // A sanity floor (tokens/second) that real hardware comfortably clears
        // but a regression to per-request base64 re-decoding would not.
        assert!(
            per_sec > 1_000.0,
            "CWT throughput unexpectedly low: {per_sec:.0} tokens/sec"
        );
        eprintln!(
            "CWT signing throughput: {per_sec:.0} tokens/sec over {ITERATIONS} iterations ({} ms)",
            elapsed.as_millis()
        );
        std::hint::black_box(checksum);
    }
}
